#include "loader.h"

#include "common.h"
#include "dyn_linker.h"

#define __USE_GNU

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <ucontext.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

enum { STACK_SIZE = PAGE_SIZE * 64ULL, };

typedef struct Info {
		uint64_t fd;
		Ehdr elf_hdr;
		uint64_t base_addr;
		Phdr* p_tab;	// program header table
		uint64_t argc;
		const char** argv;
		const char** envp;
	}Info;


static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const it);
static int make_prot(const int p_flags);
static const Phdr* find_phdr(const Phdr* const table, const size_t len, int item);
static Ehdr* read_elf(const char* const buf);
static Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf);
static size_t get_size(int fd);
static uint64_t make_stack(const Info info);
static void install_segv_handler();
static void bind_page(const uint64_t fault_addr);

static Info info;

#define MMAP(...) (assert(MAP_FAILED != mmap(__VA_ARGS__)))
#define READ(FD, BUF, SZ) assert(read(FD, BUF, SZ) >= 0)

void demand_execve(const int argc, const char* argv[], const char* envp[]) {
	install_segv_handler();

	info = (Info) { 
		.fd = open(argv[0], O_RDONLY),
		.argc = argc,
		.argv = argv,
		.envp = envp,
		.base_addr = UINT64_MAX,
	};

	if(info.fd == -1) {
		fprintf(stderr, "Open error: failed to open %s\n", argv[0]);
		exit(1);
	}

	// Read ELF header
	lseek(info.fd, 0, SEEK_SET);


	READ(info.fd, &info.elf_hdr, sizeof(info.elf_hdr));

	assert( memcmp(info.elf_hdr.e_ident, ELFMAG, SELFMAG) == 0);
	assert( info.elf_hdr.e_ident[EI_CLASS] == ELFCLASS64);
	assert( info.elf_hdr.e_type == ET_EXEC || info.elf_hdr.e_type == ET_DYN);

	DEBUG("entry point: %#lx\n", info.elf_hdr.e_entry);

	// Read program header table
	const size_t p_tab_sz = info.elf_hdr.e_phentsize * info.elf_hdr.e_phnum;
	info.p_tab = malloc(p_tab_sz);

	lseek(info.fd, info.elf_hdr.e_phoff, SEEK_SET);
	READ(info.fd, info.p_tab, p_tab_sz);

	info.base_addr = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_LOAD)->p_vaddr;
	fprintf(stderr, "Base address: %#lx\n", info.base_addr);

	if (find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_INTERP)) {
		assert("Dynamic linker is not yet implemented" && 0);
	}

	DEBUG("entry point: %#lx\n", info.elf_hdr.e_entry);

	const uint64_t entry_p = info.elf_hdr.e_entry;
	const uint64_t sp = make_stack(info);

	DEBUG("stk p: %#lx\n", sp);

	fputs("==================== End of Loader ====================\n", stderr);

	// mov src dst
	// cf. in x86-64, rbp won't be used as a frame pointer
	asm __volatile__(
			"movq %1, %%rsp\n\t"
			"movq %0, %%rbp\n\t"

			"xor %%rax, %%rax\n\t"
			"xor %%rbx, %%rbx\n\t"
			"xor %%rcx, %%rcx\n\t"
			"xor %%rdx, %%rdx\n\t"
			"xor %%rsi, %%rsi\n\t"
			"xor %%rdi, %%rdi\n\t"
			"xor %%r8, %%r8\n\t"
			"xor %%r9, %%r9\n\t"
			"xor %%r10, %%r10\n\t"
			"xor %%r11, %%r11\n\t"
			"xor %%r12, %%r12\n\t"
			"xor %%r13, %%r13\n\t"
			"xor %%r14, %%r14\n\t"
			"xor %%r15, %%r15\n\t"

			"jmp *%%rbp\n\t"
			:
			: "r" (entry_p), "r" (sp)
			);
}

static void segv_handler(int signo, siginfo_t* sinfo, void* /* ucontext_t* */ _context) {
	assert(signo == SIGSEGV);
	assert(sinfo->si_code == SEGV_MAPERR);

	const uint64_t faulty_addr = (uint64_t)sinfo->si_addr;

	if (!faulty_addr) {
		perror("NULL pointer can not be referenced");
		raise(SIGKILL);
	}

	//DEBUG("Got signal %d, faulty address is %p from %p\n", signo, faulty_addr, uc->uc_mcontext.gregs[REG_RIP]);

	bind_page(faulty_addr);
}

static void install_segv_handler() {
	struct sigaction sa;
	
	sa.sa_sigaction = segv_handler;

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);

	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGSEGV, &sa, NULL) < 0) {
		perror("Failed to register SIGSEGV handler");
		exit(1);
	}
}

static Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf) {
	assert(e_hdr->e_phentsize == sizeof(Phdr));

	unsigned int size = e_hdr->e_phentsize * e_hdr->e_phnum;
	assert(0 < size && size <= 65536);

	return (Phdr*) (buf + e_hdr->e_phoff);
}

static void bind_page(const uint64_t fault_addr) {
	int flags = info.elf_hdr.e_type == ET_EXEC ? MAP_PRIVATE | MAP_FIXED : MAP_PRIVATE;

	for (Phdr* it = info.p_tab; it != info.p_tab + info.elf_hdr.e_phnum; ++it) {
		const uint64_t begin = it->p_vaddr,
			  end = it->p_vaddr + it->p_memsz;

		if ( begin <= fault_addr && fault_addr < end ) {
			uint64_t aligned_begin = MEM_ALIGN(fault_addr, PAGE_SIZE);
			const int prot = make_prot(it->p_flags);
			size_t file_offset = -1;
			int fd = 0;

			DEBUG("segment end: %#lx\n", begin + it->p_filesz);

			// Check whether the whole page is aligned to .bss section.
			if (it->p_memsz > it->p_filesz && end <= aligned_begin) {
				// .bss section
				fd = -1;
				file_offset = 0;
				flags |= MAP_ANONYMOUS;
			} else { // Assume the page is the union of non-.bss and .bss section.
				fd = info.fd;
				// Invariant: needy_addr - v_addr == offset_in_file - segment_offset_in_file
				// ∴ offset_in_file := segment_offset_in_file + needy_addr - v_addr
				file_offset = it->p_offset + aligned_begin - it->p_vaddr;
			}
			MMAP((void*)aligned_begin, PAGE_SIZE, prot, flags, fd, file_offset);

			const size_t bss_begin = it->p_vaddr + it->p_filesz,
				  aligned_end = aligned_begin + PAGE_SIZE;

			if (bss_begin <= aligned_begin) {
				// Pure .bss section. 
				// Clear whole page to zero.
				memset((void*)aligned_begin, 0, PAGE_SIZE);
			} else { // The page might be contain .bss section or not.

				if (aligned_begin < it->p_vaddr) {
					// Zero-fill the front padding 
					memset((void*)aligned_begin, 0, it->p_vaddr - aligned_begin);
				}
				// The first condition checks the segment has .bss section.
				// The second condition checks the aligned page and .bss section is overlapped.
				if (it->p_filesz < it->p_memsz && bss_begin < aligned_end) {
					// Clear the remaining .bss section to zero.
					memset((void*)bss_begin, 0, aligned_end - bss_begin);
				}
			}

			break;
		}
	}
}

static int make_prot(const int p_flags) {
	/* Fork from github/torvalds/linux/fs/binfmt_elf.c */
	int prot = 0;

	if (p_flags & PF_R)
		prot |= PROT_READ;
	if (p_flags & PF_W)
		prot |= PROT_WRITE;
	if (p_flags & PF_X)
		prot |= PROT_EXEC;
	return prot;
}

static const Phdr* find_phdr(const Phdr* const table, const size_t len, int item) {
	for (const Phdr* it = table; it != table + len; ++it) {
		if (it->p_type == item)
			return it;
	}
	return NULL;
}

static Auxv_t* get_auxv(const char* envp[]) {
	const char** p = envp;
	while(*p++) ; //After the loop, p points auxv;

	return (Auxv_t*)p;
}

static uint64_t make_stack(const Info info) {
	void* sp = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(sp != MAP_FAILED);

	sp += STACK_SIZE;

	Auxv_t* auxv = get_auxv(info.envp);
	{	// copy auxv to stack

		Auxv_t* it = auxv;
		size_t auxc;	// Includes AT_NULL element

		for (it = auxv, auxc = 1; it->a_type != AT_NULL ; ++it, ++auxc) {
			switch(it->a_type) {
				case AT_EXECFN:
					it->a_un.a_val = (uint64_t)info.argv[0];
					break;
				case AT_EXECFD:
					it->a_un.a_val = info.fd;
					break;
				case AT_ENTRY:
					it->a_un.a_val = info.elf_hdr.e_entry;
					break;
				case AT_BASE:
					{
						// The base address of the dynamic linker.
						const Phdr* interp = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_INTERP);
						it->a_un.a_val = interp ? interp->p_vaddr : 0;
						break;
					}
				case AT_PHNUM:
					it->a_un.a_val = info.elf_hdr.e_phnum;
					break;
				case AT_PHENT:
					it->a_un.a_val = info.elf_hdr.e_phentsize;
					break;
				case AT_PHDR:
					it->a_un.a_val = info.base_addr + info.elf_hdr.e_phoff;
					break;
			}
		}


		DEBUG("########## auxc: %ld ###########\n", auxc);

		sp -= (auxc) * sizeof(Auxv_t);
		memmove(sp, auxv, (auxc) * sizeof(Auxv_t));
	}

	const size_t envc = (const char**)auxv - info.envp;	// Includes NULL

	// copy envp to stack
	sp -= envc * sizeof(char*);
	memmove(sp, info.envp, envc * sizeof(char*));

	DEBUG("########## envc: %ld ###########\n", envc);

	// copy argv to stack
	sp -= (info.argc + 1) * sizeof(char*);
	memmove(sp, info.argv, (info.argc + 1) * sizeof(char*));

	// copy argc to stack
	sp -= sizeof(info.argc);
	memmove(sp, &info.argc, sizeof(info.argc));


	return (uint64_t)sp;
}

