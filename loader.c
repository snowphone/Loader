#include "loader.h"

#include "common.h"
#include "dyn_linker.h"

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

enum { STACK_SIZE = PAGE_SIZE * 64ULL, };

typedef struct Auxv_info {
		uint64_t fd;
		Ehdr elf_hdr;
		uint64_t base_addr;
		Phdr* p_tab;	// program header table
		int argc;
		const char** argv;
		const char** envp;
	}Auxv_info;

typedef struct Stk_entry {
	uint64_t sp, bp;
} Stk_entry;


static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const it);
static int make_prot(const int p_flags);
static const Phdr* find_phdr(const Phdr* const table, const size_t len, int item);
static Ehdr* read_elf(const char* const buf);
static Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf);
static size_t get_size(int fd);
static Stk_entry make_stack(const Auxv_info info);

static unsigned long long memory_usage;

void my_exec(const int argc, const char* argv[], const char* envp[]) {
	Auxv_info info = { 
		.fd = open(argv[0], O_RDWR),
		.argc = argc,
		.argv = argv,
		.envp = envp,
		.base_addr = UINT64_MAX,
	};

	// Read ELF header
	lseek(info.fd, 0, SEEK_SET);
#define READ(FD, BUF, SZ) assert(read(FD, BUF, SZ))
	READ(info.fd, &info.elf_hdr, sizeof(info.elf_hdr));

	assert( memcmp(info.elf_hdr.e_ident, ELFMAG, SELFMAG) == 0);
	assert( info.elf_hdr.e_ident[EI_CLASS] == ELFCLASS64);
	assert( info.elf_hdr.e_type == ET_EXEC || info.elf_hdr.e_type == ET_DYN);

	DEBUG("entry point: %#lx\n", info.elf_hdr.e_entry);

	// Read program header table
	size_t p_tab_sz = info.elf_hdr.e_phentsize * info.elf_hdr.e_phnum;
	info.p_tab = malloc(p_tab_sz);

	lseek(info.fd, info.elf_hdr.e_phoff, SEEK_SET);
	READ(info.fd, info.p_tab, p_tab_sz);

#undef READ

	DEBUG("# of segments: %d\n", info.elf_hdr.e_phnum);

	for(Phdr* it = info.p_tab; it != info.p_tab + info.elf_hdr.e_phnum; ++it) {
		DEBUG("TYPE: %u, virt addr : %#lx \n",it->p_type, it->p_vaddr );
		if(it->p_type == PT_LOAD){
			uint64_t mapped_addr = (uint64_t)bind_segment(info.fd, &info.elf_hdr, it);
				info.base_addr = MIN(info.base_addr, mapped_addr);
		}

		const Phdr* interpreter;	// dynamic linker interpreter(ld-linux.so)
		if((interpreter = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_DYNAMIC))) {
			assert("Not yet implemened" && 0);
		}
	}


	fprintf(stderr, "Base address: %#lx\n", info.base_addr);
	//fclose(fp);

	Stk_entry stk_e = make_stack(info);
	uint64_t entry_p = info.elf_hdr.e_entry;
	uint64_t sp = stk_e.sp;

	DEBUG("base p: %#lx, stk p: %#lx\n", stk_e.bp, stk_e.sp);
	DEBUG("entry point: %#lx\n", info.elf_hdr.e_entry);

	DEBUG("argc: %d\n", *(int*)sp);
	DEBUG("argv[0]: %s\n", *(char**)(sp + 4));


	//asm __volatile__(
	//  "xor %rax, %rax\n\t"
    //  "xor %rbx, %rbx\n\t"
    //  "xor %rcx, %rcx\n\t"
    //  "xor %rdx, %rdx\n\t"
    //  "xor %rsi, %rsi\n\t"
    //  "xor %rdi, %rdi\n\t"
    //  "xor %r8, %r8\n\t"
    //  "xor %r9, %r9\n\t"
    //  "xor %r10, %r10\n\t"
    //  "xor %r11, %r11\n\t"
    //  "xor %r12, %r12\n\t"
    //  "xor %r13, %r13\n\t"
    //  "xor %r14, %r14\n\t"
    //  "xor %r15, %r15\n\t"
    // );

	// mov src dst
	// cf. in x86-64, rbp won't be used as frame pointer
	asm __volatile__(
			"movq %0, %%rax\n\t"
			"movq %1, %%rsp\n\t"
			"xor %%rdx, %%rdx\n\t"
			//  "xor %rbx, %rbx\n\t"
			//  "xor %rcx, %rcx\n\t"
			//  "xor %rdx, %rdx\n\t"
			//  "xor %rsi, %rsi\n\t"
			//  "xor %rdi, %rdi\n\t"
			//  "xor %r8, %r8\n\t"
			//  "xor %r9, %r9\n\t"
			//  "xor %r10, %r10\n\t"
			//  "xor %r11, %r11\n\t"
			//  "xor %r12, %r12\n\t"
			//  "xor %r13, %r13\n\t"
			//  "xor %r14, %r14\n\t"
			//  "xor %r15, %r15\n\t"
			// );

			//"xor %%rax, %%rax\n\t"
			"jmp %%rax\n\t"
			:
			: "r" (entry_p), "r" (sp)
			);
}


static Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf) {
	assert(e_hdr->e_phentsize == sizeof(Phdr));

	unsigned int size = e_hdr->e_phentsize * e_hdr->e_phnum;
	assert(0 < size && size <= 65536);

	return (Phdr*) (buf + e_hdr->e_phoff);
}

static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const it) {
	// cf. A segment contains several sections such as .text, .init, and so on.
	void* const aligned_addr = MEM_ALIGN(it->p_vaddr, PAGE_SIZE);
	const int front_pad = MEM_OFFSET(it->p_vaddr, PAGE_SIZE);
	const size_t len = it->p_filesz + front_pad;
	const int prot = make_prot(it->p_flags);
	const int flags = elf_hdr->e_type == ET_EXEC ? MAP_PRIVATE | MAP_FIXED : MAP_PRIVATE;
	const unsigned int file_offset = it->p_offset - front_pad;

	void* const mapped = mmap(aligned_addr, len, prot, flags, fd, file_offset);
	assert(mapped != MAP_FAILED);
	// Memory is mapped in private mode, so its modification only affects on private copy, not the file. 
	memset(mapped, 0, front_pad);



	if(it->p_memsz > it->p_filesz && (prot & PROT_WRITE)) {
		DEBUG("BSS section\n");
		/* zero fill procedure for .bss section */
		void* elf_bss = (void*)(it->p_vaddr + it->p_filesz);
		size_t size = MEM_OFFSET(elf_bss, PAGE_SIZE);
		if(!size) {
			// The mapped region is assigned just as filesz, so there's no space for .bss section. 
			// Map .bss section explicitly
			void* mapped_bss = mmap(elf_bss, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, -1, 0);
			assert(mapped_bss != MAP_FAILED);
		}
		size = PAGE_SIZE - size;
		memset((void*)elf_bss, 0, size);
		DEBUG("Clear bits!\n");
	}

	memory_usage += it->p_filesz;
	fprintf(stderr, "Virtual address: %p, file offset: %u, file_size: %lu, total memory usage: %llu B\n", mapped, file_offset, it->p_filesz, memory_usage);
	return mapped;
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
	for(const Phdr* it = table; it != table + len; ++it) {
		if(it->p_type == item)
			return it;
	}
	return NULL;
}

static Elf64_auxv_t* get_auxv(const char* envp[]) {
	const char** p = envp;
	while(*p++) ; //After the loop, p points auxv;

	return (Elf64_auxv_t*)p;
}

static Stk_entry make_stack(const Auxv_info info) {

	DEBUG("Enter make_stack\n");

	void* sp = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(sp != MAP_FAILED);
	memory_usage += STACK_SIZE;
	fprintf(stderr, "STACK: Virtual address: %p, memory_size: %d, total memory usage: %llu B\n", sp, STACK_SIZE, memory_usage);
	// According to some sources, MAP_GROWSDOWN is buggy
	// Check http://lkml.iu.edu/hypermail/linux/kernel/0808.1/2846.html

	sp += STACK_SIZE;

	void* const bp = sp;

	{	// copy auxv to stack
#define NEW_AUX_ENT(P, V, ID)	do{	*--P = V; *--P = ID; }while(0);
		uint64_t* auxv = sp;
		NEW_AUX_ENT(auxv, 0, AT_NULL);
		NEW_AUX_ENT(auxv, info.fd, AT_EXECFD);
		NEW_AUX_ENT(auxv, 0, AT_NOTELF);
		NEW_AUX_ENT(auxv, getegid(), AT_EGID);
		NEW_AUX_ENT(auxv, getgid(), AT_GID);
		NEW_AUX_ENT(auxv, geteuid(), AT_EUID);
		NEW_AUX_ENT(auxv, getuid(), AT_UID);
		NEW_AUX_ENT(auxv, info.elf_hdr.e_entry, AT_ENTRY);
		NEW_AUX_ENT(auxv, info.base_addr, AT_BASE);
		NEW_AUX_ENT(auxv, info.elf_hdr.e_phnum, AT_PHNUM);
		NEW_AUX_ENT(auxv, info.elf_hdr.e_phentsize, AT_PHENT);
		NEW_AUX_ENT(auxv, info.base_addr + info.elf_hdr.e_phoff, AT_PHDR);
		NEW_AUX_ENT(auxv, PAGE_SIZE, AT_PAGESZ);

#undef NEW_AUX_ENT
	}
	{	// copy envp to stack
		const char** it = info.envp;
		while(*it++ != NULL);
		size_t sz = (it - info.envp) * sizeof(char*);

		sp -= sz;
		memmove(sp, info.envp, sz);
	}
	{	// copy argv to stack
		const char** it = info.argv;
		while(*it++ != NULL);
		size_t sz = (it - info.argv) * sizeof(char*);
		sp -= sz;
		memmove(sp, info.argv, sz);
	}
	{	// copy argc to stack
		sp -= sizeof(info.argc);
		memmove(sp, &info.argc, sizeof(info.argc));
	}
	DEBUG("ARGC1: %d\n", info.argc);
	DEBUG("ARGC2: %d\n", *(int*)sp);
	DEBUG("&ARGC: %p\n", (int*)sp);
	DEBUG("&ARGC: %p\n", sp);

	return (Stk_entry){ .bp = (uint64_t)bp, .sp = (uint64_t)sp };
}

