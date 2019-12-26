#include "common.h"

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

static void install_segv_handler();
static void bind_page(const uint64_t fault_addr);


void exec(const char* filename) {
	memory_usage = 0;
	install_segv_handler();

	info = read_elf(filename);

	if (find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_INTERP)) {
		assert("Dynamic linker is not yet implemented" && 0);
	}

	bind_page(info.elf_hdr.e_entry);

	switch_context(info);

	release_memory();

	return;
}

static void segv_handler(int signo, siginfo_t* sinfo, void* /* ucontext_t* */ _context) {
	struct sigaction sa;
	if(signo != SIGSEGV || sinfo->si_code != SEGV_MAPERR)
		goto init_signal;

	const uint64_t faulty_addr = (uint64_t)sinfo->si_addr;

	if (faulty_addr && faulty_addr >= PAGE_SIZE) {
		bind_page(faulty_addr);
		return;
	} 
init_signal:
	// If faulty_addr is NULL, release the handler and let it crash.
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	Sigaction(SIGSEGV, &sa, NULL);
}

static void install_segv_handler() {
	struct sigaction sa;

	sa.sa_sigaction = segv_handler;

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);

	sa.sa_flags = SA_SIGINFO;

	Sigaction(SIGSEGV, &sa, NULL);
}

static void bind_page(const uint64_t faulty_addr) {
	int flags = info.elf_hdr.e_type == ET_EXEC ? MAP_PRIVATE | MAP_FIXED : MAP_PRIVATE;

	for (Phdr* it = info.p_tab; it != info.p_tab + info.elf_hdr.e_phnum; ++it) {
		const uint64_t seg_begin = it->p_vaddr,
			  seg_end = it->p_vaddr + it->p_memsz,

			  aligned_begin = MEM_ALIGN(faulty_addr, PAGE_SIZE),
			  bss_begin = it->p_vaddr + it->p_filesz,
			  aligned_end = aligned_begin + PAGE_SIZE;

		const int prot = make_prot(it->p_flags);
		size_t file_offset = 0;
		int fd = 0;

		if ( seg_begin <= faulty_addr && faulty_addr < seg_end ) {
			// Check whether the whole page is aligned to .bss section.
			if (it->p_memsz > it->p_filesz && bss_begin <= aligned_begin) {
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
			Mmap((void*)aligned_begin, PAGE_SIZE, prot, flags, fd, file_offset);


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

