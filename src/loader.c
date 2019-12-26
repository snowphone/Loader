#include "common.h"

#include "dynamic.h"

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const phdr);

void exec(const char* filename) {
	DEBUG("Loading %s...\n", filename);
	memory_usage = 0;
	Info l_info = read_elf(filename);

	for(Phdr* it = l_info.p_tab; it != l_info.p_tab + l_info.elf_hdr.e_phnum; ++it) {
		if(it->p_type == PT_LOAD){
			uint64_t mapped_addr = (uint64_t)bind_segment(l_info.fd, &l_info.elf_hdr, it);
			if(!l_info.base_addr)
				l_info.base_addr = mapped_addr;
		}
	}
	if(find_phdr(l_info.p_tab, l_info.elf_hdr.e_phnum, PT_DYNAMIC)) {
		load_library(l_info);
	} else {
		DEBUG("This is executable binary!\n");
		info = l_info;
		switch_context(info);

		release_memory();
	}

	return;
}

/**
 * Load information from phdr and bind to virtual memory
 * @param fd
 * @param elf_hdr
 * @param phdr
 * @return Virtual memory address of a binded segment
 */
static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const phdr) {
	// cf. A segment contains several sections such as .text, .init, and so on.
	void* aligned_begin = (void*)MEM_ALIGN(phdr->p_vaddr, PAGE_SIZE);
	const uint64_t front_pad = MEM_OFFSET(phdr->p_vaddr, PAGE_SIZE);
	size_t len = MEM_CEIL(phdr->p_filesz + front_pad, PAGE_SIZE);
	const int prot = make_prot(phdr->p_flags);
	const int flags = elf_hdr->e_type == ET_EXEC ? MAP_PRIVATE | MAP_FIXED : MAP_PRIVATE;
	const unsigned int file_offset = phdr->p_offset - front_pad;

	aligned_begin = Mmap(aligned_begin, len, prot, flags, fd, file_offset);
	// Memory is mapped in private mode, so its modification only affects on private copy, not the file. 
	memset(aligned_begin, 0, front_pad);

	if(phdr->p_memsz > phdr->p_filesz) {
		// .bss section
		void* bss = (void*)(phdr->p_vaddr + phdr->p_filesz);
		ssize_t sz = MEM_CEIL(bss, PAGE_SIZE);
		sz -= (uint64_t)bss;
		memset(bss, 0, sz);

		bss += sz;

		// If .bss section needs more than one page
		void* actual_bss_end = (void*)phdr->p_vaddr + phdr->p_memsz;
		if(bss < actual_bss_end) {
			sz = (phdr->p_memsz - phdr->p_filesz) - sz;
			Mmap(bss, sz, prot, flags | MAP_ANONYMOUS, -1, 0);
			memset(bss, 0, sz);
		}

		len += sz;
	}

	return aligned_begin + front_pad;
}

