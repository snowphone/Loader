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

static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const it);


void Execve(const int argc, const char* argv[], const char* envp[]) {
	memory_usage = 0;
	info = read_elf(argc, argv, envp);

	DEBUG("# of segments: %d\n", info.elf_hdr.e_phnum);

	for(Phdr* it = info.p_tab; it != info.p_tab + info.elf_hdr.e_phnum; ++it) {
		DEBUG("SEGMENT TYPE: %u, virt addr range: [%#lx, %#lx)\n",it->p_type, it->p_vaddr,it->p_vaddr + it->p_memsz);
		if(it->p_type == PT_LOAD){
			uint64_t mapped_addr = (uint64_t)bind_segment(info.fd, &info.elf_hdr, it);
			info.base_addr = MIN(info.base_addr, mapped_addr);
		}

		const Phdr* interpreter;	// dynamic linker interpreter(ld-linux.so)
		if((interpreter = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_DYNAMIC))) {
			assert("Not yet implemented" && 0);
		}
	}


	fprintf(stderr, "Base address: %#lx\n", info.base_addr);

	install_catcher(&info);

	const uint64_t entry_p = info.elf_hdr.e_entry;
	const uint64_t sp = make_stack(info);

	DEBUG("stk p: %#lx\n", sp);
	DEBUG("entry point: %#lx\n", info.elf_hdr.e_entry);

	DEBUG("argc: %lu\n", *(uint64_t*)sp);
	DEBUG("argv[0]: %s\n", *(char**)(sp + sizeof info.argc));


	fputs("==================== End of Loader ====================\n", stderr);

	JUMP(entry_p, sp);
}

static void* bind_segment(const int fd, const Ehdr* const elf_hdr, const Phdr* const it) {
	// cf. A segment contains several sections such as .text, .init, and so on.
	void* const aligned_begin = (void*)MEM_ALIGN(it->p_vaddr, PAGE_SIZE);
	const uint64_t front_pad = MEM_OFFSET(it->p_vaddr, PAGE_SIZE);
	size_t len = MEM_CEIL(it->p_filesz + front_pad, PAGE_SIZE);
	const int prot = make_prot(it->p_flags);
	const int flags = elf_hdr->e_type == ET_EXEC ? MAP_PRIVATE | MAP_FIXED : MAP_PRIVATE;
	const unsigned int file_offset = it->p_offset - front_pad;

	Mmap(aligned_begin, len, prot, flags, fd, file_offset);
	// Memory is mapped in private mode, so its modification only affects on private copy, not the file. 
	memset(aligned_begin, 0, front_pad);

	if(it->p_memsz > it->p_filesz) {
		// .bss section
		void* bss = (void*)(it->p_vaddr + it->p_filesz);
		size_t sz = MEM_CEIL(bss, PAGE_SIZE) - (uint64_t)bss;
		memset(bss, 0, sz);

		bss += sz;
		sz = (it->p_memsz - it->p_filesz) - sz;
		Mmap(bss, sz, prot, flags | MAP_ANONYMOUS, -1, 0);
		memset(bss, 0, sz);

		len += sz;
	}

	fprintf(stderr, "Virtual address: [%p, %p), file offset: %u, total memory usage: %llu B\n", aligned_begin, aligned_begin + len, file_offset, memory_usage);
	return aligned_begin + front_pad;
}

