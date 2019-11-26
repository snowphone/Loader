#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Shdr Shdr;

#ifndef PAGE_SIZE
	#define PAGE_SIZE (getpagesize())	//included in POSIX
#endif

#define MEM_ALIGN(M/*memory*/, U/*page unit*/) (void*)((uint64_t)(M) & ~((uint64_t)(U) - 1ull))
#define MEM_OFFSET(M, U) ((uint64_t)(M) & ((uint64_t)(U) - 1ull))


size_t get_size(int fd) {
	struct stat st;
	fstat(fd, &st);
	return st.st_size;
}

Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf) {
	assert(e_hdr->e_phentsize == sizeof(Phdr));

	unsigned int size = e_hdr->e_phentsize * e_hdr->e_phnum;
	assert(0 < size && size <= 65536);

	return (Phdr*) (buf + e_hdr->e_phoff);
}

Shdr* read_sect_hdr_table(const Ehdr* e_hdr, const char* const buf) {
	size_t size = e_hdr->e_shentsize * e_hdr->e_shnum;

	return (Shdr*) (buf + e_hdr->e_shoff);
}

Ehdr* read_elf(const char* const buf) {
	Ehdr* header = (Ehdr*)buf;

	assert( "Magic number verification" &&
			memcmp(header->e_ident, ELFMAG, SELFMAG) == 0);

	assert( "Check whether ELF64 is correct" &&
			header->e_ident[EI_CLASS] == ELFCLASS64);

	assert( "Check whether executable" &&
			header->e_type == ET_EXEC || header->e_type == ET_DYN);

	return header;
}

const Phdr* find_phdr(const Phdr* const table, const size_t len, int item) {
	for(const Phdr* it = table; it != table + len; ++it) {
		if(it->p_type == item)
			return it;
	}
	return NULL;
}
const Shdr* find_shdr(const Shdr* const table, const size_t len, int item) {
	for(const Shdr* it = table; it != table + len; ++it) {
		if(it->sh_type == item)
			return it;
	}
	return NULL;
}



int make_prot(const int p_flags) {
	int prot = 0;

	if (p_flags & PF_R)
		prot |= PROT_READ;
	if (p_flags & PF_W)
		prot |= PROT_WRITE;
	if (p_flags & PF_X)
		prot |= PROT_EXEC;
	return prot;
}

void* bind_section(const int fd, const Ehdr* const elf_hdr, const Phdr* const it) {
	void* const addr = MEM_ALIGN(it->p_vaddr, PAGE_SIZE);
	const size_t len = it->p_filesz + MEM_OFFSET(it->p_vaddr, it->p_align);
	const int prot = make_prot(it->p_flags);
	const int flags = (elf_hdr->e_type == ET_EXEC) ? (MAP_PRIVATE | MAP_EXECUTABLE) : MAP_PRIVATE;
	const unsigned int file_offset = it->p_offset - MEM_OFFSET(it->p_vaddr, PAGE_SIZE);

	void* const mapped = mmap(addr, len, prot, flags, fd, file_offset);
	assert(mapped != MAP_FAILED);

	if(it->p_memsz > it->p_filesz && (prot & PROT_WRITE)) {
		/* zero fill */
		void* const p = (char*)mapped + MEM_OFFSET(it->p_vaddr, it->p_align) + it->p_filesz;
		memset(p, 0, it->p_memsz - it->p_filesz);
	}

	fprintf(stderr, "virtual address: %p, mapped: %p\n", addr, mapped);
	return mapped;
}

void my_exec(const char* program_path, char* argv[]) {
	FILE* fp = fopen(program_path, "r+b");
	int fd = fileno(fp);
	size_t sz = get_size(fd);
	const char* const buf = mmap(0, sz, PROT_READ, MAP_PRIVATE, fd, 0);

	const Ehdr* const elf_hdr = read_elf(buf);
	const Phdr* const prog_hdr_table = read_prog_hdr_table(elf_hdr, buf);

	for(const Phdr* it = prog_hdr_table; it != prog_hdr_table + elf_hdr->e_phnum; ++it) {
		if(it->p_type == PT_LOAD){
			void* section = bind_section(fd, elf_hdr, it);
		}
	}

#if 0
	for(const Shdr* it = sect_hdr_table; it != sect_hdr_table + elf_hdr->e_shnum; ++it) {
		// Ignore useless sections
		if(it->sh_type == SHT_NULL)
			continue;

		int flags = MAP_PRIVATE | MAP_EXECUTABLE ;
		unsigned long off = it->sh_offset - it->sh_addr;
		char* addr = mmap((void*)it->sh_addr, it->sh_size, PROT_EXEC | PROT_READ , flags, fd, off);
		assert(addr != MAP_FAILED);

#ifndef NDEBUG
		const Shdr* const str_table_hdr = &sect_hdr_table[elf_hdr->e_shstrndx];
		const char* const str_table = buf + str_table_hdr->sh_offset;
		fprintf(stderr, "%s: %p, expected %p\n", str_table + it->sh_name, addr, (void*)it->sh_addr);
#endif
	}
	// Load .text, .data, .bss, .heap, .stack
	// Clear current stack, heap & registers
	//
	// Last: jmp 
	//


	const Phdr* interp_hdr = find_phdr(prog_hdr_table, elf_hdr->e_phnum, PT_INTERP);
	if(interp_hdr) {
		const Phdr* dyn_hdr = find_phdr(prog_hdr_table, elf_hdr->e_phnum, PT_DYNAMIC);
		//Call dynamic linker(same job as ld-linux.so)
		//So, I have to implement dynamic linker...
	}
#endif
}

int main(int argc, char* argv[]) {
#ifndef NDEBUG
	printf("Page size: %d\n", getpagesize());
#endif

	if(argc == 1) {
		fprintf(stderr, "Usage: %s <program>, [...]", argv[0]);
		exit(1);
	}
	my_exec(argv[0], argv + 1);	
}

