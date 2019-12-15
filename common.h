#pragma once

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>	

#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#ifdef NDEBUG
 #undef NDEBUG
 #include <assert.h>
 #define NDEBUG
#else
 #include <assert.h>
#endif

typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_auxv_t Auxv_t;

#ifndef NDEBUG
 #define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
 /* Ignore */
 #define DEBUG(...) ;
#endif

#ifndef MIN
 #define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

//Normally, PAGE_SIZE is defined in sys/user.h but just in case.
#ifndef PAGE_SIZE
	#define PAGE_SIZE (getpagesize())	//included in POSIX
#endif

// Auxilary functions that ease memory address calculation
#define MEM_ALIGN(M/*memory*/, U/*page unit*/) ((uint64_t)(M) & ~((uint64_t)(U) - 1ull))
#define MEM_OFFSET(M, U) ((uint64_t)(M) & ((uint64_t)(U) - 1ull))
#define MEM_CEIL(M, U) ( MEM_OFFSET(M, U) ? (uint64_t)MEM_ALIGN(M, U) + U : (uint64_t)M )


// Wrapper functions that guarantee to do well
#define Mmap(...)			assert(MAP_FAILED != mmap(__VA_ARGS__))
#define Read(FD, BUF, SZ)	assert(read(FD, BUF, SZ) >= 0)
#define Sigaction(...)	assert(sigaction(__VA_ARGS__) != -1)


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


Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf);

int make_prot(const int p_flags);

const Phdr* find_phdr(const Phdr* const table, const size_t len, int item);

Auxv_t* get_auxv(const char* envp[]);

uint64_t make_stack(const Info info);

Info read_elf(int argc, const char* argv[], const char* envp[]);

void install_hooker(Info* info);
