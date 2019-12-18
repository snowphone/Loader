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
#define Munmap(...)		assert(munmap(__VA_ARGS__) != -1)
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
} Info;

extern Info info;

extern unsigned long long memory_usage;

typedef struct {
	void* ptr;
	uint64_t len;
} Pair;

typedef struct {
	size_t capacity;
	size_t idx;
	Pair list[];
} Array;

extern Array* mmap_list;

Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf);

int make_prot(const int p_flags);

const Phdr* find_phdr(const Phdr* const table, const size_t len, int item);

Auxv_t* get_auxv(const char* envp[]);

uint64_t make_stack(const Info info);

Info read_elf(int argc, const char* argv[], const char* envp[]);

void install_catcher(Info* info);

void Mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);

void Read(int fd, void* buf, ssize_t sz);

// mov src dst
// cf. in x86-64, rbp won't be used as a frame pointer
#define JUMP(entry, stack)				\
	asm __volatile__(					\
			"movq %1, %%rsp\n\t"		\
			"movq %0, %%rbp\n\t"		\
										\
			"xor %%rax, %%rax\n\t"		\
			"xor %%rbx, %%rbx\n\t"		\
			"xor %%rcx, %%rcx\n\t"		\
			"xor %%rdx, %%rdx\n\t"		\
			"xor %%rsi, %%rsi\n\t"		\
			"xor %%rdi, %%rdi\n\t"		\
			"xor %%r8, %%r8\n\t"		\
			"xor %%r9, %%r9\n\t"		\
			"xor %%r10, %%r10\n\t"		\
			"xor %%r11, %%r11\n\t"		\
			"xor %%r12, %%r12\n\t"		\
			"xor %%r13, %%r13\n\t"		\
			"xor %%r14, %%r14\n\t"		\
			"xor %%r15, %%r15\n\t"		\
										\
			"jmp *%%rbp\n\t"			\
			:							\
			: "r" (entry), "r" (stack)	\
			)


