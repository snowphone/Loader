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
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Shdr Shdr;

#ifndef MIN
 #define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

//Normally, PAGE_SIZE is defined in sys/user.h but just in case.
#ifndef PAGE_SIZE
	#define PAGE_SIZE (getpagesize())	//included in POSIX
#endif

#define MEM_ALIGN(M/*memory*/, U/*page unit*/) (void*)((uint64_t)(M) & ~((uint64_t)(U) - 1ull))
#define MEM_OFFSET(M, U) ((uint64_t)(M) & ((uint64_t)(U) - 1ull))


