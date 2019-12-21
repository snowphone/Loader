#ifdef DEMAND
 #include "demand_loader.h"
#else
 #include "loader.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <asm/prctl.h>

void backup_fs(uint64_t* fs_p) {
	volatile uint64_t var;
	asm __volatile__("mov %%fs:0x0, %0\n\t": "=r" (var));
	*fs_p = var;
}
#define UNVEIL(X) #X
#define TOSTR(X) UNVEIL(X)
void restore_fs(uint64_t* fs_p) {
	volatile uint64_t fs = *fs_p;
	asm __volatile__(
		"mov %0, %%rsi\n\t"	
		"mov $0x9e, %%rax\n\t"
		"mov $"TOSTR(ARCH_SET_FS)", %%rdi\n\t"
		"syscall\n\t"
		:
		: "r" (fs)
		);
}

int main(int argc, const char* argv[]) {
	uint64_t fs_base[1];
	if(argc == 1) {
		fprintf(stderr, "Usage: %s <program>, [...]\n", argv[0]);
		exit(1);
	}
	backup_fs(fs_base);


	const char** envp = argv;
	while(*envp++);
	
	int num;
	for(argc--, argv++, num = 1; *argv; argc--, argv++, num++) {
		fprintf(stderr, "#%d: %s\n", num, argv[0]);
#ifdef DEMAND
		demand_execve(argc, argv, envp);
#else
		Execve(argc, argv, envp);
#endif
		restore_fs(fs_base);
	}

	fputs("============= Returned to main function ===============\n", stderr);
}

