#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <asm/prctl.h>

void exec(const int argc, const char **argv, const char **envp);

void backup_fs(uint64_t* fs_p) {
	volatile uint64_t var;
	asm __volatile__("mov %%fs:0x0, %0\n\t": "=r" (var));
	*fs_p = var;
}
#define UNVEIL(X) #X
#define TO_STR(X) UNVEIL(X)

void restore_fs(uint64_t* fs_p) {
	volatile uint64_t fs = *fs_p;
	asm __volatile__(
		"mov %0, %%rsi\n\t"	
		"mov $0x9e, %%rax\n\t"
		"mov $"TO_STR(ARCH_SET_FS)", %%rdi\n\t"
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
	
	for(int i = 1; i < argc; ++i) {
		fprintf(stderr, "#%d: Loading %s...\n", i, argv[i]);
		exec(argc - i, argv + i, envp);
		restore_fs(fs_base);
	}

	fprintf(stderr, "================== Terminate loader ===================\n");
}

