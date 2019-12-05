#include "loader.h"

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[]) {

	if(argc == 1) {
		fprintf(stderr, "Usage: %s <program>, [...]", argv[0]);
		exit(1);
	}

	const char** envp = argv;
	while(*envp++);

	Execve(argc - 1, argv + 1, envp);
}

