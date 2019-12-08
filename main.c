#ifdef DEMAND
 #include "demand_loader.h"
#else
 #include "loader.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[]) {

	if(argc == 1) {
		fprintf(stderr, "Usage: %s <program>, [...]\n", argv[0]);
		exit(1);
	}

	const char** envp = argv;
	while(*envp++);

#ifdef DEMAND
	demand_execve(argc - 1, argv + 1, envp);
#else
	Execve(argc - 1, argv + 1, envp);
#endif
}

