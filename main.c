#include "loader.h"

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[], const char* envp[]) {
	DEBUG("Current sp: %p\n", &argc);

	if(argc == 1) {
		fprintf(stderr, "Usage: %s <program>, [...]", argv[0]);
		exit(1);
	}
	my_exec(argc, argv, envp);
}

