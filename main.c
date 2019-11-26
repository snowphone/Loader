#include "loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[]) {
	if(argc == 1) {
		fprintf(stderr, "Usage: %s <program>, [...]", argv[0]);
		exit(1);
	}
	my_exec(argv[0], argv + 1);	
}

