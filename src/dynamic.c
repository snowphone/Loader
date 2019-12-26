#include "common.h"

#include <unistd.h>

extern void exec(const char*);

static const char* base_dir[] = {
	"/usr/local/lib/",
	"/usr/local/lib/x86_64-linux-gnu/",
	"/usr/lib/x86_64-linux-gnu/",
	"/lib/x86_64-linux-gnu/",
	"./",
	NULL
};

static Elf64_Dyn* find_dyn(Elf64_Dyn* table, uint64_t tag) {
	for(Elf64_Dyn* it = table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == tag)
			return it;
	}
	return NULL;
}

char* get_valid_lib_path(const char* path) {
	DEBUG("Filename: %s\n", path);
	static char full_path[512];

	for(const char** dir = base_dir; *dir != NULL; ++dir) {
		memset(full_path, 0, sizeof *full_path);
		strcat(full_path, *dir);
		strcat(full_path, path);
		if(access(full_path, F_OK) != -1) {
			return full_path;
		}
	}
	return NULL;
}

static uint64_t loaded_lib_list[512];
static uint64_t loaded_lib_len = 0;

static uint64_t hash(const char* str) {
	uint64_t hash = 0;
	for(const char* it = str; *it; ++it) {
		hash += *it;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^=(hash >> 11);
	hash += (hash << 15);

	return hash;
}

static bool contains(const char* str) {
	uint64_t hashed = hash(str);
	for(int i = 0; i < loaded_lib_len; ++i) {
		if(hashed == loaded_lib_list[i])
			return true;
	}
	return false;
}

static void append(const char* str) {
	assert(loaded_lib_len < sizeof loaded_lib_list);
	uint64_t hashed = hash(str);
	loaded_lib_list[loaded_lib_len++] = hashed;
}

void load_library(Info info) {
	const Phdr* dynamic = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_DYNAMIC);

	Elf64_Dyn* dyn_table = malloc(dynamic->p_memsz);
	lseek(info.fd, dynamic->p_offset, SEEK_SET);
	Read(info.fd, dyn_table, dynamic->p_memsz);

	uint64_t str_sz = find_dyn(dyn_table, DT_STRSZ)->d_un.d_val;

	char* strtab = malloc(str_sz);
	size_t offset = find_dyn(dyn_table, DT_STRTAB)->d_un.d_ptr - find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_LOAD)->p_vaddr;
	lseek(info.fd, offset, SEEK_SET);
	Read(info.fd, strtab, str_sz);

	for(Elf64_Dyn* it = dyn_table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == DT_NEEDED) {
			const char* filename = strtab + it->d_un.d_ptr;
			if(memcmp(filename, "ld", 2) == 0) {
				DEBUG("Do not load %s because it is dynamic loader\n", filename);
				continue;
			} else if(contains(filename)) {
				DEBUG("Do not load %s because it is already loaded\n", filename);
				continue;
			}
			const char* full_path = get_valid_lib_path(filename);
			append(filename);
			exec(full_path);
		}
	}
}
