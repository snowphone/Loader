#include "dynamic.h"


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

static bool already_loaded(const char* str) {
	uint64_t hashed = hash(str);
	for(int i = 0; i < loaded_lib_len; ++i) {
		if(hashed == loaded_lib_list[i])
			return true;
	}
	return false;
}

static void append_lib(const char* str) {
	assert(loaded_lib_len < sizeof loaded_lib_list);
	uint64_t hashed = hash(str);
	loaded_lib_list[loaded_lib_len++] = hashed;
}

void load_library(Info info) {
	for(Elf64_Dyn* it = info.dyn_table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == DT_NEEDED) {
			const char* filename = info.strtab + it->d_un.d_ptr;
			if(memcmp(filename, "ld", 2) == 0) {
				DEBUG("Do not load %s because it is dynamic loader\n", filename);
				continue;
			} else if(already_loaded(filename)) {
				DEBUG("Do not load %s because it is already loaded\n", filename);
				continue;
			}
			const char* full_path = get_valid_lib_path(filename);
			append_lib(filename);
			exec(full_path);
		}
	}
}

Shdr* get_plt(const Info info) {
	int cnt = 0;
	for(Shdr* it = info.shdr_tab; it != info.shdr_tab + info.elf_hdr.e_shnum; ++it) {
		if(it->sh_type == SHT_PROGBITS && it->sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
			++cnt;
		}
		if(cnt == 2)
			return it;
	}
	return NULL;
}

void relocate(Info info) {
	DEBUG("%s\n", __func__);
	/* 
	 * DT_JMPREL: .rela.plt section을 가리킴
	 * DT_PLTGOT: .got section을 가리킴
	 * DT_PLTREL: RELA를 사용할지 REL을 사용할지 담김
	 * DT_RELA: .rela.dyn 값이 들어있었다.
	 */
	Elf64_Dyn *plt = (void*)find_dyn(info.dyn_table, DT_JMPREL),
			  *pltsz = (void*)find_dyn(info.dyn_table, DT_PLTRELSZ),
			  *got = (void*)find_dyn(info.dyn_table, DT_PLTGOT),
			  *pltrel = (void*)find_dyn(info.dyn_table, DT_PLTREL),
			  *rela = (void*)find_dyn(info.dyn_table, DT_RELA);

	assert(pltrel->d_un.d_val == DT_RELA);

	Shdr* plt_hdr = get_plt(info);
	DEBUG("Real plt addr: %#lx, length: %lx, ent: %lx\n", plt_hdr->sh_addr, plt_hdr->sh_size, plt_hdr->sh_entsize);



	Elf64_Rela* rela_list = (void*)plt->d_un.d_ptr + info.base_addr; 	// .rela.plt verified
	size_t size = plt->d_un.d_val;
	DEBUG("GOT Address: %#lx\n", got->d_un.d_ptr);
	DEBUG("Symbol table size: %d\n", info.elf_hdr.e_shnum);
	DEBUG("Assumed plt addr: %p, length: %lu\n", rela_list, size);
	for(int i = 0; i < size / 24; ++i) {
		uint64_t type = ELF64_R_TYPE(rela_list[i].r_info),
				 sym_idx = ELF64_R_SYM(rela_list[i].r_info);

		if(type != DT_RELA)
			break;
		if(sym_idx >= info.elf_hdr.e_shnum)
			continue;

		DEBUG("#%d: %#lx, %#lx, %#lx\t", i, rela_list[i].r_offset, rela_list[i].r_info, rela_list[i].r_addend);
		assert(info.symtab);
		assert(info.strtab);
		char* name = info.symtab[sym_idx].st_name + info.strtab;
		DEBUG("Type : %#lx, sym_idx: %#lx, name: %s\n", type, sym_idx, name);
	}
}
