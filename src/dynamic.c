#include "dynamic.h"
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
	Elf64_Dyn* dyn_table = get_dyn_tab(info, NULL);
	char* strtab = get_strtab(info);

	for(Elf64_Dyn* it = dyn_table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == DT_NEEDED) {
			const char* filename = strtab + it->d_un.d_ptr;
			if(memcmp(filename, "ld", 2) == 0) {
				DEBUG("Do not load %s because it is dynamic loader\n", filename);
				continue;
			} else if(already_loaded(filename)) {
				DEBUG("Do not load %s because it is already loaded\n", filename);
				continue;
			}
			const char* full_path = get_valid_lib_path(filename);
			append_lib(filename);
			DEBUG("New library: %s\n", full_path);
			exec(full_path);
		}
	}
	free(dyn_table);
	free(strtab);
}

Shdr* get_plt(const Info info) {
	Shdr* result = NULL;
	size_t shdr_tab_len;
	Shdr* shdr_tab = get_shdr_tab(info, &shdr_tab_len);
	int cnt = 0;
	for(Shdr* it = shdr_tab; it != shdr_tab + shdr_tab_len; ++it) {
		if(it->sh_type == SHT_PROGBITS && it->sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
			++cnt;
		}
		if(cnt == 2) {
			result = it;
			break;
		}
	}

	free(shdr_tab);
	return result;
}

void relocate(Info info) {
	DEBUG("Current function: %s\n", __func__);

	Elf64_Dyn* dyn_table = get_dyn_tab(info, NULL);
	char* strtab = get_strtab(info);
	Elf64_Sym* symtab = get_dynsym_tab(info, NULL);
	/* 
	 * DT_JMPREL: .rela.plt section을 가리킴
	 * DT_PLTRELSZ: .rela.plt 크기를 바이트 형태로 반환
	 * DT_RELA: .rela.dyn 값이 들어있었다.
	 * DT_RELASZ: .rela.dyn 크기를 바이트 형태로 반환
	 * DT_PLTGOT: .got section을 가리킴
	 * DT_PLTREL: RELA를 사용할지 REL을 사용할지 담김
	 */
	Elf64_Dyn *rela_plt = (void*)find_dyn(dyn_table, DT_JMPREL),
			  *plt_rel_sz = (void*)find_dyn(dyn_table, DT_PLTRELSZ),
			  *got = (void*)find_dyn(dyn_table, DT_PLTGOT),
			  *pltrel = (void*)find_dyn(dyn_table, DT_PLTREL),
			  *rela_dyn = (void*)find_dyn(dyn_table, DT_RELA),
			  *rela_sz = (void*)find_dyn(dyn_table, DT_RELASZ);

	assert(pltrel->d_un.d_val == DT_RELA);

	Elf64_Rela* rela_tab = (void*)rela_dyn->d_un.d_ptr + info.base_addr; 	// .rela.plt verified
	size_t rela_tab_bytes = rela_sz->d_un.d_val + plt_rel_sz->d_un.d_val,
		   rela_tab_len = rela_tab_bytes / sizeof *rela_tab;
	DEBUG("GOT Address: %#lx\n", got->d_un.d_ptr);
	DEBUG("rela addr: %p, # of entries: %lu\n", rela_tab, rela_tab_len);

	for(int i = 0; i < rela_tab_len; ++i) {
		uint64_t type = ELF64_R_TYPE(rela_tab[i].r_info),
				 sym_idx = ELF64_R_SYM(rela_tab[i].r_info);

		if(type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) {
			if(!symtab){
				DEBUG("SHITTTTTTTTTTTTTTTTTTTTT!\n");
				continue;
			}
			char* name = symtab[sym_idx].st_name + strtab;
			DEBUG("#%d: %#lx, %#lx, %#lx\t", i, rela_tab[i].r_offset, rela_tab[i].r_info, rela_tab[i].r_addend);
			DEBUG("Type : %#lx, sym_idx: %#lx, name: %s\n", type, sym_idx, name);
		} 
	}
	free(dyn_table);
	free(strtab);
	free(symtab);
}
