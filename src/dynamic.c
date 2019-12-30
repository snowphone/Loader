#include "dynamic.h"
#include "common.h"

#include <unistd.h>

extern void exec(const char*);

static Info dependencies[128];
static size_t dependencies_len = 0;

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

static bool already_loaded(const char* lib_name) {
	for(int i = 0; i < dependencies_len; ++i) {
		if(strstr(*dependencies[i].argv, lib_name)) {
			return true;
		}
	}
	return false;
}

void append_lib(const Info info) {
	assert(dependencies_len < sizeof dependencies);
	dependencies[dependencies_len++] = info;
}

void load_library(Info info) {
	Elf64_Dyn* dyn_table = get_dyn_tab(info, NULL);
	char* strtab = get_strtab(info, NULL);

	for(Elf64_Dyn* it = dyn_table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == DT_NEEDED) {
			const char* filename = strtab + it->d_un.d_ptr;
			if(memcmp(filename, "ld", 2) == 0) {
				DEBUG("Do not load %s since it is dynamic loader\n", filename);
				continue;
			} else if(already_loaded(filename)) {
				DEBUG("Do not load %s since it is already loaded\n", filename);
				continue;
			}
			const char* full_path = get_valid_lib_path(filename);
			exec(full_path);
		}
	}
	free(dyn_table);
	free(strtab);
}

static uint64_t get_valid_addr(const char* symbol_name) {
	DEBUG("Current function: %s\tSymbol: %s\n", __func__, symbol_name);
	uint64_t result = 0;
	Info *dep,
		 *dep_end = dependencies + dependencies_len;


	for(Info* dep = dependencies; dep != dep_end; ++dep) {
		size_t symtab_len;
		Elf64_Sym* symtab = get_dynsym_tab(*dep, &symtab_len);
		size_t strtab_len;
		char* strtab = get_strtab(*dep, &strtab_len);

		for(Elf64_Sym* sym = symtab; sym != symtab + symtab_len; ++sym) {
			size_t stt = ELF64_ST_TYPE(sym->st_info);
			const char* candidate = strtab + sym->st_name;
			if(sym->st_name >= strtab_len)
				continue;
			if(strcmp(symbol_name, candidate)) 
				continue;
			DEBUG("@@@@@@@@@@@@@@@@@@ Eureka! @@@@@@@@@@@@@@@@@@\n");

			result = sym->st_value + dep->start_addr;


			free(symtab);
			free(strtab);

			goto exit;
		}

		free(symtab);
		free(strtab);
	}
exit:
	return result;
}

void relocate(Info info) {
	DEBUG("Current function: %s\n", __func__);

	Elf64_Dyn* dyn_table = get_dyn_tab(info, NULL);
	char* strtab = get_strtab(info, NULL);
	Elf64_Sym* symtab = get_dynsym_tab(info, NULL);
	/* 
	 * DT_JMPREL: .rela.plt section을 가리킴
	 * DT_PLTRELSZ: .rela.plt 크기를 바이트 형태로 반환
	 * DT_RELA: .rela.dyn 값이 들어있었다.
	 * DT_RELASZ: .rela.dyn 크기를 바이트 형태로 반환
	 * DT_PLTGOT: .got section을 가리킴
	 * DT_PLTREL: RELA를 사용할지 REL을 사용할지 담김
	 */
	Elf64_Dyn *plt_rel_sz = (void*)find_dyn(dyn_table, DT_PLTRELSZ),
			  *pltrel = (void*)find_dyn(dyn_table, DT_PLTREL),
			  *rela_dyn = (void*)find_dyn(dyn_table, DT_RELA),
			  *rela_sz = (void*)find_dyn(dyn_table, DT_RELASZ);

	assert(pltrel->d_un.d_val == DT_RELA);

	Elf64_Rela* rela_tab = (void*)rela_dyn->d_un.d_ptr + info.start_addr; 	// .rela.plt verified
	size_t rela_tab_bytes = rela_sz->d_un.d_val + plt_rel_sz->d_un.d_val,
		   rela_tab_len = rela_tab_bytes / sizeof *rela_tab;
	DEBUG("rela addr: %p, # of entries: %lu\n", rela_tab, rela_tab_len);

	for(int i = 0; i < rela_tab_len; ++i) {
		uint64_t type = ELF64_R_TYPE(rela_tab[i].r_info),
				 sym_idx = ELF64_R_SYM(rela_tab[i].r_info);

		if(type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) {
			const char* symbol_name = symtab[sym_idx].st_name + strtab;
			uint64_t* symbol_got = (uint64_t*)rela_tab[i].r_offset;
		//	DEBUG("#%d: %#lx, %#lx, %#lx\t", i, rela_tab[i].r_offset, rela_tab[i].r_info, rela_tab[i].r_addend);
		//	DEBUG("Type : %#lx, sym_idx: %#lx, name: %s\n", type, sym_idx, symbol_name);
			uint64_t new_addr = get_valid_addr(symbol_name);
			*symbol_got = new_addr;// + rela_tab[i].r_addend;
			DEBUG("%s's address: %#lx\n", symbol_name, *symbol_got);
		} 
	}
	DEBUG("Start addr: %p\n", (void*)info.start_addr);
	free(dyn_table);
	free(strtab);
	free(symtab);
}
