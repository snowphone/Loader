#include "common.h"

Phdr* read_prog_hdr_table(const Ehdr* e_hdr, const char* const buf) {
	assert(e_hdr->e_phentsize == sizeof(Phdr));

	unsigned int size = e_hdr->e_phentsize * e_hdr->e_phnum;
	assert(0 < size && size <= 65536);

	return (Phdr*) (buf + e_hdr->e_phoff);
}

int make_prot(const int p_flags) {
	/* Fork from github/torvalds/linux/fs/binfmt_elf.c */
	int prot = 0;

	if (p_flags & PF_R)
		prot |= PROT_READ;
	if (p_flags & PF_W)
		prot |= PROT_WRITE;
	if (p_flags & PF_X)
		prot |= PROT_EXEC;
	return prot;
}

const Phdr* find_phdr(const Phdr* const table, const size_t len, int item) {
	for (const Phdr* it = table; it != table + len; ++it) {
		if (it->p_type == item)
			return it;
	}
	return NULL;
}

Auxv_t* get_auxv(const char* envp[]) {
	const char** p = envp;
	while(*p++) ; //After the loop, p points auxv;

	return (Auxv_t*)p;
}


uint64_t make_stack(const Info info) {
	void* sp = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(sp != MAP_FAILED);

	sp += STACK_SIZE;

	Auxv_t* auxv = get_auxv(info.envp);
	{	// copy auxv to stack

		Auxv_t* it = auxv;
		size_t auxc;	// Includes AT_NULL element

		for (it = auxv, auxc = 1; it->a_type != AT_NULL ; ++it, ++auxc) {
			switch(it->a_type) {
				case AT_EXECFN:
					it->a_un.a_val = (uint64_t)info.argv[0];
					break;
				case AT_EXECFD:
					it->a_un.a_val = info.fd;
					break;
				case AT_ENTRY:
					it->a_un.a_val = info.elf_hdr.e_entry;
					break;
				case AT_BASE:
					{
						// The base address of the dynamic linker.
						const Phdr* interp = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_INTERP);
						it->a_un.a_val = interp ? interp->p_vaddr : 0;
						break;
					}
				case AT_PHNUM:
					it->a_un.a_val = info.elf_hdr.e_phnum;
					break;
				case AT_PHENT:
					it->a_un.a_val = info.elf_hdr.e_phentsize;
					break;
				case AT_PHDR:
					it->a_un.a_val = info.base_addr + info.elf_hdr.e_phoff;
					break;
			}
		}


		DEBUG("########## auxc: %ld ###########\n", auxc);

		sp -= (auxc) * sizeof(Auxv_t);
		memmove(sp, auxv, (auxc) * sizeof(Auxv_t));
	}

	const size_t envc = (const char**)auxv - info.envp;	// Includes NULL

	// copy envp to stack
	sp -= envc * sizeof(char*);
	memmove(sp, info.envp, envc * sizeof(char*));

	DEBUG("########## envc: %ld ###########\n", envc);

	// copy argv to stack
	sp -= (info.argc + 1) * sizeof(char*);
	memmove(sp, info.argv, (info.argc + 1) * sizeof(char*));

	// copy argc to stack
	sp -= sizeof(info.argc);
	memmove(sp, &info.argc, sizeof(info.argc));


	return (uint64_t)sp;
}
Info read_elf(int argc, const char* argv[], const char* envp[]) {
	Info info = { 
		.fd = open(argv[0], O_RDONLY),
		.argc = argc,
		.argv = argv,
		.envp = envp,
		.base_addr = UINT64_MAX,
	};

	if(info.fd == -1) {
		fprintf(stderr, "Open error: failed to open %s\n", argv[0]);
		exit(1);
	}

	// Read ELF header
	lseek(info.fd, 0, SEEK_SET);

	Read(info.fd, &info.elf_hdr, sizeof(info.elf_hdr));

	assert( memcmp(info.elf_hdr.e_ident, ELFMAG, SELFMAG) == 0);
	assert( info.elf_hdr.e_ident[EI_CLASS] == ELFCLASS64);
	assert( info.elf_hdr.e_type == ET_EXEC || info.elf_hdr.e_type == ET_DYN);

	DEBUG("entry point: %#lx\n", info.elf_hdr.e_entry);

	// Read program header table
	const size_t p_tab_sz = info.elf_hdr.e_phentsize * info.elf_hdr.e_phnum;
	info.p_tab = malloc(p_tab_sz);

	lseek(info.fd, info.elf_hdr.e_phoff, SEEK_SET);
	Read(info.fd, info.p_tab, p_tab_sz);

	return info;
}

char* get_strtab(Info* info, Elf64_Shdr* sym_tab) {
	Elf64_Shdr* hdr = sym_tab + info->elf_hdr.e_shstrndx - 1;
	size_t sz = hdr->sh_size;
	char* buf = malloc(sz);
	lseek(info->fd, hdr->sh_offset, SEEK_SET);
	Read(info->fd, buf, sz);
	return buf;
}

static void* find_exit_symbol(Info* info) {
	size_t sym_hdr_sz = info->elf_hdr.e_shnum * info->elf_hdr.e_shentsize;
	lseek(info->fd, info->elf_hdr.e_shoff, SEEK_SET);
	Elf64_Shdr* sym_hdr = malloc(sym_hdr_sz);
	Read(info->fd, sym_hdr, sym_hdr_sz);

	char* symbol_names = get_strtab(info, sym_hdr);

	void* addr = 0;

	for(Elf64_Shdr* it = sym_hdr; it != sym_hdr + info->elf_hdr.e_shnum; ++it) {
		if(it->sh_type != SHT_SYMTAB)
			continue;

		size_t sym_sz = it->sh_size * it->sh_entsize;
		Elf64_Sym* sym = malloc(sym_sz);
		lseek(info->fd, it->sh_offset, SEEK_SET);
		Read(info->fd, sym, sym_sz);


		for(Elf64_Sym* jt = sym; jt != sym + it->sh_size; ++jt) {
			if(jt->st_info & STT_OBJECT && jt->st_info & STB_GLOBAL) {
				if(jt->st_name == SHN_UNDEF) // str name is not encoded
					continue;
				char* name = symbol_names + jt->st_name;
				if(strcmp(name, "__exit_funcs") != 0) 
					continue;
				addr = (void*)jt->st_value;
				goto found_address;
			}
		}
	}
found_address:
	return addr;
}

void fin() {
	fputs("==================== Back to Loader ===================\n", stderr);
}

#define PTR_MANGLE(var) 			\
	asm ("mov %0, %%r10\n\t"		\
		"xor %%fs:0x30, %%r10\n\t"	\
		"rol $0x11, %%r10\n\t"		\
		"mov %%r10, %0\n\t"			\
		:"+r" (var)					\
		)

void install_hooker(Info* info) {
	void** target_symbol_addr = find_exit_symbol(info);
	uint64_t* list = *target_symbol_addr;

	uint64_t func_addr = (uint64_t)fin;
	PTR_MANGLE(func_addr);

	list[0] = (uint64_t)NULL;
	list[1] = 1;
	list[2] = 4;
	list[3] = func_addr;
	list[4] = 0;
	list[5] = 0; //dso_handle == *(void**)0x6b90e8. mostly, assigned to 0

	DEBUG("function address: %p, mangled address: %#lx\n", fin, func_addr);
}

