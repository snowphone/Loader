#include "common.h"

ucontext_t loader_context;
ucontext_t loadee_context;
unsigned long long memory_usage = 0ULL;
Array* mmap_list = NULL;
const char** envp = NULL;

Info info = {
	.fd = 0,
	.base_addr = 0,
	.p_tab = NULL,
	.argc = 0,
	.argv = NULL,
	.envp = NULL,
};

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

static void catcher() {
	setcontext(&loader_context);
}

/**
 * 
 * @param info
 * @param _beg The lowest address of stack space. Used as return value.
 * @param _sp  Current stack pointer which points to argc. Used as return value.
 */
static void create_stack(const Info info, void** _beg, void** _sp) {
	void* sp = Mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	void* begin = sp;

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

		sp -= (auxc) * sizeof(Auxv_t);
		memmove(sp, auxv, (auxc) * sizeof(Auxv_t));

	}

	const size_t envc = (const char**)auxv - info.envp;	// Includes NULL

	// copy envp to stack
	sp -= envc * sizeof(char*);
	memmove(sp, info.envp, envc * sizeof(char*));

	// copy argv to stack
	sp -= (info.argc + 1) * sizeof(char*);
	memmove(sp, info.argv, (info.argc + 1) * sizeof(char*));

	sp -= sizeof info.argc;
	memmove(sp, &info.argc, sizeof info.argc);

	// Assign return values
	*_beg = begin, *_sp = sp;
}

/**
 * @brief Jump to the address that info holds and jump back to here when the loadee is terminated.
 * 
 * @param info 
 */
void switch_context(const Info info) {
	void* sp_begin, *sp;
	create_stack(info, &sp_begin, &sp);

	getcontext(&loadee_context);
	loadee_context.uc_link = NULL;
	loadee_context.uc_stack.ss_size = sp - sp_begin;
	loadee_context.uc_stack.ss_sp = sp_begin;

	void* entry = (void*)info.elf_hdr.e_entry;
	if(info.dyn_table)
		entry += info.base_addr;
	makecontext(&loadee_context, entry, 0);

	loadee_context.uc_mcontext.gregs[REG_RSP] = (greg_t)sp;
	loadee_context.uc_mcontext.gregs[REG_RDX] = (greg_t)catcher;	// Exploit rtld_fini

	fputs("================== Context Switching ==================\n", stderr);
	swapcontext(&loader_context, &loadee_context);
	fputs("=================== Back to Loader ====================\n", stderr);
}

/**
 * @brief Parse elf header and other informations corresponding to loadee
 * 
 * @param argc argc of the loadee
 * @param argv argv of the loadee
 * @param envp envp of the loadee
 * @return Info 
 */
Info read_elf(const char* filename) {
	const char** argv =  calloc(2, sizeof *argv);
	argv[0] = filename;

	Info info = { 
		.fd = open(filename, O_RDONLY),
		.argc = 1,
		.argv = argv,
		.envp = envp,
		.base_addr = 0
	};

	if(info.fd == -1) {
		fprintf(stderr, "Open error: failed to open %s\n", argv[0]);
		abort();
	}

	// Read ELF header
	lseek(info.fd, 0, SEEK_SET);

	Read(info.fd, &info.elf_hdr, sizeof(info.elf_hdr));

	assert(memcmp(info.elf_hdr.e_ident, ELFMAG, SELFMAG) == 0);
	assert(info.elf_hdr.e_ident[EI_CLASS] == ELFCLASS64);
	assert(info.elf_hdr.e_type == ET_EXEC || info.elf_hdr.e_type == ET_DYN);

	// Read program header table
	const size_t p_tab_sz = info.elf_hdr.e_phentsize * info.elf_hdr.e_phnum;
	info.p_tab = malloc(p_tab_sz);

	lseek(info.fd, info.elf_hdr.e_phoff, SEEK_SET);
	Read(info.fd, info.p_tab, p_tab_sz);

	info.base_addr = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_LOAD)->p_vaddr;
	const Phdr* dynamic = find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_DYNAMIC);

	info.shdr_tab = malloc(info.elf_hdr.e_shnum * info.elf_hdr.e_shentsize);
	lseek(info.fd, info.elf_hdr.e_shoff, SEEK_SET);
	Read(info.fd, info.shdr_tab, info.elf_hdr.e_shnum * info.elf_hdr.e_shentsize);

	if(dynamic) {
		info.dyn_table = malloc(dynamic->p_memsz);
		lseek(info.fd, dynamic->p_offset, SEEK_SET);
		Read(info.fd, info.dyn_table, dynamic->p_memsz);

		uint64_t str_sz = find_dyn(info.dyn_table, DT_STRSZ)->d_un.d_val;
		info.strtab = malloc(str_sz);
		size_t offset = find_dyn(info.dyn_table, DT_STRTAB)->d_un.d_ptr - find_phdr(info.p_tab, info.elf_hdr.e_phnum, PT_LOAD)->p_vaddr;
		lseek(info.fd, offset, SEEK_SET);
		Read(info.fd, info.strtab, str_sz);

		size_t symtab_bytes = info.elf_hdr.e_shentsize * info.elf_hdr.e_shnum;
		info.symtab = malloc(symtab_bytes);
		lseek(info.fd, info.elf_hdr.e_shoff, SEEK_SET);
		Read(info.fd, info.symtab, symtab_bytes);
	} else {
		info.dyn_table = NULL;
		info.strtab = NULL;
		info.symtab = NULL;
	}

	return info;
}

Elf64_Dyn* find_dyn(Elf64_Dyn* table, uint64_t tag) {
	for(Elf64_Dyn* it = table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == tag)
			return it;
	}
	return NULL;
}

/**
 * @brief Free info.fd, info.p_tab and mapped pages
 * 
 */
void release_memory() {
	close(info.fd);
	free(info.p_tab);

	while(--mmap_list->idx){
		Pair* it = mmap_list->list + mmap_list->idx;
		DEBUG("Freeing ptr: %p, len: %#lx...", it->ptr, it->len);
		Munmap(it->ptr, it->len);
		DEBUG(" done!\n");
	}
}



void Read(int fd, void* buf, ssize_t sz) {
	while(sz > 0) {
		ssize_t readn = read(fd, buf, sz);
		if(readn < 0) {
			perror("Failed to read");
			abort();
		} else if(readn == 0) {
			break; 
		} else {
			sz -= readn;
			buf += readn;
		}
	}
}

/**
 * @brief Error-free version of mmap. It crash-checks and also store its information to page_list for releasing them later
 * 
 * @param start 
 * @param length 
 * @param prot 
 * @param flags 
 * @param fd 
 * @param offset 
 * @return void* 
 */
void* Mmap(void *start, ssize_t length, int prot, int flags, int fd, off_t offset) {
	//assert(0x6baa40 < start || start + length <= 0x6baa40);
	void* ret = mmap(start, length, prot, flags, fd, offset);
	if(ret == MAP_FAILED) {
		perror("mmap error");
		fprintf(stderr, "%p, %ld\n", start, length);
		abort();
	}
	memory_usage += length;

	if(!mmap_list) {
		mmap_list = malloc(sizeof *mmap_list + 8 * sizeof(Pair));
		mmap_list->capacity = 8;
		mmap_list->idx = 0;
	} else if(mmap_list->idx == mmap_list->capacity) {
		size_t new_sz = sizeof *mmap_list + mmap_list->capacity * 2 * sizeof(Pair);
		mmap_list = realloc(mmap_list, new_sz);
		mmap_list->capacity *= 2;
	}


	mmap_list->list[mmap_list->idx++] = (Pair) { .ptr = ret, .len = MEM_CEIL(length, PAGE_SIZE) };
	DEBUG("Virtual address: [%p, %p), total memory usage: %llu B\n", ret, ret + length, memory_usage);
	return ret;
}

void Munmap(void* addr, size_t len) {
	int r = munmap(addr, len);
	if(r < 0) {
		perror("Failed to unmap");
		abort();
	}
}

