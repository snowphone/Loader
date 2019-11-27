#include "dyn_linker.h"
#include "common.h"

Shdr* read_sect_hdr_table(const Ehdr* const e_hdr, const char* const buf) {
	size_t size = e_hdr->e_shentsize * e_hdr->e_shnum;

	return (Shdr*) (buf + e_hdr->e_shoff);
}

const Shdr* find_shdr(const Shdr* const table, const size_t len, int item) {
	for(const Shdr* it = table; it != table + len; ++it) {
		if(it->sh_type == item)
			return it;
	}
	return NULL;
}

const Elf64_Dyn* find_dyn_tag(const Elf64_Dyn* const table, int tag) {
	for(const Elf64_Dyn* it = table; it->d_tag != DT_NULL; ++it) {
		if(it->d_tag == tag){
			return it;
		}
	}
	return NULL;
}
void* const get_section(const Shdr* table, const size_t len, int item, void* buf) {
	const Shdr* section_hdr = find_shdr(table, len, item);
	return (char*)buf + section_hdr->sh_offset;
}
