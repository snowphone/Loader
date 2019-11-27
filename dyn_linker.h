#pragma once
#include "common.h"

Shdr* read_sect_hdr_table(const Ehdr* const e_hdr, const char* const buf);

const Shdr* find_shdr(const Shdr* const table, const size_t len, int item);

const Elf64_Dyn* find_dyn_tag(const Elf64_Dyn* const table, int tag);

void* const get_section(const Shdr* table, const size_t len, int item, void* buf);
