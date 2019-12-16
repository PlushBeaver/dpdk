/* SPDX-License-Identifier: LGPLv2
 * Copyright 2016 Neil Horman <nhorman@tuxdriver.com>
 * Based in part on modpost.c from the linux kernel
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License V2, incorporated herein by reference.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(RTE_EXEC_ENV_LINUX)
#include <endian.h>
#elif defined(RTE_EXEC_ENV_FREEBSD)
#include <sys/endian.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#include <rte_byteorder.h>
#include <rte_config.h>
#include <rte_pci.h>

#include "pmdinfogen.h"

/* On BSD-alike OSes elf.h defines these according to host's word size */
#undef ELF_ST_BIND
#undef ELF_ST_TYPE
#undef ELF_R_SYM
#undef ELF_R_TYPE

/*
 * Define ELF64_* to ELF_*, the latter being defined in both 32 and 64 bit
 * flavors in elf.h.  This makes our code a bit more generic between arches
 * and allows us to support 32 bit code in the future should we ever want to
 */
#ifdef RTE_ARCH_64
#define Elf_Ehdr    Elf64_Ehdr
#define Elf_Shdr    Elf64_Shdr
#define Elf_Sym     Elf64_Sym
#define Elf_Addr    Elf64_Addr
#define Elf_Sword   Elf64_Sxword
#define Elf_Section Elf64_Half
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_TYPE ELF64_ST_TYPE

#define Elf_Rel     Elf64_Rel
#define Elf_Rela    Elf64_Rela
#define ELF_R_SYM   ELF64_R_SYM
#define ELF_R_TYPE  ELF64_R_TYPE
#else
#define Elf_Ehdr    Elf32_Ehdr
#define Elf_Shdr    Elf32_Shdr
#define Elf_Sym     Elf32_Sym
#define Elf_Addr    Elf32_Addr
#define Elf_Sword   Elf32_Sxword
#define Elf_Section Elf32_Half
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_TYPE ELF32_ST_TYPE

#define Elf_Rel     Elf32_Rel
#define Elf_Rela    Elf32_Rela
#define ELF_R_SYM   ELF32_R_SYM
#define ELF_R_TYPE  ELF32_R_TYPE
#endif


/*
 * Note, it seems odd that we have both a CONVERT_NATIVE and a TO_NATIVE macro
 * below.  We do this because the values passed to TO_NATIVE may themselves be
 * macros and need both macros here to get expanded.  Specifically its the width
 * variable we are concerned with, because it needs to get expanded prior to
 * string concatenation
 */
#define CONVERT_NATIVE(fend, width, x) ({ \
typeof(x) ___x; \
if ((fend) == ELFDATA2LSB) \
	___x = le##width##toh(x); \
else \
	___x = be##width##toh(x); \
	___x; \
})

#define TO_NATIVE(fend, width, x) CONVERT_NATIVE(fend, width, x)

#ifdef RTE_ARCH_64
#define ADDR_SIZE 64
#else
#define ADDR_SIZE 32
#endif

struct image {
	unsigned long size;
	Elf_Ehdr     *hdr;
	Elf_Shdr     *sechdrs;
	Elf_Sym      *symtab_start;
	Elf_Sym      *symtab_stop;
	char         *strtab;

	/* support for 32bit section numbers */

	unsigned int num_sections; /* max_secindex + 1 */
	unsigned int secindex_strings;
	/* if Nth symbol table entry has .st_shndx = SHN_XINDEX,
	 * take shndx from symtab_shndx_start[N] instead
	 */
	Elf32_Word   *symtab_shndx_start;
	Elf32_Word   *symtab_shndx_stop;
};

/* Strong typedef, must not include other members. */
struct symbol {
	Elf_Sym elf;
};

struct image*
image_load(void* addr, size_t size)
{
    struct image *info;
	unsigned int i;
	Elf_Ehdr *hdr = addr;
	Elf_Shdr *sechdrs;
	Elf_Sym  *sym;
	int endian;
	unsigned int symtab_idx = ~0U, symtab_shndx_idx = ~0U;

    info = malloc(sizeof(*info));
    if (info == NULL) {
        LOG("ERROR: memory allocation failed");
        return NULL;
    }
    memset(info, 0, sizeof(*info));

	info->hdr = hdr;
	info->size = size;
	if (size < sizeof(*hdr)) {
		/* file too small, assume this is an empty .o file */
        LOG("ERROR: image size %lu less than ELF file header size %lu",
                size, sizeof(*hdr));
		goto error;
	}
	/* Is this a valid ELF file? */
	if ((hdr->e_ident[EI_MAG0] != ELFMAG0) ||
	    (hdr->e_ident[EI_MAG1] != ELFMAG1) ||
	    (hdr->e_ident[EI_MAG2] != ELFMAG2) ||
	    (hdr->e_ident[EI_MAG3] != ELFMAG3)) {
		/* Not an ELF file - silently ignore it */
        LOG("ERROR: ELF magic: want %02x %02x %02x %02x, got %02x %02x %02x %02x",
                ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
				hdr->e_ident[EI_MAG0], hdr->e_ident[EI_MAG2],
				hdr->e_ident[EI_MAG2], hdr->e_ident[EI_MAG3]);
		goto error;
	}

	if (!hdr->e_ident[EI_DATA]) {
		/* Unknown endian */
        LOG("ERROR: unknown endianness");
		goto error;
	}

	endian = hdr->e_ident[EI_DATA];

	/* Fix endianness in ELF header */
	hdr->e_type      = TO_NATIVE(endian, 16, hdr->e_type);
	hdr->e_machine   = TO_NATIVE(endian, 16, hdr->e_machine);
	hdr->e_version   = TO_NATIVE(endian, 32, hdr->e_version);
	hdr->e_entry     = TO_NATIVE(endian, ADDR_SIZE, hdr->e_entry);
	hdr->e_phoff     = TO_NATIVE(endian, ADDR_SIZE, hdr->e_phoff);
	hdr->e_shoff     = TO_NATIVE(endian, ADDR_SIZE, hdr->e_shoff);
	hdr->e_flags     = TO_NATIVE(endian, 32, hdr->e_flags);
	hdr->e_ehsize    = TO_NATIVE(endian, 16, hdr->e_ehsize);
	hdr->e_phentsize = TO_NATIVE(endian, 16, hdr->e_phentsize);
	hdr->e_phnum     = TO_NATIVE(endian, 16, hdr->e_phnum);
	hdr->e_shentsize = TO_NATIVE(endian, 16, hdr->e_shentsize);
	hdr->e_shnum     = TO_NATIVE(endian, 16, hdr->e_shnum);
	hdr->e_shstrndx  = TO_NATIVE(endian, 16, hdr->e_shstrndx);

	sechdrs = RTE_PTR_ADD(hdr, hdr->e_shoff);
	info->sechdrs = sechdrs;

	/* Check if file offset is correct */
	if (hdr->e_shoff > info->size) {
		LOG("ERROR: section header offset %lu is bigger than image size %lu",
		      (unsigned long)hdr->e_shoff, info->size);
		goto error;
	}

	if (hdr->e_shnum == SHN_UNDEF) {
		/*
		 * There are more than 64k sections,
		 * read count from .sh_size.
		 */
		info->num_sections =
			TO_NATIVE(endian, ADDR_SIZE, sechdrs[0].sh_size);
	} else {
		info->num_sections = hdr->e_shnum;
	}
	if (hdr->e_shstrndx == SHN_XINDEX)
		info->secindex_strings =
			TO_NATIVE(endian, 32, sechdrs[0].sh_link);
	else
		info->secindex_strings = hdr->e_shstrndx;

	/* Fix endianness in section headers */
	for (i = 0; i < info->num_sections; i++) {
		sechdrs[i].sh_name      =
			TO_NATIVE(endian, 32, sechdrs[i].sh_name);
		sechdrs[i].sh_type      =
			TO_NATIVE(endian, 32, sechdrs[i].sh_type);
		sechdrs[i].sh_flags     =
			TO_NATIVE(endian, 32, sechdrs[i].sh_flags);
		sechdrs[i].sh_addr      =
			TO_NATIVE(endian, ADDR_SIZE, sechdrs[i].sh_addr);
		sechdrs[i].sh_offset    =
			TO_NATIVE(endian, ADDR_SIZE, sechdrs[i].sh_offset);
		sechdrs[i].sh_size      =
			TO_NATIVE(endian, ADDR_SIZE, sechdrs[i].sh_size);
		sechdrs[i].sh_link      =
			TO_NATIVE(endian, 32, sechdrs[i].sh_link);
		sechdrs[i].sh_info      =
			TO_NATIVE(endian, 32, sechdrs[i].sh_info);
		sechdrs[i].sh_addralign =
			TO_NATIVE(endian, ADDR_SIZE, sechdrs[i].sh_addralign);
		sechdrs[i].sh_entsize   =
			TO_NATIVE(endian, ADDR_SIZE, sechdrs[i].sh_entsize);
	}
	/* Find symbol table. */
	for (i = 1; i < info->num_sections; i++) {
		int nobits = sechdrs[i].sh_type == SHT_NOBITS;

		if (!nobits && sechdrs[i].sh_offset > info->size) {
			LOG("ERROR: sechdrs[i].sh_offset=%lu > sizeof(*hrd)=%lu (image truncated?)",
			      (unsigned long)sechdrs[i].sh_offset, sizeof(*hdr));
			goto error;
		}

		if (sechdrs[i].sh_type == SHT_SYMTAB) {
			unsigned int sh_link_idx;
			symtab_idx = i;
			info->symtab_start = RTE_PTR_ADD(hdr,
				sechdrs[i].sh_offset);
			info->symtab_stop  = RTE_PTR_ADD(hdr,
				sechdrs[i].sh_offset + sechdrs[i].sh_size);
			sh_link_idx = sechdrs[i].sh_link;
			info->strtab       = RTE_PTR_ADD(hdr,
				sechdrs[sh_link_idx].sh_offset);
		}

		/* 32bit section no. table? ("more than 64k sections") */
		if (sechdrs[i].sh_type == SHT_SYMTAB_SHNDX) {
			symtab_shndx_idx = i;
			info->symtab_shndx_start = RTE_PTR_ADD(hdr,
				sechdrs[i].sh_offset);
			info->symtab_shndx_stop  = RTE_PTR_ADD(hdr,
				sechdrs[i].sh_offset + sechdrs[i].sh_size);
		}
	}
	if (!info->symtab_start) {
		LOG("ERROR: no symbol table");
        goto error;
	} else {
		/* Fix endianness in symbols */
		for (sym = info->symtab_start; sym < info->symtab_stop; sym++) {
			sym->st_shndx = TO_NATIVE(endian, 16, sym->st_shndx);
			sym->st_name  = TO_NATIVE(endian, 32, sym->st_name);
			sym->st_value = TO_NATIVE(endian, ADDR_SIZE, sym->st_value);
			sym->st_size  = TO_NATIVE(endian, ADDR_SIZE, sym->st_size);
		}
	}

	if (symtab_shndx_idx != ~0U) {
		Elf32_Word *p;
		if (symtab_idx != sechdrs[symtab_shndx_idx].sh_link)
			LOG("WARNING: SYMTAB_SHNDX has bad sh_link: %u!=%u",
			      sechdrs[symtab_shndx_idx].sh_link, symtab_idx);
		/* Fix endianness */
		for (p = info->symtab_shndx_start; p < info->symtab_shndx_stop; p++)
			*p = TO_NATIVE(endian, 32, *p);
	}

	return info;

error:
    free(info);
    return NULL;
}

void*
image_symbol_get(struct image *info, struct symbol *symbol)
{
	Elf_Sym *sym = (Elf_Sym *)symbol;
	return RTE_PTR_ADD(info->hdr,
		    info->sechdrs[sym->st_shndx].sh_offset + sym->st_value);
}

static const char*
sym_name(struct image *info, Elf_Sym *sym)
{
	if (sym)
		return info->strtab + sym->st_name;
	else
		return "(unknown)";
}

struct symbol*
image_symbol_find(struct image *info, const char *name, struct symbol *from)
{
	Elf_Sym *idx;

	if (from != NULL)
		idx = (Elf_Sym *)from + 1;
	else
		idx = info->symtab_start;

	for (; idx < info->symtab_stop; idx++) {
		const char *n = sym_name(info, idx);
		if (!strncmp(n, name, strlen(name)))
			return (struct symbol *)idx;
	}

	return NULL;
}

void
image_unload(struct image* info)
{
    free(info);
}
