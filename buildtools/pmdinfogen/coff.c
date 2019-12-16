/** SPDX-License-Identifier: BSD-3-Clause
 *  Copyright (c) 2019 Dmitry Kozlyuk <dmitry.kozliuk@gmail.com>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "pmdinfogen.h"

/* x64_64, value is little-endian */
#define COFF_MAGIC 0x8664

/* names up to this length are stored immediately in symbol table entries */
#define COFF_NAMELEN 8

/* special "section numbers" changing the meaning of symbol table entry */
#define COFF_SN_UNDEFINED 0
#define COFF_SN_ABSOLUTE (-1)
#define COFF_SN_DEBUG (-2)

struct coff_file_header {
    uint16_t magic;
    uint16_t section_count;
    uint32_t timestamp;
    uint32_t symbol_table_offset;
    uint32_t symbol_count;
    uint16_t optional_header_size;
    uint16_t flags;
}
__attribute__((packed));

union coff_name {
    char immediate[8];
    struct 
    {
        uint32_t zeroes;
        uint32_t offset;
    } __attribute__((packed));
};

struct coff_string_table {
    uint32_t size;
    const char data[0];
} __attribute__((packed));

struct coff_section {
    union coff_name name;
    uint32_t physical_address;
    uint32_t virtual_address;
    uint32_t size;
    uint32_t data_offset;
    uint32_t relocations_offset;
    uint32_t line_numbers_offset;
    uint16_t relocation_count;
    uint16_t line_number_count;
    uint32_t flags;
} __attribute__((packed));

struct symbol {
    union coff_name name;
    uint32_t value;
    int16_t section_number;
    uint16_t type;
    uint8_t storage_class;
    uint8_t auxiliary_count;
}
__attribute__((packed));

struct image {
    struct coff_file_header* header;
    struct coff_section* sections;
    struct symbol* symbols;
    struct coff_string_table* strings;
    size_t size;
};

struct image*
image_load(void* addr, size_t size)
{
    struct coff_file_header *header = NULL;
    struct coff_section *sections = NULL;
    struct symbol *symbol_start = NULL, *symbol_end = NULL;
    struct image *image = NULL;
    
    if (size < sizeof(*image->header)) {
        LOG("ERROR: image size %" PRIzu " less than "
                "COFF file header size %" PRIzu,
                size, sizeof(*image->header));
        return NULL;
    }
    
    header = addr;

    if (header->magic != COFF_MAGIC) {
        LOG("ERROR: COFF magic: want %04x, got %04x",
                COFF_MAGIC, header->magic);
        return NULL;
    }

    sections = (struct coff_section*)(
            (uint8_t*)addr + (sizeof(*header) + header->optional_header_size));

    if ((char*)sections >= (char*)addr + size) {
        LOG("ERROR: optional header size %d exceeds image size %" PRIzu,
                header->optional_header_size, size);
        return NULL;
    }
    if ((char*)(sections + header->section_count) >= (char*)addr + size) {
        LOG("ERROR: section count %d too large", header->section_count);
        return NULL;
    }

    symbol_start = (struct symbol*)((char*)addr + header->symbol_table_offset);
    symbol_end = symbol_start + header->symbol_count;

    if (header->symbol_table_offset > size) {
        LOG("ERROR: symbol table offset %u larger than "
                "image size %" PRIzu, header->symbol_table_offset, size);
        return NULL;
    }
    if ((char*)symbol_end >= (char*)addr + size) {
        LOG("ERROR: symbol count %u too large", header->symbol_count);
        return NULL;
    }

    image = malloc(sizeof(*image));
    if (!image) {
        LOG("ERROR: memory allocation failed");
        return NULL;
    }

    image->header = header;
    image->sections = sections;
    image->symbols = symbol_start;
    image->strings = (struct coff_string_table*)symbol_end;
    image->size = size;
    return image;
}

static const char*
image_symbol_name(struct image* image, uint32_t i)
{
    struct symbol* symbol = &image->symbols[i];
    uint32_t offset;

    if (symbol->name.zeroes) {
        return symbol->name.immediate;
    }

    offset = symbol->name.offset;
    if (offset >= image->strings->size) {
        LOG("WARNING: offset %d of symbol #%u exceeds "
                "string table size %u", offset, i, image->strings->size);
        return NULL;
    }
    if (offset < sizeof(image->strings->size)) {
        LOG("WARNING: offset %d of symbol #%u is too small",
                offset, i);
        return NULL;
    }
    offset -= sizeof(image->strings->size);

    return &image->strings->data[offset];
}

struct symbol*
image_symbol_find(struct image* image, const char* name, struct symbol *from)
{
    uint32_t i = 0;
    struct symbol* symbol = NULL;
    size_t name_len = strlen(name);
    int may_be_immediate = name_len <= COFF_NAMELEN;

    if (from != NULL) {
        i = from - image->symbols;
        if (i >= image->header->symbol_count) {
            LOG("ERROR: initial symbol index %u exceeds symbol count %u",
                    i, image->header->symbol_count);
            return NULL;
        }
    }

    for (; i < image->header->symbol_count; i += symbol->auxiliary_count + 1) {
        const char* symbol_name = image_symbol_name(image, i);
        
        symbol = &image->symbols[i];

        if (symbol_name == NULL) {
            LOG("WARNING: unable to parse name for symbol #%u", i);
            continue;
        } else if ((symbol_name != symbol->name.immediate) &&
                !strncmp(symbol_name, name, name_len)) {
            return symbol;
        } else if (may_be_immediate &&
                !strncmp(symbol->name.immediate, name, name_len)) {
            return symbol;
        }
    }

    return NULL;
}

void*
image_symbol_get(struct image* image, struct symbol* symbol)
{
    struct coff_section *section = NULL;
    uint32_t value_offset;

    switch (symbol->section_number) {
    case COFF_SN_UNDEFINED:
        return NULL;
    case COFF_SN_ABSOLUTE:
        return (void*)((uintptr_t)symbol->value);
    case COFF_SN_DEBUG:
        return NULL;
    }

    if (symbol->section_number >= image->header->section_count) {
        LOG("ERROR: section number %d larger than section count %d",
                symbol->section_number, image->header->section_count);
        return NULL;
    }

    /* section numbers are 1-based */
    section = &image->sections[symbol->section_number - 1];

    value_offset = section->data_offset + symbol->value;
    if (value_offset >= image->size) {
        LOG("ERROR: section data offset (%u) and symbol offset (%u) yield"
                "file offset %u exceeding image size %" PRIzu,
                section->data_offset, symbol->value, value_offset, image->size);
        return NULL;
    }

    return (char*)image->header + value_offset;
}

void
image_unload(struct image *image)
{
    free(image);
}
