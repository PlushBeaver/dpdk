
/* Postprocess PMD object files to export hardware support.
 *
 * Copyright 2016 Neil Horman <nhorman@tuxdriver.com>
 * Based in part on modpost.c from the linux kernel
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License V2, incorporated herein by reference.
 *
 */

#include <stdio.h>

#include <rte_pci_id.h>

/* Object file parsing facilities are linked with target implementation. */

struct image;
struct symbol;

struct image* image_load(void* addr, size_t size);
struct symbol* image_symbol_find(
		struct image* image, const char* name, struct symbol *from);
void* image_symbol_get(struct image* image, struct symbol* symbol);
void image_unload(struct image* image);


/* RTE_LOG() would require linking of host program to target libraries. */

#define LOG(fmt, ...) \
        do { \
            fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
            fflush(stderr); \
        } while (0)

#ifndef NDEBUG
#define LOG_DEBUG(fmt, ...) LOG("DEBUG: " fmt, ##__VA_ARGS__)
#else
#define LOG_DEBUG(...)
#endif

#ifdef _WIN32
#define PRIzu PRIu64
#else
#define PRIzu "zu"
#endif

void* file_map(int fd, size_t size);
void file_unmap(void* virt, size_t size);


/* Application state and parameters. */

enum opt_params {
	PMD_PARAM_STRING = 0,
	PMD_KMOD_DEP,
	PMD_OPT_MAX
};

struct pmd_driver {
	struct symbol *name_symbol;
	const char *name;
	struct rte_pci_id *pci_table;
	struct pmd_driver *next;
	const char *opt_vals[PMD_OPT_MAX];
};

struct state {
	void* mapping;
	size_t size;
	struct image* image;
	struct pmd_driver *drivers;
};
