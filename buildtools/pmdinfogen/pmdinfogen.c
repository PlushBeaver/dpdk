/* Postprocess pmd object files to export hw support
 *
 * Copyright 2016 Neil Horman <nhorman@tuxdriver.com>
 * Based in part on modpost.c from the linux kernel
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License V2, incorporated herein by reference.
 *
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pmdinfogen.h"

static int use_stdin, use_stdout;

static void*
grab_file(const char *filename, size_t *size)
{
	struct stat st;
	void *map = NULL;
	int fd = -1;
	int ret;

	if (!use_stdin) {
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			LOG("ERROR: open() failed: %s\n",
					strerror(errno));
			return NULL;
		}
	} else {
		/* from stdin, use a temporary file to mmap */
		FILE *infile;
		char buffer[1024];
		int n;

		infile = tmpfile();
		if (infile == NULL) {
			LOG("ERROR: tmpfile() failed: %s\n",
					strerror(errno));
			return NULL;
		}

		fd = dup(fileno(infile));
		ret = errno;
		fclose(infile);
		if (fd < 0) {
			LOG("ERROR: dup() failed: %s\n",
					strerror(ret));
			return NULL;
		}

		n = read(STDIN_FILENO, buffer, sizeof(buffer));
		while (n > 0) {
			if (write(fd, buffer, n) != n) {
				LOG("ERROR: write() failed: %s\n",
						strerror(errno));
				goto failed;
			}
			n = read(STDIN_FILENO, buffer, sizeof(buffer));
		}
	}

	if (fstat(fd, &st)) {
		LOG("ERROR: fstat() failed: %s\n",
				strerror(errno));
		goto failed;
	}

	*size = st.st_size;
	map = file_map(fd, *size);

failed:
	close(fd);
	return map;
}

static void
release_file(void *file, unsigned long size)
{
	file_unmap(file, size);
}

static void
open_object_file(struct state *app, const char *filename)
{
	app->mapping = grab_file(filename, &app->size);
	if (!app->mapping) {
		LOG("ERROR: error opening %s: %s\n",
				filename, strerror(errno));
		exit(1);
	}
	
	app->image = image_load(app->mapping, app->size);
	if (!app->image) {
		/* diagnostics printed by image_load() */
		exit(1);
	}
}

static void
close_object_file(struct state *app)
{
	struct pmd_driver *tmp, *idx = app->drivers;
	release_file(app->mapping, app->size);
	while (idx) {
		tmp = idx->next;
		free(idx);
		idx = tmp;
	}
}

struct opt_tag {
	const char *suffix;
	const char *json_id;
};

static const struct opt_tag opt_tags[] = {
	{"_param_string_export", "params"},
	{"_kmod_dep_export", "kmod"},
};

static int
complete_pmd_entry(struct state *app, struct pmd_driver *drv)
{
	const char *tname;
	int i;
	char tmpsymname[128];
	struct symbol *tmpsym;

	drv->name = image_symbol_get(app->image, drv->name_symbol);

	for (i = 0; i < PMD_OPT_MAX; i++) {
		memset(tmpsymname, 0, 128);
		sprintf(tmpsymname, "__%s%s", drv->name, opt_tags[i].suffix);
		tmpsym = image_symbol_find(app->image, tmpsymname, NULL);
		if (!tmpsym)
			continue;
		drv->opt_vals[i] = image_symbol_get(app->image, tmpsym);
	}

	memset(tmpsymname, 0, 128);
	sprintf(tmpsymname, "__%s_pci_tbl_export", drv->name);

	tmpsym = image_symbol_find(app->image, tmpsymname, NULL);


	/*
	 * If this returns NULL, then this is a PMD_VDEV, because
	 * it has no pci table reference
	 */
	if (!tmpsym) {
		drv->pci_table = NULL;
		return 0;
	}

	tname = image_symbol_get(app->image, tmpsym);
	tmpsym = image_symbol_find(app->image, tname, NULL);
	if (!tmpsym)
		return -ENOENT;

	drv->pci_table = (struct rte_pci_id *)image_symbol_get(app->image, tmpsym);
	if (!drv->pci_table)
		return -ENOENT;

	return 0;
}

static int
locate_pmd_entries(struct state *app)
{
	struct symbol *last = NULL;
	struct pmd_driver *new;

	app->drivers = NULL;

	do {
		new = calloc(sizeof(struct pmd_driver), 1);
		if (new == NULL) {
			LOG("ERROR: calloc");
			return -1;
		}

		new->name_symbol = image_symbol_find(app->image, "this_pmd_name", NULL);
		if (!new->name_symbol)
			free(new);
		else {
			if (complete_pmd_entry(app, new)) {
				LOG("WARNING: failed to complete PMD entry");
				free(new);
			} else {
				new->next = app->drivers;
				app->drivers = new;
			}
		}
	} while (last);

	return 0;
}

static void
output_pmd_info_string(struct state *app, char *outfile)
{
	FILE *ofd;
	struct pmd_driver *drv;
	struct rte_pci_id *pci_ids;
	int idx = 0;

	if (use_stdout)
		ofd = stdout;
	else {
		ofd = fopen(outfile, "w+");
		if (!ofd) {
			fprintf(stderr, "Unable to open output file\n");
			return;
		}
	}

	drv = app->drivers;

	while (drv) {
		fprintf(ofd, "const char %s_pmd_info[] __attribute__((used)) = "
			"\"PMD_INFO_STRING= {",
			drv->name);
		fprintf(ofd, "\\\"name\\\" : \\\"%s\\\", ", drv->name);

		for (idx = 0; idx < PMD_OPT_MAX; idx++) {
			if (drv->opt_vals[idx])
				fprintf(ofd, "\\\"%s\\\" : \\\"%s\\\", ",
					opt_tags[idx].json_id,
					drv->opt_vals[idx]);
		}

		pci_ids = drv->pci_table;
		fprintf(ofd, "\\\"pci_ids\\\" : [");

		while (pci_ids && pci_ids->device_id) {
			fprintf(ofd, "[%d, %d, %d, %d]",
				pci_ids->vendor_id, pci_ids->device_id,
				pci_ids->subsystem_vendor_id,
				pci_ids->subsystem_device_id);
			pci_ids++;
			if (pci_ids->device_id)
				fprintf(ofd, ",");
			else
				fprintf(ofd, " ");
		}
		fprintf(ofd, "]}\";\n");
		drv = drv->next;
	}

	fclose(ofd);
}

int main(int argc, char **argv)
{
	struct state app;
	int rc = 1;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <object file> <c output file>\n",
			basename(argv[0]));
		exit(127);
	}
	use_stdin = !strcmp(argv[1], "-");
	use_stdout = !strcmp(argv[2], "-");
	open_object_file(&app, argv[1]);

	if (locate_pmd_entries(&app) < 0)
		exit(1);

	if (app.drivers) {
		output_pmd_info_string(&app, argv[2]);
		rc = 0;
	} else {
		fprintf(stderr, "No drivers registered\n");
	}

	close_object_file(&app);
	exit(rc);
}
