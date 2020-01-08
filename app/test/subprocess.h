/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _PROCESS_H_
#define _PROCESS_H_

#include "test.h"

#ifndef RTE_EXEC_ENV_WINDOWS /* POSIX implementation */

#include <errno.h>  /* errno */
#include <limits.h> /* PATH_MAX */
#include <libgen.h> /* basename et al */
#include <stdlib.h> /* NULL */
#include <string.h> /* strerror */
#include <unistd.h> /* readlink */
#include <dirent.h>
#include <sys/wait.h>

#include <rte_string_fns.h> /* strlcpy */

#ifdef RTE_EXEC_ENV_FREEBSD
#define self "curproc"
#define exe "file"
#else
#define self "self"
#define exe "exe"
#endif

#ifdef RTE_LIBRTE_PDUMP
#include <pthread.h>
extern void *send_pkts(void *empty);
extern uint16_t flag_for_send_pkts;
#endif

/*
 * launches a second copy of the test process using the given argv parameters,
 * which should include argv[0] as the process name. To identify in the
 * subprocess the source of the call, the env_value parameter is set in the
 * environment as $RTE_TEST
 */
static inline int
process_dup(const char *const argv[], int numargs, const char *env_value)
{
	int num;
	char *argv_cpy[numargs + 1];
	int i, status;
	char path[32];
#ifdef RTE_LIBRTE_PDUMP
	pthread_t thread;
#endif

	pid_t pid = fork();
	if (pid < 0)
		return -1;
	else if (pid == 0) {
		/* make a copy of the arguments to be passed to exec */
		for (i = 0; i < numargs; i++)
			argv_cpy[i] = strdup(argv[i]);
		argv_cpy[i] = NULL;
		num = numargs;

#ifdef RTE_EXEC_ENV_LINUX
		{
			const char *procdir = "/proc/" self "/fd/";
			struct dirent *dirent;
			char *endptr;
			int fd, fdir;
			DIR *dir;

			/* close all open file descriptors, check /proc/self/fd
			 * to only call close on open fds. Exclude fds 0, 1 and
			 * 2
			 */
			dir = opendir(procdir);
			if (dir == NULL) {
				rte_panic("Error opening %s: %s\n", procdir,
						strerror(errno));
			}

			fdir = dirfd(dir);
			if (fdir < 0) {
				status = errno;
				closedir(dir);
				rte_panic("Error %d obtaining fd for dir %s: %s\n",
						fdir, procdir,
						strerror(status));
			}

			while ((dirent = readdir(dir)) != NULL) {
				errno = 0;
				fd = strtol(dirent->d_name, &endptr, 10);
				if (errno != 0 || endptr[0] != '\0') {
					printf("Error converting name fd %d %s:\n",
						fd, dirent->d_name);
					continue;
				}

				if (fd == fdir || fd <= 2)
					continue;

				close(fd);
			}
			closedir(dir);
		}
#endif
		printf("Running binary with argv[]:");
		for (i = 0; i < num; i++)
			printf("'%s' ", argv_cpy[i]);
		printf("\n");

		/* set the environment variable */
		if (setenv(RECURSIVE_ENV_VAR, env_value, 1) != 0)
			rte_panic("Cannot export environment variable\n");

		strlcpy(path, "/proc/" self "/" exe, sizeof(path));
		if (execv(path, argv_cpy) < 0) {
			if (errno == ENOENT) {
				printf("Could not find '%s', is procfs mounted?\n",
						path);
			}
			rte_panic("Cannot exec: %s\n", strerror(errno));
		}
	}
	/* parent process does a wait */
#ifdef RTE_LIBRTE_PDUMP
	if ((strcmp(env_value, "run_pdump_server_tests") == 0))
		pthread_create(&thread, NULL, &send_pkts, NULL);
#endif

	while (wait(&status) != pid)
		;
#ifdef RTE_LIBRTE_PDUMP
	if ((strcmp(env_value, "run_pdump_server_tests") == 0)) {
		flag_for_send_pkts = 0;
		pthread_join(thread, NULL);
	}
#endif
	return status;
}

/* FreeBSD doesn't support file prefixes, so force compile failures for any
 * tests attempting to use this function on FreeBSD.
 */
#ifdef RTE_EXEC_ENV_LINUX
static char *
get_current_prefix(char *prefix, int size)
{
	char path[PATH_MAX] = {0};
	char buf[PATH_MAX] = {0};

	/* get file for config (fd is always 3) */
	snprintf(path, sizeof(path), "/proc/self/fd/%d", 3);

	/* return NULL on error */
	if (readlink(path, buf, sizeof(buf)) == -1)
		return NULL;

	/* get the prefix */
	snprintf(prefix, size, "%s", basename(dirname(buf)));

	return prefix;
}
#endif

#else /* Windows implementation */

#include <rte_windows.h>

static inline int
process_dup(const char *const argv[], int numargs, const char *env_value)
{
	char exe_path[PATH_MAX];
	char *env = NULL, *new_env = NULL, *new_cmdline = NULL, *env_var;
	size_t env_size, new_env_size, env_string_size, new_cmdline_size;
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	DWORD exit_code;
	int i, ret = -1;

	RTE_SET_USED(argv);
	RTE_SET_USED(numargs);

	if (!GetModuleFileNameA(NULL, exe_path, sizeof(exe_path))) {
		printf("Cannot get current executable path\n");
		goto exit;
	}

	env = GetEnvironmentStrings();
	if (env == NULL) {
		printf("Cannot get current process environment\n");
		goto exit;
	}

	env_var = env;
	while (env_var[0] != '\0') {
		env_var += strlen(env_var) + 1;
	}
	env_size = env_var - env;

	new_cmdline_size = 0;
	for (i = 0; i < numargs; i++) {
		new_cmdline_size += strlen(argv[i]) + 1;
	}

	new_cmdline = malloc(new_cmdline_size);
	if (new_cmdline == NULL) {
		printf("Cannot allocate new process command line\n");
		goto exit;
	}

	new_cmdline[0] = '\0';
	for (i = 0; i < numargs; i++) {
		strcat(new_cmdline, argv[i]);
		strcat(new_cmdline, " ");
	}

	env_string_size = strlen(RECURSIVE_ENV_VAR) + strlen(env_value) + 1;
	new_env_size = env_size + env_string_size + 1; /* + empty last string */
	new_env = malloc(new_env_size);
	if (new_env == NULL) {
		printf("Cannot allocate new process environment\n");
		goto exit;
	}

	memcpy(new_env, env, env_size);
	sprintf(new_env + env_size, "%s=%s", RECURSIVE_ENV_VAR, env_value);
	new_env[new_env_size - 1] = '\0';

	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	pinfo.hProcess = INVALID_HANDLE_VALUE; /* marker for cleanup */
	if (!CreateProcessA(NULL, new_cmdline, NULL, NULL, FALSE, 0, new_env,
			NULL, &sinfo, &pinfo)) {
		printf("Cannot create process\n");
		goto exit;
	}

	WaitForSingleObject(pinfo.hProcess, INFINITE);

	if (!GetExitCodeProcess(pinfo.hProcess, &exit_code)) {
		printf("Cannot get process exit code\n");
		goto exit;
	}

	ret = (int)exit_code;

exit:
	if (env != NULL) {
		FreeEnvironmentStrings(env);
	}
	if (new_env != NULL) {
		free(new_env);
	}
	if (new_cmdline != NULL) {
		free(new_cmdline);
	}
	if (pinfo.hProcess != INVALID_HANDLE_VALUE) {
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
	}
	return ret;
}

#endif /* POSIX or Windows */
#endif /* _PROCESS_H_ */
