/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdint.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_os.h>
#include <rte_windows.h>

#include "eal_private.h"

static DWORD
process_rte_logs(LPVOID param)
{
	HANDLE log = (HANDLE)param;
	char buffer[512];
	DWORD bytes_read;

	while (ReadFile(log, buffer, sizeof(buffer), &bytes_read, NULL)) {
		fwrite(buffer, 1, bytes_read, stdout);
		fflush(stdout);
	}

	return GetLastError();
}

/*
 * There is no portable way to create custom FILE* on Windows.
 * Receive messages from EAL in a non-EAL thread via a pipe.
 */
int
rte_eal_log_init(__rte_unused const char *id, __rte_unused int facility)
{
	HANDLE read_end = INVALID_HANDLE_VALUE;
	HANDLE write_end = INVALID_HANDLE_VALUE;
	int log_fd = -1;
	FILE *log_stream = NULL;
	HANDLE thread = INVALID_HANDLE_VALUE;

	if (!CreatePipe(&read_end, &write_end, NULL, 1)) {
		fprintf(stderr, "CreatePipe() failed, error %lu", GetLastError());
		goto error;
	}

	log_fd = _open_osfhandle((intptr_t)write_end, _O_APPEND);
	if (log_fd == -1) {
		fprintf(stderr, "_open_osfhandle() failed, error %lu", GetLastError());
		goto error;
	}

	log_stream = _fdopen(log_fd, "a");
	if (log_stream == NULL) {
		fprintf(stderr, "_fdopen() failed, error %lu", GetLastError());
		goto error;
	}

	thread = CreateThread(NULL, 0, process_rte_logs, (LPVOID)read_end, 0, NULL);
	if (thread == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "CreateThread() failed, error %lu", GetLastError());
		goto error;
	}

	eal_log_set_default(log_stream);

	return 0;

error:
	if (log_stream != NULL) {
		/* closing log_stream also closes log_fd */
		fclose(log_stream);
	} else if (log_fd != -1) {
		/* log_fd owns write end handle */
		_close(log_fd);
	} else if (write_end != INVALID_HANDLE_VALUE) {
		/* only necessary until handle ownership is treansferred to log_fd */
		CloseHandle(write_end);
	}

	/* read end handle ownership is retained */
	if (read_end != INVALID_HANDLE_VALUE)
		CloseHandle(read_end);
	
	return -1;
}
