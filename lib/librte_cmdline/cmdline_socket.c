/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright (c) 2009, Olivier MATZ <zer0@droids-corp.org>
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>

#include "cmdline_parse.h"
#include "cmdline_private.h"
#include "cmdline_rdline.h"
#include "cmdline_socket.h"
#include "cmdline.h"

/* Disables buffering and echoing on the terminal.
 * Saves previous terminal settings to `oldterm`.
 * On Windows, also switches console to emulate VT100.
 */
static void
cmdline_adjust_terminal(struct cmdline_terminal* oldterm)
{
#ifndef RTE_EXEC_ENV_WINDOWS
	struct termios term;

	tcgetattr(0, &oldterm->termios);
	memcpy(&term, &oldterm->termios, sizeof(term));
	term.c_lflag &= ~(ICANON | ECHO | ISIG);
	tcsetattr(0, TCSANOW, &term);

	setbuf(stdin, NULL);
#else
	HANDLE handle;
	DWORD mode;

	ZeroMemory(oldterm, sizeof(*oldterm));

	/* Detect console input, set it up and make it emulate VT100. */
	handle = GetStdHandle(STD_INPUT_HANDLE);
	if (GetConsoleMode(handle, &mode)) {
		oldterm->is_console_input = 1;
		oldterm->input_mode = mode;

		mode &= ~(
			ENABLE_LINE_INPUT |      /* no line buffering */
			ENABLE_ECHO_INPUT |      /* no echo */
			ENABLE_PROCESSED_INPUT | /* pass Ctrl+C to program */
			ENABLE_MOUSE_INPUT |     /* no mouse events */
			ENABLE_WINDOW_INPUT);    /* no window resize events */
		mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
		SetConsoleMode(handle, mode);
	}

	/* Detect console output and make it emulate VT100. */
	handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (GetConsoleMode(handle, &mode)) {
		oldterm->is_console_output = 1;
		oldterm->output_mode = mode;

		mode &= ~ENABLE_WRAP_AT_EOL_OUTPUT;
		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		SetConsoleMode(handle, mode);
	}
#endif
}

/* Restores saved terminal settings. */
static void
cmdline_restore_terminal(const struct cmdline_terminal *oldterm) {
#ifndef RTE_EXEC_ENV_WINDOWS
	tcsetattr(fileno(stdin), TCSANOW, &oldterm->termios);
#else
	if (oldterm->is_console_input) {
		HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
		SetConsoleMode(handle, oldterm->input_mode);
	}
	if (oldterm->is_console_output) {
		HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleMode(handle, oldterm->output_mode);
	}
#endif
}

struct cmdline *
cmdline_file_new(cmdline_parse_ctx_t *ctx, const char *prompt, const char *path)
{
	int fd;

	/* everything else is checked in cmdline_new() */
	if (!path)
		return NULL;

	fd = open(path, O_RDONLY, 0);
	if (fd < 0) {
		dprintf("open() failed\n");
		return NULL;
	}
	return cmdline_new(ctx, prompt, fd, -1);
}

struct cmdline *
cmdline_stdin_new(cmdline_parse_ctx_t *ctx, const char *prompt)
{
	struct cmdline *cl;
	struct cmdline_terminal oldterm;

	cmdline_adjust_terminal(&oldterm);

	cl = cmdline_new(ctx, prompt, 0, 1);

	if (cl) {
		memcpy(&cl->oldterm, &oldterm, sizeof(oldterm));
	}

	return cl;
}

void
cmdline_stdin_exit(struct cmdline *cl)
{
	if (!cl)
		return;

	cmdline_restore_terminal(&cl->oldterm);
}
