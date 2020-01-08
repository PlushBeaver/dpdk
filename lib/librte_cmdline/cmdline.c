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
#include <errno.h>
#include <netinet/in.h>

#ifndef RTE_EXEC_ENV_WINDOWS
#include <poll.h>
#include <termios.h>
#else
#include <rte_windows.h>
#endif

#include <rte_string_fns.h>

#include "cmdline_parse.h"
#include "cmdline_private.h"
#include "cmdline_rdline.h"
#include "cmdline.h"

static void
cmdline_valid_buffer(struct rdline *rdl, const char *buf,
		     __attribute__((unused)) unsigned int size)
{
	struct cmdline *cl = rdl->opaque;
	int ret;
	ret = cmdline_parse(cl, buf);
	if (ret == CMDLINE_PARSE_AMBIGUOUS)
		cmdline_printf(cl, "Ambiguous command\n");
	else if (ret == CMDLINE_PARSE_NOMATCH)
		cmdline_printf(cl, "Command not found\n");
	else if (ret == CMDLINE_PARSE_BAD_ARGS)
		cmdline_printf(cl, "Bad arguments\n");
}

static int
cmdline_complete_buffer(struct rdline *rdl, const char *buf,
			char *dstbuf, unsigned int dstsize,
			int *state)
{
	struct cmdline *cl = rdl->opaque;
	return cmdline_complete(cl, buf, state, dstbuf, dstsize);
}

int
cmdline_write_char(struct rdline *rdl, char c)
{
	int ret = -1;
	struct cmdline *cl;

	if (!rdl)
		return -1;

	cl = rdl->opaque;

	if (cl->s_out >= 0)
		ret = write(cl->s_out, &c, 1);

	return ret;
}

struct rdline*
cmdline_get_rdline(struct cmdline *cl)
{
	return &cl->rdl;
}

void
cmdline_set_prompt(struct cmdline *cl, const char *prompt)
{
	if (!cl || !prompt)
		return;
	strlcpy(cl->prompt, prompt, sizeof(cl->prompt));
}

struct cmdline *
cmdline_new(cmdline_parse_ctx_t *ctx, const char *prompt, int s_in, int s_out)
{
	struct cmdline *cl;
	int ret;

	if (!ctx || !prompt)
		return NULL;

	cl = malloc(sizeof(struct cmdline));
	if (cl == NULL)
		return NULL;
	memset(cl, 0, sizeof(struct cmdline));
	cl->s_in = s_in;
	cl->s_out = s_out;
	cl->ctx = ctx;

	ret = rdline_init(&cl->rdl, cmdline_write_char, cmdline_valid_buffer,
			cmdline_complete_buffer);
	if (ret != 0) {
		free(cl);
		return NULL;
	}

	cl->rdl.opaque = cl;
	cmdline_set_prompt(cl, prompt);
	rdline_newline(&cl->rdl, cl->prompt);

	return cl;
}

void
cmdline_free(struct cmdline *cl)
{
	dprintf("called\n");

	if (!cl)
		return;

	if (cl->s_in > 2)
		close(cl->s_in);
	if (cl->s_out != cl->s_in && cl->s_out > 2)
		close(cl->s_out);
	free(cl);
}

void
cmdline_printf(const struct cmdline *cl, const char *fmt, ...)
{
	va_list ap;

	if (!cl || !fmt)
		return;

	if (cl->s_out < 0)
		return;
	va_start(ap, fmt);
	vdprintf(cl->s_out, fmt, ap);
	va_end(ap);
}

int
cmdline_in(struct cmdline *cl, const char *buf, int size)
{
	const char *history, *buffer;
	size_t histlen, buflen;
	int ret = 0;
	int i, same;

	if (!cl || !buf)
		return -1;

	for (i=0; i<size; i++) {
		ret = rdline_char_in(&cl->rdl, buf[i]);

		if (ret == RDLINE_RES_VALIDATED) {
			buffer = rdline_get_buffer(&cl->rdl);
			history = rdline_get_history_item(&cl->rdl, 0);
			if (history) {
				histlen = strnlen(history, RDLINE_BUF_SIZE);
				same = !memcmp(buffer, history, histlen) &&
					buffer[histlen] == '\n';
			}
			else
				same = 0;
			buflen = strnlen(buffer, RDLINE_BUF_SIZE);
			if (buflen > 1 && !same)
				rdline_add_history(&cl->rdl, buffer);
			rdline_newline(&cl->rdl, cl->prompt);
		}
		else if (ret == RDLINE_RES_EOF)
			return -1;
		else if (ret == RDLINE_RES_EXITED)
			return -1;
	}
	return i;
}

void
cmdline_quit(struct cmdline *cl)
{
	if (!cl)
		return;
	rdline_quit(&cl->rdl);
}

/* Checks if a single character can be read from input. */
static int cmdline_poll_char(struct cmdline *cl);

/* Reads one character from input. */
static ssize_t cmdline_read_char(struct cmdline *cl, char *c);

int
cmdline_poll(struct cmdline *cl)
{
	int status;
	ssize_t read_status;
	char c;

	if (!cl)
		return -EINVAL;
	else if (cl->rdl.status == RDLINE_EXITED)
		return RDLINE_EXITED;

	status = cmdline_poll_char(cl);
	if (status < 0)
		return status;
	else if (status > 0) {
		c = -1;
		read_status = cmdline_read_char(cl, &c);
		if (read_status < 0)
			return read_status;

		status = cmdline_in(cl, &c, 1);
		if (status < 0 && cl->rdl.status != RDLINE_EXITED)
			return status;
	}

	return cl->rdl.status;
}

void
cmdline_interact(struct cmdline *cl)
{
	char c;

	if (!cl)
		return;

	c = -1;
	while (1) {
		if (cmdline_read_char(cl, &c) <= 0)
			break;
		if (cmdline_in(cl, &c, 1) < 0)
			break;
	}
}

#ifndef RTE_EXEC_ENV_WINDOWS

static int
cmdline_poll_char(struct cmdline *cl)
{
	struct pollfd pfd;

	pfd.fd = cl->s_in;
	pfd.events = POLLIN;
	pfd.revents = 0;

	return poll(&pfd, 1, 0);
}

static ssize_t
cmdline_read_char(struct cmdline *cl, char *c)
{
	return read(cl->s_in, c, 1);
}

#else /* POSIX */

static int
cmdline_is_key_down(const INPUT_RECORD* record) {
	return (record->EventType == KEY_EVENT) &&
		record->Event.KeyEvent.bKeyDown;
}

static int
cmdline_poll_char_console(HANDLE handle)
{
	INPUT_RECORD record;
	DWORD events;

	if (!PeekConsoleInput(handle, &record, 1, &events)) {
		/* Simulate poll(3) behavior on EOF. */
		if (GetLastError() == ERROR_HANDLE_EOF)
			return 0;

		errno = EIO;
		return -1;
	}
	
	if ((events == 0) || !cmdline_is_key_down(&record)) {
		errno = EAGAIN;
		return 0;
	}
	return 1;
}

static int
cmdline_poll_char_file(HANDLE handle)
{
	char dummy;
	DWORD bytes_read;
	OVERLAPPED overlapped;

	ZeroMemory(&overlapped, sizeof(overlapped));
	if (!ReadFile(handle, &dummy, 0, NULL, &overlapped)) {
		switch (GetLastError()) {
		case ERROR_INSUFFICIENT_BUFFER:
			/* Operation completed immediately. */
			return 1;
		case ERROR_IO_PENDING:
			/* Asynchronous operation started. */
			break;
		default:
			/* Failed to start an asynchronous operation. */
			errno = EIO;
			return -1;
		}
	}

	if (GetOverlappedResult(
		/* Operation completed, result does not matter. */
		handle, &overlapped, &bytes_read, FALSE)) {
		return 1;
	}

	CancelIo(handle);

	/* Simulate poll(3) behavior with zero timeout. */
	errno = EAGAIN;
	return 0;
}

static int
cmdline_poll_char(struct cmdline *cl)
{
	HANDLE handle = (HANDLE)_get_osfhandle(cl->s_in);
	return cl->oldterm.is_console ?
		cmdline_poll_char_console(handle) :
		cmdline_poll_char_file(handle);
}

static ssize_t
cmdline_read_char(struct cmdline *cl, char *c)
{
	HANDLE handle;
	INPUT_RECORD record;
	KEY_EVENT_RECORD *key;
    	DWORD events;

	if (!cl->oldterm.is_console)
		return read(cl->s_in, c, 1);

	/* Return repeated strokes from previous event. */
	if (cl->repeat_count > 0) {
		*c = cl->repeated_char;
		cl->repeat_count--;
		return 1;
	}

	handle = (HANDLE)_get_osfhandle(cl->s_in);
	key = &record.Event.KeyEvent;
	do {
		if (!ReadConsoleInput(handle, &record, 1, &events)) {
			if (GetLastError() == ERROR_HANDLE_EOF)
				return 0;

			errno = EIO;
			return -1;
		}
		// printf("down=%u count=%u\n", key->bKeyDown, key->wRepeatCount);
	} while (!cmdline_is_key_down(&record));

	*c = key->uChar.AsciiChar;

	/* Save repeated strokes from a single event. */
	if (key->wRepeatCount > 1) {
		cl->repeated_char = *c;
		cl->repeat_count = key->wRepeatCount - 1;
	}

	return 1;
}

#endif /* Windows */
