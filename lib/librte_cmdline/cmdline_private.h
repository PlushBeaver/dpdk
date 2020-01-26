#ifndef _CMDLINE_PRIVATE_H_
#define _CMDLINE_PRIVATE_H_

#ifndef RTE_EXEC_ENV_WINDOWS
#include <termios.h>
#else
#include <rte_windows.h>
#endif

#include <cmdline_rdline.h>
#include <cmdline_parse.h>

/* Terminal mode. */
struct cmdline_terminal {
#ifndef RTE_EXEC_ENV_WINDOWS
	struct termios termios;
#else
	DWORD input_mode;
	DWORD output_mode;
	int is_console_input;
	int is_console_output;
#endif
};

struct cmdline {
	int s_in;
	int s_out;
	cmdline_parse_ctx_t *ctx;
	struct rdline rdl;
	char prompt[RDLINE_PROMPT_SIZE];
	struct cmdline_terminal oldterm;
#ifdef RTE_EXEC_ENV_WINDOWS
	char repeated_char;
	WORD repeat_count;
#endif
};

#endif
