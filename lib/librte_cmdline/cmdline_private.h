#ifndef _CMDLINE_PRIVATE_H_
#define _CMDLINE_PRIVATE_H_

#include <termios.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>

struct cmdline {
	int s_in;
	int s_out;
	cmdline_parse_ctx_t *ctx;
	struct rdline rdl;
	char prompt[RDLINE_PROMPT_SIZE];
	struct termios oldterm;
};

#endif
