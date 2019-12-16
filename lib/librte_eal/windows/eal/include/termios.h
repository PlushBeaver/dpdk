#ifndef _TERMIOS_H_
#define _TERMIOS_H_

#include <inttypes.h>

struct termios {
    unsigned long int c_lflag;
};

#define ICANON 0x0002 /* ENABLE_LINE_INPUT */
#define ECHO   0x0004 /* ENABLE_ECHO_INPUT */
#define ISIG   0      /* ignored */

#define TCSANOW 1

int tcgetattr(int fd, struct termios *termios);
int tcsetattr(int fd, int actions, const struct termios *termios);

#endif
