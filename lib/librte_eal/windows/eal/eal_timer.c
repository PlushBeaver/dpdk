#include <assert.h>

#include <rte_os.h>
#include <rte_windows.h>

#include "eal_private.h"

enum timer_source eal_timer_source = EAL_TIMER_TSC;

uint64_t
get_tsc_freq(void)
{
    LARGE_INTEGER freq;
    BOOL ret;

    /* MSDN:
     *  On systems that run Windows XP or later, the function will
     *  always succeed and will thus never return zero.
     */
    ret = QueryPerformanceFrequency(&freq);
    assert(ret);

    return freq.QuadPart;
}

int
rte_eal_timer_init(void)
{
	set_tsc_freq();
	return 0;
}