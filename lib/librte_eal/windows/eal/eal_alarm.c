#include <rte_alarm.h>
#include <rte_errno.h>
#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_os.h>
#include <rte_spinlock.h>
#include <rte_windows.h>

#include "eal_private.h"

typedef ULARGE_INTEGER alarm_time;

/* Windows timers operate 100ns intervals since January 1, 1601 */
#define ALARM_TICKS_FROM_US(us) (10 * (us))

/* Intervals can be compared as ULARGE_INTEGERs. */
#define ALARM_TIME_COMPARE(lhs, op, rhs) ((lhs).QuadPart op (rhs).QuadPart)

struct alarm_entry {
	LIST_ENTRY(alarm_entry) next;
	alarm_time time;
	rte_eal_alarm_callback cb_fn;
	void *cb_arg;
	volatile uint8_t executing;
	volatile pthread_t executing_id;
};

static LIST_HEAD(alarm_list, alarm_entry) alarm_list = LIST_HEAD_INITIALIZER();
static rte_spinlock_t alarm_list_lk = RTE_SPINLOCK_INITIALIZER;

static struct rte_intr_handle intr_handle = {.fd = RTE_INVALID_FD };
static int handler_registered = 0;

static alarm_time get_current_time(void);
static void eal_alarm_callback(void *arg);

int
rte_eal_alarm_init(void)
{
    intr_handle.type = RTE_INTR_HANDLE_ALARM;
	intr_handle.fd = CreateWaitableTimer(NULL, FALSE, NULL);
	if (intr_handle.fd == INVALID_HANDLE_VALUE) {
        rte_errno = GetLastError();
        RTE_LOG(DEBUG, EAL, "CreateWaitableTimer() failed, "
                "GetLastError() is %d\n", rte_errno);
		return -1;
    }

	return 0;
}

static alarm_time
get_current_time(void)
{
    FILETIME ft;
    ULARGE_INTEGER now;

    GetSystemTimePreciseAsFileTime(&ft);
    now.LowPart = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;

    return now;
}

static void
eal_alarm_callback(void *arg __rte_unused)
{
    ULARGE_INTEGER now;
	struct alarm_entry *ap;

	rte_spinlock_lock(&alarm_list_lk);
	while ((ap = LIST_FIRST(&alarm_list)) != NULL) {
        now = get_current_time();
		if (ALARM_TIME_COMPARE(now, >=, ap->time)) {
            break;
        }

		ap->executing = 1;
		ap->executing_id = pthread_self();
		rte_spinlock_unlock(&alarm_list_lk);

		ap->cb_fn(ap->cb_arg);

		rte_spinlock_lock(&alarm_list_lk);

		LIST_REMOVE(ap, next);
		free(ap);
	}

	if (!LIST_EMPTY(&alarm_list)) {
		LARGE_INTEGER due;

		ap = LIST_FIRST(&alarm_list);
        due.HighPart = (LONG)now.HighPart;
        due.LowPart = now.LowPart;
        SetWaitableTimer(intr_handle.fd, &due, 0, NULL, NULL, FALSE);
	}
	rte_spinlock_unlock(&alarm_list_lk);
}

int
rte_eal_alarm_set(uint64_t us, rte_eal_alarm_callback cb_fn, void *cb_arg)
{
    alarm_time now;
	BOOL ret = TRUE;
	struct alarm_entry *ap, *new_alarm;

	/* Check parameters, including that us won't cause a uint64_t overflow */
	if (us < 1 || us > (UINT64_MAX - US_PER_S) || cb_fn == NULL)
		return -EINVAL;

	new_alarm = calloc(1, sizeof(*new_alarm));
	if (new_alarm == NULL)
		return -ENOMEM;

	/* use current time to calculate absolute time of alarm */
    now = get_current_time();

	new_alarm->cb_fn = cb_fn;
	new_alarm->cb_arg = cb_arg;
    new_alarm->time = now;
    new_alarm->time.QuadPart += ALARM_TICKS_FROM_US(us);

	rte_spinlock_lock(&alarm_list_lk);
	if (!handler_registered) {
		/* registration can fail, callback can be registered later */
		if (rte_intr_callback_register(&intr_handle,
				eal_alarm_callback, NULL) == 0)
			handler_registered = 1;
	}

	if (LIST_EMPTY(&alarm_list))
		LIST_INSERT_HEAD(&alarm_list, new_alarm, next);
	else {
		LIST_FOREACH(ap, &alarm_list, next) {
			if (ALARM_TIME_COMPARE(ap->time, >, now)) {
				LIST_INSERT_BEFORE(ap, new_alarm, next);
				break;
			}
			if (LIST_NEXT(ap, next) == NULL) {
				LIST_INSERT_AFTER(ap, new_alarm, next);
				break;
			}
		}
	}

	if (LIST_FIRST(&alarm_list) == new_alarm) {
        /* Negative value indicatres relative time. */
        LARGE_INTEGER timeout;
        timeout.QuadPart = -ALARM_TICKS_FROM_US(us);
		ret &= SetWaitableTimer(
                intr_handle.fd, &timeout, 0, NULL, NULL, FALSE);
	}
	rte_spinlock_unlock(&alarm_list_lk);

	return ret ? 0 : -1;
}

/* TODO: verbatim copy of Linux implementation, extract common code. */
int
rte_eal_alarm_cancel(rte_eal_alarm_callback cb_fn, void *cb_arg)
{
    struct alarm_entry *ap, *ap_prev;
	int count = 0;
	int err = 0;
	int executing;

	if (!cb_fn) {
		rte_errno = EINVAL;
		return -1;
	}

	do {
		executing = 0;
		rte_spinlock_lock(&alarm_list_lk);
		/* remove any matches at the start of the list */
		while ((ap = LIST_FIRST(&alarm_list)) != NULL &&
				cb_fn == ap->cb_fn &&
				(cb_arg == (void *)-1 || cb_arg == ap->cb_arg)) {

			if (ap->executing == 0) {
				LIST_REMOVE(ap, next);
				free(ap);
				count++;
			} else {
				/* If calling from other context, mark that alarm is executing
				 * so loop can spin till it finish. Otherwise we are trying to
				 * cancel our self - mark it by EINPROGRESS */
				if (pthread_equal(ap->executing_id, pthread_self()) == 0)
					executing++;
				else
					err = EINPROGRESS;

				break;
			}
		}
		ap_prev = ap;

		/* now go through list, removing entries not at start */
		LIST_FOREACH(ap, &alarm_list, next) {
			/* this won't be true first time through */
			if (cb_fn == ap->cb_fn &&
					(cb_arg == (void *)-1 || cb_arg == ap->cb_arg)) {

				if (ap->executing == 0) {
					LIST_REMOVE(ap, next);
					free(ap);
					count++;
					ap = ap_prev;
				} else if (pthread_equal(ap->executing_id, pthread_self()) == 0)
					executing++;
				else
					err = EINPROGRESS;
			}
			ap_prev = ap;
		}
		rte_spinlock_unlock(&alarm_list_lk);
	} while (executing != 0);

	if (count == 0 && err == 0)
		rte_errno = ENOENT;
	else if (err)
		rte_errno = err;

	return count;
}