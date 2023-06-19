/*
 * Copyright (c) 2010-2014, Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Macros to abstract toolchain specific capabilities
 *
 * This file contains various macros to abstract compiler capabilities that
 * utilize toolchain specific attributes and/or pragmas.
 */

#ifndef _ZEPHYR_POLLING_UTILS_TIMEOUT_H_
#define _ZEPHYR_POLLING_UTILS_TIMEOUT_H_

#include "easybt_config.h"

#include "base/types.h"

#include "utils/dlist.h"


/**
 * @addtogroup clock_apis
 * @{
 */

typedef uint32_t k_ticks_t;

/* number of nsec per usec */
#define NSEC_PER_USEC 1000U

/* number of microseconds per millisecond */
#define USEC_PER_MSEC 1000U

/* number of milliseconds per second */
#define MSEC_PER_SEC 1000U

/**
 * @brief Generate timeout delay from system ticks.
 *
 * This macro generates a timeout delay that instructs a kernel API
 * to wait up to @a t ticks to perform the requested operation.
 *
 * @param t Duration in system ticks.
 *
 * @return Timeout delay value.
 */
#define K_TICKS(t) (t)

/**
 * @brief Generate timeout delay from milliseconds.
 *
 * This macro generates a timeout delay that instructs a kernel API
 * to wait up to @a ms milliseconds to perform the requested operation.
 *
 * @param ms Duration in milliseconds.
 *
 * @return Timeout delay value.
 */
#define K_MSEC(ms) (ms)

/**
 * @brief Generate timeout delay from seconds.
 *
 * This macro generates a timeout delay that instructs a kernel API
 * to wait up to @a s seconds to perform the requested operation.
 *
 * @param s Duration in seconds.
 *
 * @return Timeout delay value.
 */
#define K_SECONDS(s) K_MSEC((s)*MSEC_PER_SEC)

/**
 * @brief Generate timeout delay from minutes.

 * This macro generates a timeout delay that instructs a kernel API
 * to wait up to @a m minutes to perform the requested operation.
 *
 * @param m Duration in minutes.
 *
 * @return Timeout delay value.
 */
#define K_MINUTES(m) K_SECONDS((m)*60)

/**
 * @brief Generate timeout delay from hours.
 *
 * This macro generates a timeout delay that instructs a kernel API
 * to wait up to @a h hours to perform the requested operation.
 *
 * @param h Duration in hours.
 *
 * @return Timeout delay value.
 */
#define K_HOURS(h) K_MINUTES((h)*60)

struct _timeout;
typedef void (*_timeout_func_t)(struct _timeout *t);

struct _timeout
{
    sys_dnode_t node;
    _timeout_func_t fn;
#ifdef CONFIG_TIMEOUT_64BIT
    /* Can't use k_ticks_t for header dependency reasons */
    int64_t dticks;
#else
    int32_t dticks;
#endif
};

static inline void z_init_timeout(struct _timeout *to)
{
    sys_dnode_init(&to->node);
}

void z_add_timeout(struct _timeout *to, _timeout_func_t fn, k_ticks_t timeout);

int z_abort_timeout(struct _timeout *to);

static inline bool z_is_inactive_timeout(const struct _timeout *to)
{
    return !sys_dnode_is_linked(&to->node);
}

// static inline void z_init_thread_timeout(struct _thread_base *thread_base)
// {
// 	z_init_timeout(&thread_base->timeout);
// }

// extern void z_thread_timeout(struct _timeout *timeout);

// static inline void z_add_thread_timeout(struct k_thread *thread, k_timeout_t ticks)
// {
// 	z_add_timeout(&thread->base.timeout, z_thread_timeout, ticks);
// }

// static inline int z_abort_thread_timeout(struct k_thread *thread)
// {
// 	return z_abort_timeout(&thread->base.timeout);
// }

int32_t z_get_next_timeout_expiry(void);

void z_set_timeout_expiry(int32_t ticks, bool is_idle);

k_ticks_t z_timeout_remaining(const struct _timeout *timeout);
k_ticks_t z_timeout_expires(const struct _timeout *timeout);

k_ticks_t z_get_recent_timeout_expiry(void);

/**
 * @brief Announce time progress to the kernel
 *
 * Informs the kernel that the specified number of ticks have elapsed
 * since the last call to sys_clock_announce() (or system startup for
 * the first call).  The timer driver is expected to delivery these
 * announcements as close as practical (subject to hardware and
 * latency limitations) to tick boundaries.
 *
 * @param ticks Elapsed time, in ticks
 */
void sys_clock_announce(uint32_t ticks);

uint32_t sys_clock_tick_get(void);

void timeout_polling_work(void);

#endif /* _ZEPHYR_POLLING_UTILS_TIMEOUT_H_ */