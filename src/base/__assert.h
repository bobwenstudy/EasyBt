/*
 * Copyright (c) 2011-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ZEPHYR_POLLING_BASE___ASSERT_H_
#define _ZEPHYR_POLLING_BASE___ASSERT_H_

#include "bt_config.h"

#include "base/types.h"

#include "logging/bt_log.h"

#define CONFIG_ASSERT
#define CONFIG_ASSERT_VERBOSE
//#define CONFIG_ASSERT_NO_MSG_INFO

#ifdef CONFIG_ASSERT
#ifndef __ASSERT_ON
#define __ASSERT_ON 1
#endif
#endif

#if defined(CONFIG_ASSERT_VERBOSE)
#define __ASSERT_PRINT(fmt, ...) LOG_ERR(fmt, ##__VA_ARGS__)
#else /* CONFIG_ASSERT_VERBOSE */
#define __ASSERT_PRINT(fmt, ...)
#endif /* CONFIG_ASSERT_VERBOSE */

#ifdef CONFIG_ASSERT_NO_MSG_INFO
#define __ASSERT_MSG_INFO(fmt, ...)
#else /* CONFIG_ASSERT_NO_MSG_INFO */
#define __ASSERT_MSG_INFO(fmt, ...) __ASSERT_PRINT("\t" fmt "\n", ##__VA_ARGS__)
#endif /* CONFIG_ASSERT_NO_MSG_INFO */

#if !defined(CONFIG_ASSERT_NO_COND_INFO) && !defined(CONFIG_ASSERT_NO_FILE_INFO)
#define __ASSERT_LOC(test)                                                                         \
    __ASSERT_PRINT("ASSERTION FAIL [%s] @ %s:%d\n", #test, __FILE__, __LINE__)
#endif

#if defined(CONFIG_ASSERT_NO_COND_INFO) && !defined(CONFIG_ASSERT_NO_FILE_INFO)
#define __ASSERT_LOC(test) __ASSERT_PRINT("ASSERTION FAIL @ %s:%d\n", __FILE__, __LINE__)
#endif

#if !defined(CONFIG_ASSERT_NO_COND_INFO) && defined(CONFIG_ASSERT_NO_FILE_INFO)
#define __ASSERT_LOC(test) __ASSERT_PRINT("ASSERTION FAIL [%s]\n", #test)
#endif

#if defined(CONFIG_ASSERT_NO_COND_INFO) && defined(CONFIG_ASSERT_NO_FILE_INFO)
#define __ASSERT_LOC(test) __ASSERT_PRINT("ASSERTION FAIL\n")
#endif

#ifdef CONFIG_ASSERT_NO_FILE_INFO
void assert_post_action(void)
{
    while (1)
    {
    }
}
#define __ASSERT_POST_ACTION() assert_post_action()
#else /* CONFIG_ASSERT_NO_FILE_INFO */
static inline void assert_post_action(const char *file, unsigned int line)
{
    while (1)
    {
    }
}
#define __ASSERT_POST_ACTION() assert_post_action(__FILE__, __LINE__)
#endif /* CONFIG_ASSERT_NO_FILE_INFO */

#ifdef __ASSERT_ON

#define __ASSERT_NO_MSG(test)                                                                      \
    do                                                                                             \
    {                                                                                              \
        if (!(test))                                                                               \
        {                                                                                          \
            __ASSERT_LOC(test);                                                                    \
            __ASSERT_POST_ACTION();                                                                \
        }                                                                                          \
    } while (false)

#define __ASSERT(test, fmt, ...)                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (!(test))                                                                               \
        {                                                                                          \
            __ASSERT_LOC(test);                                                                    \
            __ASSERT_MSG_INFO(fmt, ##__VA_ARGS__);                                                 \
            __ASSERT_POST_ACTION();                                                                \
        }                                                                                          \
    } while (false)

#define __ASSERT_EVAL(expr1, expr2, test, fmt, ...)                                                \
    do                                                                                             \
    {                                                                                              \
        expr2;                                                                                     \
        __ASSERT(test, fmt, ##__VA_ARGS__);                                                        \
    } while (false)
#else
#define __ASSERT(test, fmt, ...)                                                                   \
    {                                                                                              \
        if (!(test))                                                                               \
        {                                                                                          \
            __ASSERT_POST_ACTION()                                                                 \
        }                                                                                          \
    }
#define __ASSERT_EVAL(expr1, expr2, test, fmt, ...) expr1
#define __ASSERT_NO_MSG(test)                                                                      \
    {                                                                                              \
        if (!(test))                                                                               \
        {                                                                                          \
            __ASSERT_POST_ACTION()                                                                 \
        }                                                                                          \
    }
#endif

#endif /* _ZEPHYR_POLLING_BASE___ASSERT_H_ */