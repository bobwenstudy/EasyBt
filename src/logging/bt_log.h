#ifndef _ZEPHYR_POLLING_LOGGING_LOG_IMPL_H_
#define _ZEPHYR_POLLING_LOGGING_LOG_IMPL_H_

#include <stddef.h>
#include <stdarg.h>

#include "easybt_config.h"

#include "base/types.h"

#define FUNCTION_CONTROL_DEBUG_ENABLE

#define LOG_IMPL_LEVEL_NONE 0U
#define LOG_IMPL_LEVEL_ERR  1U
#define LOG_IMPL_LEVEL_WRN  2U
#define LOG_IMPL_LEVEL_INF  3U
#define LOG_IMPL_LEVEL_DBG  4U

// #ifdef CONFIG_BT_DEBUG
// #define LOG_LEVEL CONFIG_BT_LOG_LEVEL
// #else
// #define LOG_LEVEL LOG_IMPL_LEVEL_NONE
// #endif

#define LOG_LEVEL LOG_IMPL_LEVEL_DBG
















static inline char z_log_minimal_level_to_char(int level)
{
    switch (level)
    {
    case LOG_IMPL_LEVEL_ERR:
        return 'E';
    case LOG_IMPL_LEVEL_WRN:
        return 'W';
    case LOG_IMPL_LEVEL_INF:
        return 'I';
    case LOG_IMPL_LEVEL_DBG:
        return 'D';
    default:
        return '?';
    }
}

extern void bt_log_impl_printf(uint8_t _level, const char *format, ...);
extern void bt_log_impl_packet(uint8_t packet_type, uint8_t in, uint8_t *packet, uint16_t len);
extern void bt_log_impl_init(void);

#define LOG_IMPL_TO_PRINTK(_fun, _line, _level, _name, fmt, ...)                                   \
    do                                                                                             \
    {                                                                                              \
        bt_log_impl_printf(_level,                                                                 \
                           "%c: "                                                                  \
                           "(%s)"                                                                  \
                           "%s():%d: " fmt "\n",                                                   \
                           z_log_minimal_level_to_char(_level), #_name, _fun, _line,               \
                           ##__VA_ARGS__);                                                         \
    } while (false);

#ifdef FUNCTION_CONTROL_DEBUG_ENABLE
#define __LOG_IMPL(_level, _name, _level_thod, ...)                                                \
    if (_level <= _level_thod)                                                                     \
    {                                                                                              \
        LOG_IMPL_TO_PRINTK(__func__, __LINE__, _level, _name, __VA_ARGS__);                        \
    }

#define __LOG_IMPL_RAW(_level, _fmt, ...)                                                          \
    do                                                                                             \
    {                                                                                              \
        bt_log_impl_printf(_level, _fmt, ##__VA_ARGS__);                                           \
    } while (false);

#define __PACKET_IMPL(_packet_type, _in, _packet, _len)                                            \
    do                                                                                             \
    {                                                                                              \
        bt_log_impl_packet(_packet_type, _in, _packet, _len);                                      \
    } while (false)
#define __LOG_INIT_IMPL()                                                                          \
    do                                                                                             \
    {                                                                                              \
        bt_log_impl_init(_packet_type, _in, _packet, _len);                                        \
    } while (false)
#else
#define __LOG_IMPL(_level, _name, _level_thod, ...)
#define __LOG_IMPL_RAW(_level, _fmt, ...)
#define __PACKET_IMPL(_packet_type, _in, _packet, _len)
#define __LOG_INIT_IMPL()
#endif

static inline char *log_strdup(const char *str)
{
    return (char *)str;
}

/**
 * @brief Logger API
 * @defgroup log_api Logging API
 * @ingroup logger
 * @{
 */

/**
 * @brief Writes an ERROR level message to the log.
 *
 * @details It's meant to report severe errors, such as those from which it's
 * not possible to recover.
 *
 * @param ... A string optionally containing printk valid conversion specifier,
 * followed by as many values as specifiers.
 */
#define LOG_IMPL_ERR(...) __LOG_IMPL(LOG_IMPL_LEVEL_ERR, __VA_ARGS__)

/**
 * @brief Writes a WARNING level message to the log.
 *
 * @details It's meant to register messages related to unusual situations that
 * are not necessarily errors.
 *
 * @param ... A string optionally containing printk valid conversion specifier,
 * followed by as many values as specifiers.
 */
#define LOG_IMPL_WRN(...) __LOG_IMPL(LOG_IMPL_LEVEL_WRN, __VA_ARGS__)

/**
 * @brief Writes an INFO level message to the log.
 *
 * @details It's meant to write generic user oriented messages.
 *
 * @param ... A string optionally containing printk valid conversion specifier,
 * followed by as many values as specifiers.
 */
#define LOG_IMPL_INF(...) __LOG_IMPL(LOG_IMPL_LEVEL_INF, __VA_ARGS__)

/**
 * @brief Writes a DEBUG level message to the log.
 *
 * @details It's meant to write developer oriented information.
 *
 * @param ... A string optionally containing printk valid conversion specifier,
 * followed by as many values as specifiers.
 */
#define LOG_IMPL_DBG(...) __LOG_IMPL(LOG_IMPL_LEVEL_DBG, __VA_ARGS__)

#define LOG_INIT() __LOG_INIT_IMPL()

#define LOG_PACKET_DUMP(_packet_type, _in, _packet, _len)                                          \
    __PACKET_IMPL(_packet_type, _in, _packet, _len)

#define printk(fmt, ...) __LOG_IMPL_RAW(LOG_IMPL_LEVEL_INF, fmt, ##__VA_ARGS__)








#define LOG_DBG(fmt, ...)  LOG_IMPL_DBG(LOG_MODULE_NAME, LOG_LEVEL, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  LOG_IMPL_ERR(LOG_MODULE_NAME, LOG_LEVEL, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) LOG_IMPL_WRN(LOG_MODULE_NAME, LOG_LEVEL, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) LOG_IMPL_INF(LOG_MODULE_NAME, LOG_LEVEL, fmt, ##__VA_ARGS__)

#define BT_PACKET_DUMP(_packet_type, _in, _packet, _len)                                           \
    LOG_PACKET_DUMP(_packet_type, _in, _packet, _len)

#if defined(CONFIG_BT_ASSERT_VERBOSE)
#define BT_ASSERT_PRINT(test)         __ASSERT_LOC(test)
#define BT_ASSERT_PRINT_MSG(fmt, ...) __ASSERT_MSG_INFO(fmt, ##__VA_ARGS__)
#else
#define BT_ASSERT_PRINT(test)
#define BT_ASSERT_PRINT_MSG(fmt, ...)
#endif /* CONFIG_BT_ASSERT_VERBOSE */

#if defined(CONFIG_BT_ASSERT_PANIC)
#define BT_ASSERT_DIE() while (1)
#else
#define BT_ASSERT_DIE() while (1)
#endif /* CONFIG_BT_ASSERT_PANIC */

#if defined(CONFIG_BT_ASSERT)
#define BT_ASSERT(cond)                                                                            \
    do                                                                                             \
    {                                                                                              \
        if (!(cond))                                                                               \
        {                                                                                          \
            BT_ASSERT_PRINT(cond);                                                                 \
            BT_ASSERT_DIE();                                                                       \
        }                                                                                          \
    } while (0)

#define BT_ASSERT_MSG(cond, fmt, ...)                                                              \
    do                                                                                             \
    {                                                                                              \
        if (!(cond))                                                                               \
        {                                                                                          \
            BT_ASSERT_PRINT(cond);                                                                 \
            BT_ASSERT_PRINT_MSG(fmt, ##__VA_ARGS__);                                               \
            BT_ASSERT_DIE();                                                                       \
        }                                                                                          \
    } while (0)
#else
#define BT_ASSERT(cond)               __ASSERT_NO_MSG(cond)
#define BT_ASSERT_MSG(cond, msg, ...) __ASSERT(cond, msg, ##__VA_ARGS__)
#endif /* CONFIG_BT_ASSERT*/

#define Z_LOG_HEXDUMP(_level, _data, _length, _str) \
    LOG_IMPL_DBG(LOG_MODULE_NAME, LOG_LEVEL, _str "%s", bt_hex_real(_data, _length))

/**
 * @brief Writes an ERROR level hexdump message to the log.
 *
 * @details It's meant to report severe errors, such as those from which it's
 * not possible to recover.
 *
 * @param _data   Pointer to the data to be logged.
 * @param _length Length of data (in bytes).
 * @param _str    Persistent, raw string.
 */
#define LOG_HEXDUMP_ERR(_data, _length, _str) \
    LOG_IMPL_ERR(LOG_MODULE_NAME, LOG_LEVEL, _str "%s", bt_hex_real(_data, _length))
	// Z_LOG_HEXDUMP(LOG_LEVEL_ERR, _data, _length, _str)

/**
 * @brief Writes a WARNING level message to the log.
 *
 * @details It's meant to register messages related to unusual situations that
 * are not necessarily errors.
 *
 * @param _data   Pointer to the data to be logged.
 * @param _length Length of data (in bytes).
 * @param _str    Persistent, raw string.
 */
#define LOG_HEXDUMP_WRN(_data, _length, _str) \
    LOG_IMPL_WRN(LOG_MODULE_NAME, LOG_LEVEL, _str "%s", bt_hex_real(_data, _length))
	// Z_LOG_HEXDUMP(LOG_LEVEL_WRN, _data, _length, _str)

/**
 * @brief Writes an INFO level message to the log.
 *
 * @details It's meant to write generic user oriented messages.
 *
 * @param _data   Pointer to the data to be logged.
 * @param _length Length of data (in bytes).
 * @param _str    Persistent, raw string.
 */
#define LOG_HEXDUMP_INF(_data, _length, _str) \
    LOG_IMPL_INF(LOG_MODULE_NAME, LOG_LEVEL, _str "%s", bt_hex_real(_data, _length))
	// Z_LOG_HEXDUMP(LOG_LEVEL_INF, _data, _length, _str)

/**
 * @brief Writes a DEBUG level message to the log.
 *
 * @details It's meant to write developer oriented information.
 *
 * @param _data   Pointer to the data to be logged.
 * @param _length Length of data (in bytes).
 * @param _str    Persistent, raw string.
 */
#define LOG_HEXDUMP_DBG(_data, _length, _str) \
    LOG_IMPL_DBG(LOG_MODULE_NAME, LOG_LEVEL, _str "%s", bt_hex_real(_data, _length))
	// Z_LOG_HEXDUMP(LOG_LEVEL_DBG, _data, _length, _str)



#define BT_HEXDUMP_DBG(_data, _length, _str) LOG_HEXDUMP_DBG((const uint8_t *)_data, _length, _str)

















typedef struct
{
    // init work
    void (*init)(void);
    // log packet
    void (*packet)(uint8_t packet_type, uint8_t in, uint8_t *packet, uint16_t len);
    // log message
    void (*printf)(uint8_t level, const char *format, va_list argptr);
    // log point
    void (*point)(uint32_t val);
} bt_log_impl_t;

/**
 * @brief Init Logger
 * @param log_impl - platform-specific implementation
 */
void bt_log_impl_register(const bt_log_impl_t *log_impl);

void log_hex_dump(char *str, size_t out_len, const void *buf, size_t len);

#endif /* _ZEPHYR_POLLING_LOGGING_LOG_IMPL_H_ */