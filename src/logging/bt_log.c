#include "bt_log.h"

#include <stdarg.h>
#include "base/util.h"

static const bt_log_impl_t *bt_log_implementation;

void bt_log_impl_printf(uint8_t level, const char *format, ...)
{
    va_list argptr;
    va_start(argptr, format);
    (*bt_log_implementation->printf)(level, format, argptr);
    va_end(argptr);
}

void bt_log_impl_packet(uint8_t packet_type, uint8_t in, uint8_t *packet, uint16_t len)
{
    (*bt_log_implementation->packet)(packet_type, in, packet, len);
}

void bt_log_impl_init(void)
{
    (*bt_log_implementation->init)();
}

void bt_log_impl_register(const bt_log_impl_t *log_impl)
{
    bt_log_implementation = log_impl;
    bt_log_impl_init();
}


void log_hex_dump(char *str, size_t out_len, const void *buf, size_t len)
{
    static const char hex[] = "0123456789ABCDEF";
    const uint8_t *b = buf;
    size_t i;

    len = MIN(len, (out_len - 1) / 3);

    for (i = 0; i < len; i++)
    {
        str[i * 3] = hex[b[i] >> 4];
        str[i * 3 + 1] = hex[b[i] & 0xf];
        if (i != len - 1)
        {
            str[i * 3 + 2] = ' ';
        }
    }

    str[i * 3 - 1] = '\0';
}
