#include "cm0_bt_log_impl.h"

#include "base/byteorder.h"
#include "logging/bt_log.h"


static void log_printf_dump(uint8_t level, const char *format, va_list argptr)
{
}

static void log_packet_dump(uint8_t packet_type, uint8_t in, uint8_t *packet, uint16_t len)
{
}

static void log_point_dump(uint32_t point)
{
}

static void log_init(void)
{

}

static const bt_log_impl_t log_impl = {
        log_init,
        log_packet_dump,
        log_printf_dump,
        log_point_dump,
};

const bt_log_impl_t *bt_log_impl_local_instance(void)
{
    return &log_impl;
}
