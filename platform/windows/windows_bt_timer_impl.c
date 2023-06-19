#include "base\byteorder.h"
#include "utils\timer.h"

#include <stdio.h>

#include <pthread.h>
#include <windows.h>

#include <logging\bt_log.h>

// start time.
static ULARGE_INTEGER last_time;

uint32_t timer_get_delay_time_ms(void)
{
    FILETIME file_time;
    SYSTEMTIME system_time;
    ULARGE_INTEGER now_time;
    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    now_time.LowPart = file_time.dwLowDateTime;
    now_time.HighPart = file_time.dwHighDateTime;
    uint32_t time_ms = (uint32_t)((now_time.QuadPart - last_time.QuadPart) / 10000);

    if(time_ms)
    {
        last_time.LowPart = now_time.LowPart;
        last_time.HighPart = now_time.HighPart;
    }

    // printf("timer_get_delay_time_ms: %u\n", time_ms);
    return time_ms;
}

void bt_timer_impl_local_init(void)
{
    FILETIME file_time;
    SYSTEMTIME system_time;
    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);
    last_time.LowPart = file_time.dwLowDateTime;
    last_time.HighPart = file_time.dwHighDateTime;

    sys_clock_announce(0);
}

uint32_t sys_clock_elapsed(void)
{
    return timer_get_delay_time_ms();
}
