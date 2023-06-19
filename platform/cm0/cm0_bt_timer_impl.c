#include "base/byteorder.h"
#include "utils/timer.h"
#include "host/hci_core.h"

#include "logging/bt_log.h"

#include <stdio.h>

uint32_t sys_clock_elapsed(void)
{
    return 0;
}

void bt_timer_impl_local_init(void)
{
    sys_clock_announce(0);
}
