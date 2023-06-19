#include <stdio.h>

#include "cm0_driver_serial.h"
#include "drivers/hci_driver.h"
#include "drivers/hci_h4.h"

#include "logging/bt_log.h"

#include "utils/bt_buf.h"

static int hci_driver_h4_open(void)
{
    return 0;
}

static int hci_driver_h4_send(uint8_t *buf, uint16_t len)
{
    return 0;
}

static int hci_driver_h4_recv(uint8_t *buf, uint16_t len)
{
    return 0;
}

static const struct bt_hci_h4_driver h4_drv = {
        .open = hci_driver_h4_open,
        .send = hci_driver_h4_send,
        .recv = hci_driver_h4_recv,
};

static void hci_driver_h4_init(void)
{
    // hci_h4_init(&h4_drv);
}




int bt_hci_init_serial_device(int idx, int rate, int databits, int stopbits, int parity, bool flowcontrol)
{
    hci_driver_h4_init();

    return (0);
}
