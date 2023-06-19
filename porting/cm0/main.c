#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include "cm0_driver_serial.h"

#include "chipset_interface.h"
#include "platform_interface.h"

#include "base/types.h"
#include <logging/bt_log.h>
#include <drivers/hci_driver.h>

#include <host/hci_core.h>

#include <bluetooth/bluetooth.h>

extern void bt_ready(int err);
extern void app_polling_work(void);

ebt_base_t ebt_hw_interrupt_disable(void)
{
    return 0;
}
void ebt_hw_interrupt_enable(ebt_base_t level)
{

}

int bt_init_hci_driver(void)
{
    bt_uart_interface_t *p_interface = NULL;
    uint8_t com_num;

    p_interface = (bt_uart_interface_t *)bt_chipset_get_uart_interface();
    bt_uart_interface_t tmp = {0, 0, 0, 0, 0};
    tmp.rate = 115200;
    tmp.databits = p_interface->databits;
    tmp.stopbits = p_interface->stopbits;
    tmp.parity = p_interface->parity;
    tmp.flowcontrol = 1;
    
    com_num = 0;

    if (bt_hci_init_serial_device(com_num, tmp.rate, tmp.databits, tmp.stopbits,
                           tmp.parity, tmp.flowcontrol) < 0)
    {
        printk("Error, uart open failed.");
        return -1;
    }

    return 0;
}

void main(void)
{
    int err = 0;

    bt_log_impl_register(bt_log_impl_local_instance());

    bt_init_hci_driver();
    bt_hci_chipset_driver_register(bt_hci_chipset_impl_local_instance());
    bt_storage_kv_register(bt_storage_kv_impl_local_instance());
    bt_timer_impl_local_init();

    /* Initialize the Bluetooth Subsystem */
    err = bt_enable(bt_ready);

    while (1)
    {
        bt_polling_work();

        app_polling_work();
    }

    return (err);
}