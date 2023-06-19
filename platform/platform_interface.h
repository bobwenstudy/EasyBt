
#ifndef _PLATFORM_INTERFACE_H_
#define _PLATFORM_INTERFACE_H_

#include "utils/bt_storage_kv.h"
#include "logging/bt_log.h"
#include "drivers/hci_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

const bt_log_impl_t *bt_log_impl_local_instance(void);
const struct bt_hci_chipset_driver *bt_hci_chipset_impl_local_instance(void);
const struct bt_storage_kv_impl *bt_storage_kv_impl_local_instance(void);
void bt_timer_impl_local_init(void);

typedef void (*bt_hci_driver_reset_callback_t)(void);


int bt_hci_init_usb_device(uint16_t vid, uint16_t pid);
void bt_hci_reset_usb_device(bt_hci_driver_reset_callback_t callback);

int bt_hci_init_serial_device(int idx, int rate, int databits, int stopbits, int parity, bool flowcontrol);

#ifdef __cplusplus
}
#endif

#endif //_PLATFORM_INTERFACE_H_
