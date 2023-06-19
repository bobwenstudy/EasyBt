/* hci_core.h - Bluetooth HCI core access */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ZEPHYR_POLLING_HOST_HCI_CORE_H_
#define _ZEPHYR_POLLING_HOST_HCI_CORE_H_

#include "easybt_config.h"

#include <drivers/hci_driver.h>

#include "utils/timer.h"
#include "utils/slist.h"

#include <bluetooth/addr.h>

#if defined(CONFIG_BT_BREDR)
#define LMP_FEAT_PAGES_COUNT 3
#else
#define LMP_FEAT_PAGES_COUNT 1
#endif

#if defined(CONFIG_BT_EXT_ADV_LEGACY_SUPPORT)
/* Check the feature bit for extended or legacy advertising commands */
#define BT_DEV_FEAT_LE_EXT_ADV(feat) BT_FEAT_LE_EXT_ADV(feat)
#else
/* Always use extended advertising commands. */
#define BT_DEV_FEAT_LE_EXT_ADV(feat) 1
#endif

struct bt_dev_le
{
    /* LE features */
    uint8_t features[8];
    /* LE states */
    uint64_t states;

#if defined(CONFIG_BT_CONN)
    /* Controller buffer information */
    uint16_t acl_mtu;
#endif /* CONFIG_BT_CONN */
#if defined(CONFIG_BT_SMP)
    /* Size of the the controller resolving list */
    uint8_t rl_size;
    /* Number of entries in the resolving list. rl_entries > rl_size
     * means that host-side resolving is used.
     */
    uint8_t rl_entries;
#endif /* CONFIG_BT_SMP */
};

#if defined(CONFIG_BT_BREDR)
struct bt_dev_br
{
    /* Max controller's acceptable ACL packet length */
    uint16_t mtu;
    struct k_sem pkts;
    uint16_t esco_pkt_type;
};
#endif


typedef enum
{
    HCI_STATE_NONE = 0,
    HCI_STATE_BOOTING,
    HCI_STATE_BOOTING_WAIT,
    HCI_STATE_PREPARING,
    HCI_STATE_PREPARING_WAIT,
    HCI_STATE_INITIALING,
    HCI_STATE_READY,
} HCI_STATE;

/* State tracking for the local Bluetooth controller */
struct bt_dev_set
{
    bt_addr_le_t public_addr;

    /* Current local Random Address */
    bt_addr_le_t random_addr;
    uint8_t adv_conn_id;

    /* Controller version & manufacturer information */
    uint8_t hci_version;
    uint8_t lmp_version;
    uint16_t hci_revision;
    uint16_t lmp_subversion;
    uint16_t manufacturer;

    /* LMP features (pages 0, 1, 2) */
    uint8_t features[LMP_FEAT_PAGES_COUNT][8];

    /* Supported commands */
    uint8_t supported_commands[64];

    /* LE controller specific features */
    struct bt_dev_le le;

#if defined(CONFIG_BT_BREDR)
    /* BR/EDR controller specific features */
    struct bt_dev_br br;
#endif

    /* Number of commands controller can accept */
    uint8_t ncmd_sem;

    /* Queue for incoming HCI events & ACL data */
    sys_slist_t rx_queue;
    
    /* Queue for incoming HCI events. */
    sys_slist_t rx_evt_queue;

#if defined(CONFIG_BT_PRIVACY)
    /* Local Identity Resolving Key */
    uint8_t irk[CONFIG_BT_ID_MAX][16];

    /* Work used for RPA rotation */
    struct k_timer rpa_update;

    /* The RPA timeout value. */
    uint16_t rpa_timeout;
#endif

    /* Local Name */
#if defined(CONFIG_BT_DEVICE_NAME_DYNAMIC)
    char name[CONFIG_BT_DEVICE_NAME_MAX + 1];
#endif
#if defined(CONFIG_BT_DEVICE_APPEARANCE_DYNAMIC)
    /* Appearance Value */
    uint16_t appearance;
#endif

    HCI_STATE hci_state;

    bt_hci_event_process_t hci_event_process;

    /* Registered HCI driver */
    const struct bt_hci_driver *drv;

    /* Registered HCI chipset driver */
    const struct bt_hci_chipset_driver *chipset_drv;
};

extern struct bt_dev_set bt_dev;


#if defined(CONFIG_BT_MONITOR_SLEEP)
void bt_init_monitor_sleep(void);
uint8_t bt_check_is_in_sleep(void);
uint8_t bt_check_allow_sleep(void);
void bt_monitor_sleep(void);
void bt_sleep_prepare_work(void);
void bt_sleep_wakeup_work_start(void);
void bt_sleep_wakeup_work_end(void);
void bt_sleep_wakeup_work(void);
void bt_sleep_wakeup_with_timeout(void);
#endif

void bt_set_rx_acl_lock(uint8_t rx_lock);
uint8_t bt_get_rx_acl_lock(void);
void bt_polling_work(void);
#endif /* _ZEPHYR_POLLING_HOST_HCI_CORE_H_ */