#include <stddef.h>
#include <stdio.h>

#include "base/types.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>

#include "utils/timer.h"

#include <drivers/hci_driver.h>
#include <logging/bt_log.h>

#include "services/bas.h"
#include "services/dis.h"
#include "services/hrs.h"

/* Idle timer */
struct k_timer idle_work;

static const struct bt_data ad[] = {
        BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
        BT_DATA_BYTES(BT_DATA_UUID16_ALL, BT_UUID_16_ENCODE(BT_UUID_HRS_VAL),
                      BT_UUID_16_ENCODE(BT_UUID_BAS_VAL), BT_UUID_16_ENCODE(BT_UUID_DIS_VAL))};


int le_start_adv(void)
{
    int err;
    struct bt_hci_cp_le_set_adv_param adv_param;
    adv_param.min_interval = BT_GAP_ADV_FAST_INT_MIN_2;
    adv_param.max_interval = BT_GAP_ADV_FAST_INT_MAX_2;
    adv_param.type = BT_HCI_ADV_IND;
    adv_param.own_addr_type = BT_ADDR_LE_PUBLIC;
    bt_addr_le_copy(&adv_param.direct_addr, BT_ADDR_LE_ANY);
    adv_param.channel_map = 0x07;
    adv_param.filter_policy = BT_LE_ADV_FP_NO_FILTER;
    err = hci_send_cmd_le_set_adv_param(&adv_param);
    if(err) {
        return err;
    }


    struct bt_hci_cp_le_set_adv_data adv_data;
    adv_data.len = 31;
    memset(adv_data.data, 0, adv_data.len);
    err = bt_adv_data_copy(adv_data.data, &adv_data.len, ad, ARRAY_SIZE(ad));
    if(err) {
        return err;
    }
    err = hci_send_cmd_le_set_adv_data(&adv_data);
    if(err) {
        return err;
    }
    
    // struct bt_hci_cp_le_set_scan_rsp_data scan_rsp_data;
    // scan_rsp_data.len = 31;
    // err = bt_adv_data_copy(scan_rsp_data.data, &scan_rsp_data.len, sd, ARRAY_SIZE(sd));
    // if(err) {
    //     return err;
    // }
    // err = hci_send_cmd_le_set_scan_rsp_data(&scan_rsp_data);
    // if(err) {
    //     return err;
    // }
    
    struct bt_hci_cp_le_set_adv_enable adv_enable;
    adv_enable.enable = true;
    err = hci_send_cmd_le_set_adv_enable(&adv_enable);
    if(err) {
        return err;
    }

    return 0;
}
static void connected(struct bt_conn *conn, uint8_t err)
{
    if (err)
    {
        printk("Connection failed (err 0x%02x)\n", err);
    }
    else
    {
        printk("Connected\n");
    }
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
    printk("Disconnected (reason 0x%02x)\n", reason);
}

static struct bt_conn_cb conn_callbacks = {
        .connected = connected,
        .disconnected = disconnected,
};

struct bt_gatt_service_static* sevice_list[] = {
    &dis_svc,
    &bas_svc,
    &hrs_svc,
};

static void auth_cancel(struct bt_conn *conn)
{
    char addr[BT_ADDR_LE_STR_LEN];

    // bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    printk("Pairing cancelled: %s\n", addr);
}

static struct bt_conn_auth_cb auth_cb_display = {
        .cancel = auth_cancel,
};

static void bas_notify(void)
{
    uint8_t battery_level = bt_bas_get_battery_level();

    battery_level--;

    if (!battery_level)
    {
        battery_level = 100U;
    }

    bt_bas_set_battery_level(battery_level);
}

static void hrs_notify(void)
{
    static uint8_t heartrate = 90U;

    /* Heartrate measurements simulation */
    heartrate++;
    if (heartrate == 160U)
    {
        heartrate = 90U;
    }

    bt_hrs_notify(heartrate);
}

static void idle_timeout(struct k_timer *work)
{
    /* Heartrate measurements simulation */
    hrs_notify();

    /* Battery level simulation */
    bas_notify();
}

void bt_ready(int err)
{
    if (err)
    {
        printk("Bluetooth init failed (err %d)\n", err);
        return;
    }

    printk("Bluetooth initialized\n");
    
    bt_gatt_service_init(3, sevice_list);

    bt_conn_cb_register(&conn_callbacks);
    //bt_conn_auth_cb_register(&auth_cb_display);

#if defined(CONFIG_BT_FIXED_PASSKEY)
    bt_passkey_set(1234);
#endif

    k_timer_init(&idle_work, idle_timeout, NULL);
    k_timer_start(&idle_work, K_SECONDS(1), K_SECONDS(1));

    err = le_start_adv();
    if (err)
    {
        printk("Advertising failed to start (err %d)\n", err);
        return;
    }

    printk("Advertising successfully started\n");
}

void app_polling_work(void)
{
}
