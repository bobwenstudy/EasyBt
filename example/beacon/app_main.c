#include <stddef.h>
#include <stdio.h>

#include "base/types.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>

#include <drivers/hci_driver.h>
#include <logging/bt_log.h>

#include "services/bas.h"
#include "services/dis.h"
#include "services/hrs.h"

#define DEVICE_NAME     CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

/*
 * Set Advertisement data. Based on the Eddystone specification:
 * https://github.com/google/eddystone/blob/master/protocol-specification.md
 * https://github.com/google/eddystone/tree/master/eddystone-url
 */
static const struct bt_data ad[] = {
        BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_NO_BREDR),
        BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0xaa, 0xfe),
        BT_DATA_BYTES(BT_DATA_SVC_DATA16, 0xaa, 0xfe, /* Eddystone UUID */
                      0x10,                           /* Eddystone-URL frame type */
                      0x00,                           /* Calibrated Tx power at 0m */
                      0x00,                           /* URL Scheme Prefix http://www. */
                      'z', 'e', 'p', 'h', 'y', 'r', 'p', 'r', 'o', 'j', 'e', 'c', 't',
                      0x08) /* .org */
};

/* Set Scan Response data */
static const struct bt_data sd[] = {
        BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

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
    err = bt_adv_data_copy(adv_data.data, &adv_data.len, ad, ARRAY_SIZE(ad));
    if(err) {
        return err;
    }
    err = hci_send_cmd_le_set_adv_data(&adv_data);
    if(err) {
        return err;
    }
    
    struct bt_hci_cp_le_set_scan_rsp_data scan_rsp_data;
    scan_rsp_data.len = 31;
    err = bt_adv_data_copy(scan_rsp_data.data, &scan_rsp_data.len, sd, ARRAY_SIZE(sd));
    if(err) {
        return err;
    }
    err = hci_send_cmd_le_set_scan_rsp_data(&scan_rsp_data);
    if(err) {
        return err;
    }
    
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

    err = le_start_adv();
    if (err)
    {
        printk("Advertising failed to start (err %d)\n", err);
        return;
    }
    
    printk("Beacon started\n");
}

void app_polling_work(void)
{
    
}