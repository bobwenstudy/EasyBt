/*
 * Copyright (c) 2017-2021 Nordic Semiconductor ASA
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <errno.h>

#include "base/common.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include <utils/bt_buf.h>

#include "host/hci_core.h"

#define LOG_MODULE_NAME bt_adv
#include "logging/bt_log.h"

#if defined(CONFIG_BT_BROADCASTER)

int bt_adv_data_copy(uint8_t *data, uint8_t *data_len,
                                 const struct bt_data *ad, size_t ad_len)
{
    uint8_t set_data_len = 0;

    for (size_t i = 0; i < ad_len; i++)
    {
        const struct bt_data *ad_data = &ad[i];

        size_t len = ad_data->data_len;
        uint8_t type = ad_data->type;

        /* Check if ad fit in the remaining buffer */
        if ((set_data_len + len + 2) > *data_len)
        {
            LOG_ERR("Too big advertising data");
            return -EINVAL;
        }
        data[set_data_len++] = len + 1;
        data[set_data_len++] = type;

        memcpy(&data[set_data_len], ad_data->data, len);
        set_data_len += len;
    }

    *data_len = set_data_len;
    return 0;
}

int hci_send_cmd_le_set_adv_param(struct bt_hci_cp_le_set_adv_param *cp_le)
{
    struct net_buf *buf;

    buf = bt_hci_cmd_create(BT_HCI_OP_LE_SET_ADV_PARAM, sizeof(*cp_le));
    if (!buf)
    {
        return -ENOBUFS;
    }

    net_buf_add_mem(buf, cp_le, sizeof(*cp_le));

    return bt_hci_cmd_send_sync(BT_HCI_OP_LE_SET_ADV_PARAM, buf, NULL);
}

int hci_send_cmd_le_set_adv_data(struct bt_hci_cp_le_set_adv_data *cp_le)
{
    struct net_buf *buf;

    buf = bt_hci_cmd_create(BT_HCI_OP_LE_SET_ADV_DATA, sizeof(*cp_le));
    if (!buf)
    {
        return -ENOBUFS;
    }

    net_buf_add_mem(buf, cp_le, sizeof(*cp_le));

    return bt_hci_cmd_send_sync(BT_HCI_OP_LE_SET_ADV_DATA, buf, NULL);
}

int hci_send_cmd_le_set_scan_rsp_data(struct bt_hci_cp_le_set_scan_rsp_data *cp_le)
{
    struct net_buf *buf;

    buf = bt_hci_cmd_create(BT_HCI_OP_LE_SET_SCAN_RSP_DATA, sizeof(*cp_le));
    if (!buf)
    {
        return -ENOBUFS;
    }

    net_buf_add_mem(buf, cp_le, sizeof(*cp_le));

    return bt_hci_cmd_send_sync(BT_HCI_OP_LE_SET_SCAN_RSP_DATA, buf, NULL);
}


int hci_send_cmd_le_set_adv_enable(struct bt_hci_cp_le_set_adv_enable *cp_le)
{
    struct net_buf *buf;

    buf = bt_hci_cmd_create(BT_HCI_OP_LE_SET_ADV_ENABLE, sizeof(*cp_le));
    if (!buf)
    {
        return -ENOBUFS;
    }

    net_buf_add_mem(buf, cp_le, sizeof(*cp_le));

    return bt_hci_cmd_send_sync(BT_HCI_OP_LE_SET_ADV_ENABLE, buf, NULL);
}





#endif /* defined(CONFIG_BT_BROADCASTER) */