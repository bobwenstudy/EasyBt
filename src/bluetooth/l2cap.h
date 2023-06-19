/** @file
 *  @brief Bluetooth L2CAP handling
 */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ZEPHYR_POLLING_BLUETOOTH_L2CAP_H_
#define _ZEPHYR_POLLING_BLUETOOTH_L2CAP_H_

/**
 * @brief L2CAP
 * @defgroup bt_l2cap L2CAP
 * @ingroup bluetooth
 * @{
 */
#include "bt_config.h"

#include "base/common.h"
#include <bluetooth/buf.h>
#include <bluetooth/hci.h>

#ifdef __cplusplus
extern "C" {
#endif

/** L2CAP PDU header size, used for buffer size calculations */
#define BT_L2CAP_HDR_SIZE 4

/** Maximum Transmission Unit (MTU) for an outgoing L2CAP PDU. */
#define BT_L2CAP_TX_MTU (CONFIG_BT_L2CAP_TX_MTU)

/** Maximum Transmission Unit (MTU) for an incoming L2CAP PDU. */
#define BT_L2CAP_RX_MTU (CONFIG_BT_BUF_ACL_RX_SIZE - BT_L2CAP_HDR_SIZE)

/** @brief Helper to calculate needed buffer size for L2CAP PDUs.
 *         Useful for creating buffer pools.
 *
 *  @param mtu Needed L2CAP PDU MTU.
 *
 *  @return Needed buffer size to match the requested L2CAP PDU MTU.
 */
#define BT_L2CAP_BUF_SIZE(mtu) BT_BUF_ACL_SIZE(BT_L2CAP_HDR_SIZE + (mtu))

/** L2CAP SDU header size, used for buffer size calculations */
#define BT_L2CAP_SDU_HDR_SIZE 2

/** @brief Maximum Transmission Unit for an unsegmented outgoing L2CAP SDU.
 *
 *  The Maximum Transmission Unit for an outgoing L2CAP SDU when sent without
 *  segmentation, i.e. a single L2CAP SDU will fit inside a single L2CAP PDU.
 *
 *  The MTU for outgoing L2CAP SDUs with segmentation is defined by the
 *  size of the application buffer pool.
 */
#define BT_L2CAP_SDU_TX_MTU (BT_L2CAP_TX_MTU - BT_L2CAP_SDU_HDR_SIZE)

/** @brief Maximum Transmission Unit for an unsegmented incoming L2CAP SDU.
 *
 *  The Maximum Transmission Unit for an incoming L2CAP SDU when sent without
 *  segmentation, i.e. a single L2CAP SDU will fit inside a single L2CAP PDU.
 *
 *  The MTU for incoming L2CAP SDUs with segmentation is defined by the
 *  size of the application buffer pool. The application will have to define
 *  an alloc_buf callback for the channel in order to support receiving
 *  segmented L2CAP SDUs.
 */
#define BT_L2CAP_SDU_RX_MTU (BT_L2CAP_RX_MTU - BT_L2CAP_SDU_HDR_SIZE)

/**
 *
 *  @brief Helper to calculate needed buffer size for L2CAP SDUs.
 *         Useful for creating buffer pools.
 *
 *  @param mtu Required BT_L2CAP_*_SDU.
 *
 *  @return Needed buffer size to match the requested L2CAP SDU MTU.
 */
#define BT_L2CAP_SDU_BUF_SIZE(mtu) BT_L2CAP_BUF_SIZE(BT_L2CAP_SDU_HDR_SIZE + (mtu))

struct bt_l2cap_chan;

/** @typedef bt_l2cap_chan_destroy_t
 *  @brief Channel destroy callback
 *
 *  @param chan Channel object.
 */
typedef void (*bt_l2cap_chan_destroy_t)(struct bt_l2cap_chan *chan);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* _ZEPHYR_POLLING_BLUETOOTH_L2CAP_H_ */