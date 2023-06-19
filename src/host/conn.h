
#ifndef _CONN_INTERNAL_H_
#define _CONN_INTERNAL_H_

#include "base\util.h"
#include "base\types.h"

#include "utils\net_buf.h"
#include "utils\slist.h"

#include "bluetooth\addr.h"

typedef enum __packed
{
    BT_CONN_DISCONNECTED,
    BT_CONN_DISCONNECT_COMPLETE,
    BT_CONN_CONNECTING_SCAN,
    BT_CONN_CONNECTING_AUTO,
    BT_CONN_CONNECTING_ADV,
    BT_CONN_CONNECTING_DIR_ADV,
    BT_CONN_CONNECTING,
    BT_CONN_CONNECTED,
    BT_CONN_DISCONNECTING,
} bt_conn_state_t;

struct bt_conn_le
{
    bt_addr_le_t peer;
    bt_addr_le_t dst;

    bt_addr_le_t init_addr;
    bt_addr_le_t resp_addr;

    uint16_t interval;
    uint16_t interval_min;
    uint16_t interval_max;

    uint16_t latency;
    uint16_t timeout;
    uint16_t pending_latency;
    uint16_t pending_timeout;

    uint8_t features[8];

#if defined(CONFIG_BT_USER_PHY_UPDATE)
    struct bt_conn_le_phy_info phy;
#endif

#if defined(CONFIG_BT_USER_DATA_LEN_UPDATE)
    struct bt_conn_le_data_len_info data_len;
#endif
};

struct bt_conn
{
    uint16_t handle;
    uint8_t type;
    uint8_t role;

    uint8_t mtu;
    /* Which local identity address this connection uses */
    uint8_t id;

    /* Connection error or reason for disconnect */
    uint8_t err;

    bt_conn_state_t state;
    uint16_t rx_len;
    struct net_buf *rx;

    /* Sent but not acknowledged TX packets with a callback */
    sys_slist_t tx_pending;
    /* Sent but not acknowledged TX packets without a callback before
     * the next packet (if any) in tx_pending.
     */
    uint32_t pending_no_cb;

    /* Completed TX for which we need to call the callback */
    sys_slist_t tx_complete;

    /* Queue for outgoing ACL data */
    sys_slist_t tx_queue;

    /* Active L2CAP channels */
    sys_slist_t channels;

    union
    {
        struct bt_conn_le le;
#if defined(CONFIG_BT_BREDR)
        struct bt_conn_br br;
        struct bt_conn_sco sco;
#endif
#if defined(CONFIG_BT_ISO)
        struct bt_conn_iso iso;
#endif
    };
};
#endif //_CONN_INTERNAL_H_
