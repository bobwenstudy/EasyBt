#include "base\util.h"
#include "base\types.h"
#include "base\byteorder.h"
#include "errno.h"

#include "utils\bt_buf.h"

#include "host\hci_core.h"
#include "host\l2cap.h"

#include "bluetooth\conn.h"

#include "conn.h"

#define LOG_MODULE_NAME conn
#include "logging/bt_log.h"

static struct bt_conn acl_conns[CONFIG_BT_MAX_CONN];
struct bt_conn_cb *conn_cb;

static inline const char *state2str(bt_conn_state_t state)
{
    switch (state)
    {
    case BT_CONN_DISCONNECTED:
        return "disconnected";
    case BT_CONN_DISCONNECT_COMPLETE:
        return "disconnect-complete";
    case BT_CONN_CONNECTING_SCAN:
        return "connecting-scan";
    case BT_CONN_CONNECTING_DIR_ADV:
        return "connecting-dir-adv";
    case BT_CONN_CONNECTING_ADV:
        return "connecting-adv";
    case BT_CONN_CONNECTING_AUTO:
        return "connecting-auto";
    case BT_CONN_CONNECTING:
        return "connecting";
    case BT_CONN_CONNECTED:
        return "connected";
    case BT_CONN_DISCONNECTING:
        return "disconnecting";
    default:
        return "(unknown)";
    }
}

struct net_buf *bt_conn_create_pdu(struct spool *pool, size_t reserve)
{
    struct net_buf *buf;

    if (!pool)
    {
        buf = bt_buf_get_host_tx_acl();
    }
    else
    {
        buf = net_buf_alloc(pool);
    }

    if (!buf)
    {
        LOG_WRN("Unable to allocate buffer within timeout");
        return NULL;
    }

    reserve += sizeof(struct bt_hci_acl_hdr) + BT_BUF_RESERVE;
    net_buf_reserve(buf, reserve);

    return buf;
}

int bt_conn_send(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_conn_tx *tx;

    LOG_DBG("conn handle %u buf len %u", conn->handle, buf->len);

    if (conn->state != BT_CONN_CONNECTED)
    {
        LOG_ERR("not connected!");
        return -ENOTCONN;
    }

    net_buf_slist_put(&conn->tx_queue, buf);
    return 0;
}

void bt_conn_connected(struct bt_conn *conn)
{
    //bt_l2cap_connected(conn);
    //notify_connected(conn);
    sys_slist_init(&conn->tx_queue);

    conn->mtu = 23;
}

static int send_acl(struct bt_conn *conn, struct net_buf *buf, uint8_t flags)
{
    struct bt_hci_acl_hdr *hdr;

    // switch (flags)
    // {
    // case FRAG_START:
    // case FRAG_SINGLE:
    //     flags = BT_ACL_START_NO_FLUSH;
    //     break;
    // case FRAG_CONT:
    // case FRAG_END:
    //     flags = BT_ACL_CONT;
    //     break;
    // default:
    //     return -EINVAL;
    // }

    hdr = net_buf_push(buf, sizeof(*hdr));
    hdr->handle = sys_cpu_to_le16(bt_acl_handle_pack(conn->handle, flags));
    hdr->len = sys_cpu_to_le16(buf->len - sizeof(*hdr));

    bt_buf_set_type(buf, BT_BUF_ACL_OUT);

    return bt_send(buf);
}

void bt_conn_reset_rx_state(struct bt_conn *conn)
{
    if (!conn->rx)
    {
        return;
    }

    net_buf_unref(conn->rx);
    conn->rx = NULL;
}

static void bt_acl_recv(struct bt_conn *conn, struct net_buf *buf, uint8_t flags)
{
    uint16_t acl_total_len;

    /* Check packet boundary flags */
    switch (flags)
    {
    case BT_ACL_START:
        if (conn->rx)
        {
            LOG_ERR("Unexpected first L2CAP frame");
            bt_conn_reset_rx_state(conn);
        }

        LOG_DBG("First, len %u final %u", buf->len,
                (buf->len < sizeof(uint16_t)) ? 0 : sys_get_le16(buf->data));

        conn->rx = buf;
        break;
    case BT_ACL_CONT:
        if (!conn->rx)
        {
            LOG_ERR("Unexpected L2CAP continuation");
            bt_conn_reset_rx_state(conn);
            net_buf_unref(buf);
            return;
        }

        if (!buf->len)
        {
            LOG_DBG("Empty ACL_CONT");
            net_buf_unref(buf);
            return;
        }

        if (buf->len > net_buf_tailroom(conn->rx))
        {
            LOG_ERR("Not enough buffer space for L2CAP data");

            /* Frame is not complete but we still pass it to L2CAP
             * so that it may handle error on protocol level
             * eg disconnect channel.
             */
            bt_l2cap_recv(conn, conn->rx, false);
            conn->rx = NULL;
            net_buf_unref(buf);
            return;
        }

        net_buf_add_mem(conn->rx, buf->data, buf->len);
        net_buf_unref(buf);
        break;
    default:
        /* BT_ACL_START_NO_FLUSH and BT_ACL_COMPLETE are not allowed on
         * LE-U from Controller to Host.
         * Only BT_ACL_POINT_TO_POINT is supported.
         */
        LOG_ERR("Unexpected ACL flags (0x%02x)", flags);
        bt_conn_reset_rx_state(conn);
        net_buf_unref(buf);
        return;
    }

    if (conn->rx->len < sizeof(uint16_t))
    {
        /* Still not enough data received to retrieve the L2CAP header
         * length field.
         */
        return;
    }

    acl_total_len = sys_get_le16(conn->rx->data) + sizeof(struct bt_l2cap_hdr);

    if (conn->rx->len < acl_total_len)
    {
        /* L2CAP frame not complete. */
        return;
    }

    if (conn->rx->len > acl_total_len)
    {
        LOG_ERR("ACL len mismatch (%u > %u)", conn->rx->len, acl_total_len);
        bt_conn_reset_rx_state(conn);
        return;
    }

    /* L2CAP frame complete. */
    buf = conn->rx;
    conn->rx = NULL;

    LOG_DBG("Successfully parsed %u byte L2CAP packet", buf->len);
    bt_l2cap_recv(conn, buf, true);
}

void bt_conn_recv(struct bt_conn *conn, struct net_buf *buf, uint8_t flags)
{
    /* Make sure we notify any pending TX callbacks before processing
     * new data for this connection.
     */
    // tx_notify(conn);

    LOG_DBG("handle %u len %u flags %02x", conn->handle, buf->len, flags);

#if defined(CONFIG_BT_CONN)
    bt_acl_recv(conn, buf, flags);
#else
    __ASSERT(false, "Invalid connection type %u", conn->type);
#endif
}

struct bt_conn *bt_conn_new(struct bt_conn *conns, size_t size)
{
    struct bt_conn *conn = NULL;
    int i;

    for (i = 0; i < size; i++)
    {
        conn = &conns[i];
        if (conn->state == BT_CONN_DISCONNECTED)
        {
            conn = &conns[i];
            break;
        }
    }

    memset(conn, 0, sizeof(struct bt_conn));

    return conn;
}

struct bt_conn *acl_conn_new(void)
{
    return bt_conn_new(acl_conns, ARRAY_SIZE(acl_conns));
}

struct bt_conn *conn_lookup_handle(struct bt_conn *conns, size_t size, uint16_t handle)
{
    int i;

    for (i = 0; i < size; i++)
    {
        struct bt_conn *conn = &conns[i];

        if (conn->handle != handle)
        {
            continue;
        }

        return conn;
    }

    return NULL;
}

struct bt_conn * bt_conn_lookup_handle(uint16_t handle)
{
    struct bt_conn *conn;

#if defined(CONFIG_BT_CONN)
    conn = conn_lookup_handle(acl_conns, ARRAY_SIZE(acl_conns), handle);
    if (conn)
    {
        return conn;
    }
#endif /* CONFIG_BT_CONN */

    return NULL;
}


static void notify_connected(struct bt_conn *conn)
{
    struct bt_conn_cb *cb = conn_cb;

    if (cb && cb->connected)
    {
        cb->connected(conn, conn->err);
    }
}

static void notify_disconnected(struct bt_conn *conn)
{
    struct bt_conn_cb *cb = conn_cb;

    if (cb && cb->disconnected)
    {
        cb->disconnected(conn, conn->err);
    }
}

void bt_conn_set_state(struct bt_conn *conn, bt_conn_state_t state)
{
    bt_conn_state_t old_state;
    old_state = conn->state;

    LOG_DBG("%s -> %s", state2str(old_state), state2str(state));

    if (old_state == state)
    {
        LOG_WRN("no transition %s", state2str(state));
        return;
    }

    conn->state = state;

    /* Actions needed for entering the new state */
    switch (conn->state)
    {
    case BT_CONN_CONNECTED:
        bt_conn_connected(conn);
        break;
    case BT_CONN_DISCONNECTED:
        notify_disconnected(conn);
        break;
    default:
        LOG_WRN("no valid (%u) state was set", state);
        break;
    }
}

void bt_conn_process_tx(struct bt_conn *conn)
{
    struct net_buf *buf;
    int err;

    LOG_DBG("conn %p", conn);

    if (conn->state == BT_CONN_DISCONNECTED)
    {
        LOG_DBG("handle %u disconnected - cleaning up", conn->handle);
        //conn_cleanup(conn);
        return;
    }

    buf = net_buf_slist_get(&conn->tx_queue);
    BT_ASSERT(buf);

    err = send_acl(conn, buf, 0);

    if (err)
    {
        /* destroy the buffer */
        net_buf_unref(buf);
    }
}

void bt_conn_tx_polling(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(acl_conns); i++)
    {
        struct bt_conn *conn = &acl_conns[i];

        if (!sys_slist_is_empty(&conn->tx_queue))
        {
            bt_conn_process_tx(conn);
        }
        // tx_complete_polling(conn);
    }
}


int bt_conn_init(void)
{
    return 0;
}


void bt_conn_cb_register(struct bt_conn_cb *cb)
{
    conn_cb = cb;
}

bool bt_conn_is_peer_addr_le(const struct bt_conn *conn, const bt_addr_le_t *peer)
{
    /* Check against conn dst address as it may be the identity address */
    if (bt_addr_le_eq(peer, &conn->le.dst))
    {
        return true;
    }

    /* Check against initial connection address */
    if (conn->role == BT_HCI_ROLE_CENTRAL)
    {
        return bt_addr_le_eq(peer, &conn->le.resp_addr);
    }

    return bt_addr_le_eq(peer, &conn->le.init_addr);
}

struct bt_conn *bt_conn_lookup_addr_le(const bt_addr_le_t *peer)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(acl_conns); i++)
    {
        struct bt_conn *conn = &acl_conns[i];

        if (conn->type != BT_CONN_TYPE_LE)
        {
            continue;
        }

        if (!bt_conn_is_peer_addr_le(conn, peer))
        {
            continue;
        }

        return conn;
    }

    return NULL;
}