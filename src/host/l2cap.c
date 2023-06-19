#include "le.h"
#include "l2cap.h"

#include "base\byteorder.h"

#define LOG_MODULE_NAME l2cap
#include "logging/bt_log.h"

struct net_buf *bt_l2cap_create_pdu(struct spool *pool, size_t reserve)
{
    return bt_conn_create_pdu(pool, sizeof(struct bt_l2cap_hdr) + reserve);
}


int bt_l2cap_send(struct bt_conn *conn, uint16_t cid, struct net_buf *buf)
{
    struct bt_l2cap_hdr *hdr;

    LOG_DBG("conn %p cid %u len %zu", conn, cid, net_buf_frags_len(buf));

    hdr = net_buf_push(buf, sizeof(*hdr));
    hdr->len = sys_cpu_to_le16(buf->len - sizeof(*hdr));
    hdr->cid = sys_cpu_to_le16(cid);

    return bt_conn_send(conn, buf);
}

void le_send_l2cap(word cid, word len, byte *p)
{
	// PUTW(p, len);
	// PUTW(p + 2, cid);
	// tx_queue(LLID_START, len + 4, p);
}

void bt_l2cap_recv(struct bt_conn *conn, struct net_buf *buf, bool complete)
{
    struct bt_l2cap_hdr *hdr;
    uint16_t cid;

    if (buf->len < sizeof(*hdr))
    {
        LOG_ERR("Too small L2CAP PDU received");
        net_buf_unref(buf);
        return;
    }

    hdr = net_buf_pull_mem(buf, sizeof(*hdr));
    cid = sys_le16_to_cpu(hdr->cid);

    LOG_DBG("Packet for CID %u len %u", cid, buf->len);

	switch(cid) {
		case LE_L2CAP_CID_ATT:
			bt_att_recv(conn, buf);
			break;
		default:
			BT_ASSERT_MSG(0, "cid not support: ", cid);
			break;
	}
    
    net_buf_unref(buf);
}