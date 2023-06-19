#include "le.h"

#include "bluetooth\uuid.h"
#include "bluetooth\att.h"
#include "bluetooth\gatt.h"

#include "base\byteorder.h"

#include "host\gatt_internal.h"
#include "host\att_internal.h"
#include "host\l2cap.h"

#include "utils\net_buf.h"

#define LOG_MODULE_NAME att
#include "logging/bt_log.h"

typedef enum __packed
{
    ATT_COMMAND,
    ATT_REQUEST,
    ATT_RESPONSE,
    ATT_NOTIFICATION,
    ATT_CONFIRMATION,
    ATT_INDICATION,
    ATT_UNKNOWN,
} att_type_t;

static att_type_t att_op_get_type(uint8_t op);


void le_send_att(byte op, word len, byte *p)
{
	p[4] = op;
	le_send_l2cap(LE_L2CAP_CID_ATT, len + 1, p);
}

void le_send_att_err(byte *txp, byte *rxp)
{
	txp[5] = rxp[6];
	txp[8] = ATT_ERR_ATTRIBUTE_NOT_FOUND;
	PUTW(txp + 6, GETW(rxp + 7));
	le_send_att(ATTOP_ERROR_RESPONSE, 4, txp);
}






static bool range_is_valid(uint16_t start, uint16_t end, uint16_t *err)
{
    /* Handle 0 is invalid */
    if (!start || !end)
    {
        if (err)
        {
            *err = 0U;
        }
        return false;
    }

    /* Check if range is valid */
    if (start > end)
    {
        if (err)
        {
            *err = start;
        }
        return false;
    }

    return true;
}











struct net_buf *bt_att_create_pdu(uint8_t op, size_t len)
{
    struct bt_att_hdr *hdr;
    struct net_buf *buf;

    buf = bt_l2cap_create_pdu(NULL, 0);
    if (!buf)
    {
        LOG_ERR("Unable to allocate buffer for op 0x%02x", op);
        return NULL;
    }

    hdr = net_buf_add(buf, sizeof(*hdr));
    hdr->code = op;

    return buf;
}



struct bt_att_req *bt_att_req_alloc(void)
{
    struct bt_att_req *req = NULL;

    // if (k_current_get() == att_handle_rsp_thread)
    //{
    /* No req will be fulfilled while blocking on the bt_recv thread.
     * Blocking would cause deadlock.
     */
    // timeout = K_NO_WAIT;
    //}

    /* Reserve space for request */
    // if (k_mem_slab_alloc(&req_slab, (void **)&req, timeout))
    // {
    //     LOG_DBG("No space for req");
    //     return NULL;
    // }

    // LOG_DBG("req %p", req);

    // memset(req, 0, sizeof(*req));

    return req;
}

void bt_att_req_free(struct bt_att_req *req)
{
    // LOG_DBG("req %p", req);

    // if (req->buf)
    // {
    //     tx_meta_data_free(bt_att_tx_meta_data(req->buf));
    //     net_buf_unref(req->buf);
    //     req->buf = NULL;
    // }

    // k_mem_slab_free(&req_slab, (void **)&req);
}


int bt_att_req_send(struct bt_conn *conn, struct bt_att_req *req)
{
    // struct bt_att *att;

    // LOG_DBG("conn %p req %p", conn, req);

    // __ASSERT_NO_MSG(conn);
    // __ASSERT_NO_MSG(req);

    // att = att_get(conn);
    // if (!att)
    // {
    //     return -ENOTCONN;
    // }

    // sys_slist_append(&att->reqs, &req->node);
    // att_req_send_process(att);

    return 0;
}


int bt_att_send(struct bt_conn *conn, struct net_buf *buf)
{
    // struct bt_att *att;

    // __ASSERT_NO_MSG(conn);
    // __ASSERT_NO_MSG(buf);

    // att = att_get(conn);
    // if (!att)
    // {
    //     tx_meta_data_free(bt_att_tx_meta_data(buf));
    //     net_buf_unref(buf);
    //     return -ENOTCONN;
    // }

    // net_buf_put(&att->tx_queue, buf);
    // att_send_process(att);

    return bt_att_chan_send_rsp(conn, buf);
}


uint16_t bt_att_get_mtu(struct bt_conn *conn)
{
    // struct bt_att_chan *chan, *tmp;
    // struct bt_att *att;
    // uint16_t mtu = 0;

    // att = att_get(conn);
    // if (!att)
    // {
    //     return 0;
    // }

    // SYS_SLIST_FOR_EACH_CONTAINER_SAFE (&att->chans, chan, tmp, node)
    // {
    //     if (chan->chan.tx.mtu > mtu)
    //     {
    //         mtu = chan->chan.tx.mtu;
    //     }
    // }

    // return mtu;
    return 23;
}

int bt_att_chan_send_rsp(struct bt_conn *conn, struct net_buf *buf)
{
	int err;
	err = bt_l2cap_send(conn, BT_L2CAP_CID_ATT, buf);
	if (err < 0)
	{
		return err;
	}

	return 0;
}


static void send_err_rsp(struct bt_conn *conn, uint8_t req, uint16_t handle, uint8_t err)
{
    struct bt_att_error_rsp *rsp;
    struct net_buf *buf;

    /* Ignore opcode 0x00 */
    if (!req)
    {
        return;
    }

    buf = bt_att_create_pdu(BT_ATT_OP_ERROR_RSP, sizeof(*rsp));
    if (!buf)
    {
        return;
    }

    rsp = net_buf_add(buf, sizeof(*rsp));
    rsp->request = req;
    rsp->handle = sys_cpu_to_le16(handle);
    rsp->error = err;

    bt_att_chan_send_rsp(conn, buf);
}






static uint8_t att_mtu_req(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_att_exchange_mtu_req *req;
    struct bt_att_exchange_mtu_rsp *rsp;
    struct net_buf *pdu;
    uint16_t mtu_client, mtu_server;

    req = (void *)buf->data;

    mtu_client = sys_le16_to_cpu(req->mtu);

    LOG_DBG("Client MTU %u", mtu_client);

    /* Check if MTU is valid */
    if (mtu_client < BT_ATT_DEFAULT_LE_MTU)
    {
        return BT_ATT_ERR_INVALID_PDU;
    }

    pdu = bt_att_create_pdu(BT_ATT_OP_MTU_RSP, sizeof(*rsp));
    if (!pdu)
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    mtu_server = BT_ATT_MTU;

    LOG_DBG("Server MTU %u", mtu_server);

    rsp = net_buf_add(pdu, sizeof(*rsp));
    rsp->mtu = sys_cpu_to_le16(mtu_server);

    bt_att_chan_send_rsp(conn, pdu);

    /* BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part F] page 484:
     *
     * A device's Exchange MTU Request shall contain the same MTU as the
     * device's Exchange MTU Response (i.e. the MTU shall be symmetric).
     */
    // chan->chan.rx.mtu = MIN(mtu_client, mtu_server);
    // chan->chan.tx.mtu = chan->chan.rx.mtu;

    // LOG_DBG("Negotiated MTU %u", chan->chan.rx.mtu);

    // att_chan_mtu_updated(chan);

    return 0;
}


struct find_info_data
{
    struct bt_conn *conn;
    struct net_buf *buf;
    struct bt_att_find_info_rsp *rsp;
    union
    {
        struct bt_att_info_16 *info16;
        struct bt_att_info_128 *info128;
    };
};

static uint8_t find_info_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct find_info_data *data = user_data;
    struct bt_conn *conn = data->conn;

    LOG_DBG("handle 0x%04x", handle);

    /* Initialize rsp at first entry */
    if (!data->rsp)
    {
        data->rsp = net_buf_add(data->buf, sizeof(*data->rsp));
        data->rsp->format =
                (attr->uuid->type == BT_UUID_TYPE_16) ? BT_ATT_INFO_16 : BT_ATT_INFO_128;
    }

    switch (data->rsp->format)
    {
    case BT_ATT_INFO_16:
        if (attr->uuid->type != BT_UUID_TYPE_16)
        {
            return BT_GATT_ITER_STOP;
        }

        /* Fast forward to next item position */
        data->info16 = net_buf_add(data->buf, sizeof(*data->info16));
        data->info16->handle = sys_cpu_to_le16(handle);
        data->info16->uuid = sys_cpu_to_le16(BT_UUID_16(attr->uuid)->val);

        if (conn->mtu - data->buf->len > sizeof(*data->info16))
        {
            return BT_GATT_ITER_CONTINUE;
        }

        break;
    case BT_ATT_INFO_128:
        if (attr->uuid->type != BT_UUID_TYPE_128)
        {
            return BT_GATT_ITER_STOP;
        }

        /* Fast forward to next item position */
        data->info128 = net_buf_add(data->buf, sizeof(*data->info128));
        data->info128->handle = sys_cpu_to_le16(handle);
        memcpy(data->info128->uuid, BT_UUID_128(attr->uuid)->val, sizeof(data->info128->uuid));

        if (conn->mtu - data->buf->len > sizeof(*data->info128))
        {
            return BT_GATT_ITER_CONTINUE;
        }
    }

    return BT_GATT_ITER_STOP;
}

static uint8_t att_find_info_rsp(struct bt_conn *conn, uint16_t start_handle,
                                 uint16_t end_handle)
{
    struct find_info_data data;

    (void)memset(&data, 0, sizeof(data));

    data.buf = bt_att_create_pdu(BT_ATT_OP_FIND_INFO_RSP, 0);
    if (!data.buf)
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    data.conn = conn;
    bt_gatt_foreach_attr(start_handle, end_handle, find_info_cb, &data);

    if (!data.rsp)
    {
        net_buf_unref(data.buf);
        /* Respond since handle is set */
        send_err_rsp(conn, BT_ATT_OP_FIND_INFO_REQ, start_handle, BT_ATT_ERR_ATTRIBUTE_NOT_FOUND);
        return 0;
    }

    bt_att_chan_send_rsp(conn, data.buf);

    return 0;
}

static uint8_t att_find_info_req(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_att_find_info_req *req;
    uint16_t start_handle, end_handle, err_handle;

    req = (void *)buf->data;

    start_handle = sys_le16_to_cpu(req->start_handle);
    end_handle = sys_le16_to_cpu(req->end_handle);

    LOG_DBG("start_handle 0x%04x end_handle 0x%04x", start_handle, end_handle);

    if (!range_is_valid(start_handle, end_handle, &err_handle))
    {
        send_err_rsp(conn, BT_ATT_OP_FIND_INFO_REQ, err_handle, BT_ATT_ERR_INVALID_HANDLE);
        return 0;
    }

    return att_find_info_rsp(conn, start_handle, end_handle);
}


struct find_type_data
{
    struct bt_conn *conn;
    struct net_buf *buf;
    struct bt_att_handle_group *group;
    const void *value;
    uint8_t value_len;
    uint8_t err;
};

static uint8_t find_type_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct find_type_data *data = user_data;
    struct bt_conn *conn = data->conn;
    int read;
    uint8_t uuid[16];
    struct net_buf *frag;
    size_t len;

    /* Skip secondary services */
    if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_SECONDARY))
    {
        goto skip;
    }

    /* Update group end_handle if not a primary service */
    if (bt_uuid_cmp(attr->uuid, BT_UUID_GATT_PRIMARY))
    {
        if (data->group && handle > sys_le16_to_cpu(data->group->end_handle))
        {
            data->group->end_handle = sys_cpu_to_le16(handle);
        }
        return BT_GATT_ITER_CONTINUE;
    }

    LOG_DBG("handle 0x%04x", handle);

    /* stop if there is no space left */
    if (conn->mtu - net_buf_frags_len(data->buf) < sizeof(*data->group))
    {
        return BT_GATT_ITER_STOP;
    }

    frag = net_buf_frag_last(data->buf);

    len = MIN(conn->mtu - net_buf_frags_len(data->buf), net_buf_tailroom(frag));
    if (!len)
    {
        frag = net_buf_alloc(data->buf->pool_id);
        /* If not buffer can be allocated immediately stop */
        if (!frag)
        {
            return BT_GATT_ITER_STOP;
        }

        net_buf_frag_add(data->buf, frag);
    }

    /* Read attribute value and store in the buffer */
    read = attr->read(conn, attr, uuid, sizeof(uuid), 0);
    if (read < 0)
    {
        /*
         * Since we don't know if it is the service with requested UUID,
         * we cannot respond with an error to this request.
         */
        goto skip;
    }

    /* Check if data matches */
    if (read != data->value_len)
    {
        /* Use bt_uuid_cmp() to compare UUIDs of different form. */
        struct bt_uuid_128 ref_uuid;
        struct bt_uuid_128 recvd_uuid;

        if (!bt_uuid_create(&recvd_uuid.uuid, data->value, data->value_len))
        {
            LOG_WRN("Unable to create UUID: size %u", data->value_len);
            goto skip;
        }
        if (!bt_uuid_create(&ref_uuid.uuid, uuid, read))
        {
            LOG_WRN("Unable to create UUID: size %d", read);
            goto skip;
        }
        if (bt_uuid_cmp(&recvd_uuid.uuid, &ref_uuid.uuid))
        {
            goto skip;
        }
    }
    else if (memcmp(data->value, uuid, read))
    {
        goto skip;
    }

    /* If service has been found, error should be cleared */
    data->err = 0x00;

    /* Fast forward to next item position */
    data->group = net_buf_add(frag, sizeof(*data->group));
    data->group->start_handle = sys_cpu_to_le16(handle);
    data->group->end_handle = sys_cpu_to_le16(handle);

    /* continue to find the end_handle */
    return BT_GATT_ITER_CONTINUE;

skip:
    data->group = NULL;
    return BT_GATT_ITER_CONTINUE;
}


static uint8_t att_find_type_rsp(struct bt_conn *conn, uint16_t start_handle,
                                 uint16_t end_handle, const void *value, uint8_t value_len)
{
    struct bt_att_find_type_rsp *rsp;
    struct find_type_data data;

    (void)memset(&data, 0, sizeof(data));

    data.buf = bt_att_create_pdu(BT_ATT_OP_FIND_TYPE_RSP, 0);
    if (!data.buf)
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    data.conn = conn;
    data.group = NULL;
    data.value = value;
    data.value_len = value_len;

    /* Pre-set error in case no service will be found */
    data.err = BT_ATT_ERR_ATTRIBUTE_NOT_FOUND;

    bt_gatt_foreach_attr(start_handle, end_handle, find_type_cb, &data);

    /* If error has not been cleared, no service has been found */
    if (data.err)
    {
        // tx_meta_data_free(bt_att_tx_meta_data(data.buf));
        net_buf_unref(data.buf);
        /* Respond since handle is set */
        send_err_rsp(conn, BT_ATT_OP_FIND_TYPE_REQ, start_handle, data.err);
        return 0;
    }

    bt_att_chan_send_rsp(conn, data.buf);

    return 0;
}

static uint8_t att_find_type_req(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_att_find_type_req *req;
    uint16_t start_handle, end_handle, err_handle, type;
    uint8_t *value;

    req = net_buf_pull_mem(buf, sizeof(*req));

    start_handle = sys_le16_to_cpu(req->start_handle);
    end_handle = sys_le16_to_cpu(req->end_handle);
    type = sys_le16_to_cpu(req->type);
    value = buf->data;

    LOG_DBG("start_handle 0x%04x end_handle 0x%04x type %u", start_handle, end_handle, type);

    if (!range_is_valid(start_handle, end_handle, &err_handle))
    {
        send_err_rsp(conn, BT_ATT_OP_FIND_TYPE_REQ, err_handle, BT_ATT_ERR_INVALID_HANDLE);
        return 0;
    }

    /* The Attribute Protocol Find By Type Value Request shall be used with
     * the Attribute Type parameter set to the UUID for "Primary Service"
     * and the Attribute Value set to the 16-bit Bluetooth UUID or 128-bit
     * UUID for the specific primary service.
     */
    if (bt_uuid_cmp(BT_UUID_DECLARE_16(type), BT_UUID_GATT_PRIMARY))
    {
        send_err_rsp(conn, BT_ATT_OP_FIND_TYPE_REQ, start_handle, BT_ATT_ERR_ATTRIBUTE_NOT_FOUND);
        return 0;
    }

    return att_find_type_rsp(conn, start_handle, end_handle, value, buf->len);
}






static uint8_t err_to_att(int err)
{
    LOG_DBG("%d", err);

    if (err < 0 && err >= -0xff)
    {
        return -err;
    }

    return BT_ATT_ERR_UNLIKELY;
}


struct read_type_data
{
    struct bt_conn *conn;
    struct bt_uuid *uuid;
    struct net_buf *buf;
    struct bt_att_read_type_rsp *rsp;
    struct bt_att_data *item;
    uint8_t err;
};

typedef bool (*attr_read_cb)(struct net_buf *buf, ssize_t read, void *user_data);

static bool attr_read_type_cb(struct net_buf *frag, ssize_t read, void *user_data)
{
    struct read_type_data *data = user_data;

    if (!data->rsp->len)
    {
        /* Set len to be the first item found */
        data->rsp->len = read + sizeof(*data->item);
    }
    else if (data->rsp->len != read + sizeof(*data->item))
    {
        /* All items should have the same size */
        frag->len -= sizeof(*data->item);
        data->item = NULL;
        return false;
    }

    return true;
}

static ssize_t att_chan_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                             struct net_buf *buf, uint16_t offset, attr_read_cb cb, void *user_data)
{
    ssize_t read;
    struct net_buf *frag;
    size_t len, total = 0;

    if (conn->mtu <= net_buf_frags_len(buf))
    {
        return 0;
    }

    frag = net_buf_frag_last(buf);

    /* Create necessary fragments if MTU is bigger than what a buffer can
     * hold.
     */
    do
    {
        len = MIN(conn->mtu - net_buf_frags_len(buf), net_buf_tailroom(frag));
        if (!len)
        {
            frag = net_buf_alloc(buf->pool_id);
            /* If not buffer can be allocated immediately return */
            if (!frag)
            {
                return total;
            }

            net_buf_frag_add(buf, frag);

            len = MIN(conn->mtu - net_buf_frags_len(buf), net_buf_tailroom(frag));
        }

        read = attr->read(conn, attr, frag->data + frag->len, len, offset);
        if (read < 0)
        {
            if (total)
            {
                return total;
            }

            return read;
        }

        if (cb && !cb(frag, read, user_data))
        {
            break;
        }

        net_buf_add(frag, read);
        total += read;
        offset += read;
    } while (conn->mtu > net_buf_frags_len(buf) && read == len);

    return total;
}

static uint8_t read_type_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct read_type_data *data = user_data;
    struct bt_conn *conn = data->conn;
    ssize_t read;

    /* Skip if doesn't match */
    if (bt_uuid_cmp(attr->uuid, data->uuid))
    {
        return BT_GATT_ITER_CONTINUE;
    }

    LOG_DBG("handle 0x%04x", handle);

    /*
     * If an attribute in the set of requested attributes would cause an
     * Error Response then this attribute cannot be included in a
     * Read By Type Response and the attributes before this attribute
     * shall be returned
     *
     * If the first attribute in the set of requested attributes would
     * cause an Error Response then no other attributes in the requested
     * attributes can be considered.
     */
    data->err = bt_gatt_check_perm(conn, attr, BT_GATT_PERM_READ_MASK);
    if (data->err)
    {
        if (data->rsp->len)
        {
            data->err = 0x00;
        }
        return BT_GATT_ITER_STOP;
    }

    /*
     * If any attribute is founded in handle range it means that error
     * should be changed from pre-set: attr not found error to no error.
     */
    data->err = 0x00;

    /* Fast forward to next item position */
    data->item = net_buf_add(net_buf_frag_last(data->buf), sizeof(*data->item));
    data->item->handle = sys_cpu_to_le16(handle);

    read = att_chan_read(conn, attr, data->buf, 0, attr_read_type_cb, data);
    if (read < 0)
    {
        data->err = err_to_att(read);
        return BT_GATT_ITER_STOP;
    }

    if (!data->item)
    {
        return BT_GATT_ITER_STOP;
    }

    /* continue only if there are still space for more items */
    return conn->mtu - net_buf_frags_len(data->buf) > data->rsp->len ? BT_GATT_ITER_CONTINUE
                                                                             : BT_GATT_ITER_STOP;
}


static uint8_t att_read_type_rsp(struct bt_conn *conn, struct bt_uuid *uuid,
                                 uint16_t start_handle, uint16_t end_handle)
{
	struct net_buf* buf;

    struct read_type_data data;

    (void)memset(&data, 0, sizeof(data));

    data.buf = bt_att_create_pdu(BT_ATT_OP_READ_TYPE_RSP, sizeof(*data.rsp));
    if (!data.buf)
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    data.conn = conn;
    data.uuid = uuid;
    data.rsp = net_buf_add(data.buf, sizeof(*data.rsp));
    data.rsp->len = 0U;

    /* Pre-set error if no attr will be found in handle */
    data.err = BT_ATT_ERR_ATTRIBUTE_NOT_FOUND;

    bt_gatt_foreach_attr(start_handle, end_handle, read_type_cb, &data);

    if (data.err)
    {
        // tx_meta_data_free(bt_att_tx_meta_data(data.buf));
        net_buf_unref(data.buf);
        /* Response here since handle is set */
        send_err_rsp(conn, BT_ATT_OP_READ_TYPE_REQ, start_handle, data.err);
        return 0;
    }

    bt_att_chan_send_rsp(conn, data.buf);

    return 0;
}

static uint8_t att_read_type_req(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_att_read_type_req *req;
    uint16_t start_handle, end_handle, err_handle;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_16 u16;
        struct bt_uuid_128 u128;
    } u;
    uint8_t uuid_len = buf->len - sizeof(*req);

    /* Type can only be UUID16 or UUID128 */
    if (uuid_len != 2 && uuid_len != 16)
    {
        return BT_ATT_ERR_INVALID_PDU;
    }

    req = net_buf_pull_mem(buf, sizeof(*req));

    start_handle = sys_le16_to_cpu(req->start_handle);
    end_handle = sys_le16_to_cpu(req->end_handle);
    if (!bt_uuid_create(&u.uuid, req->uuid, uuid_len))
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    // LOG_DBG("start_handle 0x%04x end_handle 0x%04x type %s", start_handle, end_handle,
    //         bt_uuid_str(&u.uuid));
    LOG_DBG("start_handle 0x%04x end_handle 0x%04x", start_handle, end_handle);

    if (!range_is_valid(start_handle, end_handle, &err_handle))
    {
        send_err_rsp(conn, BT_ATT_OP_READ_TYPE_REQ, err_handle, BT_ATT_ERR_INVALID_HANDLE);
        return 0;
    }

    return att_read_type_rsp(conn, &u.uuid, start_handle, end_handle);
}





struct read_data
{
    struct bt_conn *conn;
    uint16_t offset;
    struct net_buf *buf;
    uint8_t err;
};

static uint8_t read_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct read_data *data = user_data;
    struct bt_conn *conn = data->conn;
    int ret;

    LOG_DBG("handle 0x%04x", handle);

    /*
     * If any attribute is founded in handle range it means that error
     * should be changed from pre-set: invalid handle error to no error.
     */
    data->err = 0x00;

    /* Check attribute permissions */
    data->err = bt_gatt_check_perm(conn, attr, BT_GATT_PERM_READ_MASK);
    if (data->err)
    {
        return BT_GATT_ITER_STOP;
    }

    /* Read attribute value and store in the buffer */
    ret = att_chan_read(conn, attr, data->buf, data->offset, NULL, NULL);
    if (ret < 0)
    {
        data->err = err_to_att(ret);
        return BT_GATT_ITER_STOP;
    }

    return BT_GATT_ITER_CONTINUE;
}

static uint8_t att_read_rsp(struct bt_conn *conn, uint8_t op, uint8_t rsp, uint16_t handle,
                            uint16_t offset)
{
    struct read_data data;

    // if (!bt_gatt_change_aware(conn, true))
    // {
    //     if (!atomic_test_and_set_bit(chan->flags, ATT_OUT_OF_SYNC_SENT))
    //     {
    //         return BT_ATT_ERR_DB_OUT_OF_SYNC;
    //     }
    //     else
    //     {
    //         return 0;
    //     }
    // }

    if (!handle)
    {
        return BT_ATT_ERR_INVALID_HANDLE;
    }

    (void)memset(&data, 0, sizeof(data));

    data.buf = bt_att_create_pdu(rsp, 0);
    if (!data.buf)
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    data.conn = conn;
    data.offset = offset;

    /* Pre-set error if no attr will be found in handle */
    data.err = BT_ATT_ERR_INVALID_HANDLE;

    bt_gatt_foreach_attr(handle, handle, read_cb, &data);

    /* In case of error discard data and respond with an error */
    if (data.err)
    {
        // tx_meta_data_free(bt_att_tx_meta_data(data.buf));
        net_buf_unref(data.buf);
        /* Respond here since handle is set */
        send_err_rsp(conn, op, handle, data.err);
        return 0;
    }

    bt_att_chan_send_rsp(conn, data.buf);

    return 0;
}

static uint8_t att_read_req(struct bt_att_chan *chan, struct net_buf *buf)
{
    struct bt_att_read_req *req;
    uint16_t handle;

    req = (void *)buf->data;

    handle = sys_le16_to_cpu(req->handle);

    LOG_DBG("handle 0x%04x", handle);

    return att_read_rsp(chan, BT_ATT_OP_READ_REQ, BT_ATT_OP_READ_RSP, handle, 0);
}




















struct read_group_data
{
    struct bt_conn *conn;
    struct bt_uuid *uuid;
    struct net_buf *buf;
    struct bt_att_read_group_rsp *rsp;
    struct bt_att_group_data *group;
};

static bool attr_read_group_cb(struct net_buf *frag, ssize_t read, void *user_data)
{
    struct read_group_data *data = user_data;

    if (!data->rsp->len)
    {
        /* Set len to be the first group found */
        data->rsp->len = read + sizeof(*data->group);
    }
    else if (data->rsp->len != read + sizeof(*data->group))
    {
        /* All groups entries should have the same size */
        data->buf->len -= sizeof(*data->group);
        data->group = NULL;
        return false;
    }

    return true;
}

static uint8_t read_group_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct read_group_data *data = user_data;
    struct bt_conn *conn = data->conn;
    int read;

    /* Update group end_handle if attribute is not a service */
    if (bt_uuid_cmp(attr->uuid, BT_UUID_GATT_PRIMARY) &&
        bt_uuid_cmp(attr->uuid, BT_UUID_GATT_SECONDARY))
    {
        if (data->group && handle > sys_le16_to_cpu(data->group->end_handle))
        {
            data->group->end_handle = sys_cpu_to_le16(handle);
        }
        return BT_GATT_ITER_CONTINUE;
    }

    /* If Group Type don't match skip */
    if (bt_uuid_cmp(attr->uuid, data->uuid))
    {
        data->group = NULL;
        return BT_GATT_ITER_CONTINUE;
    }

    LOG_DBG("handle 0x%04x", handle);

    /* Stop if there is no space left */
    if (data->rsp->len && conn->mtu - data->buf->len < data->rsp->len)
    {
        return BT_GATT_ITER_STOP;
    }

    /* Fast forward to next group position */
    data->group = net_buf_add(data->buf, sizeof(*data->group));

    /* Initialize group handle range */
    data->group->start_handle = sys_cpu_to_le16(handle);
    data->group->end_handle = sys_cpu_to_le16(handle);

    /* Read attribute value and store in the buffer */
    read = att_chan_read(conn, attr, data->buf, 0, attr_read_group_cb, data);
    if (read < 0)
    {
        /* TODO: Handle read errors */
        return BT_GATT_ITER_STOP;
    }

    if (!data->group)
    {
        return BT_GATT_ITER_STOP;
    }

    /* continue only if there are still space for more items */
    return BT_GATT_ITER_CONTINUE;
}

static uint8_t att_read_group_rsp(struct bt_conn *conn, struct bt_uuid *uuid,
                                  uint16_t start_handle, uint16_t end_handle)
{
    struct read_group_data data;

    (void)memset(&data, 0, sizeof(data));

    data.buf = bt_att_create_pdu(BT_ATT_OP_READ_GROUP_RSP, sizeof(*data.rsp));
    if (!data.buf)
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    data.conn = conn;
    data.uuid = uuid;
    data.rsp = net_buf_add(data.buf, sizeof(*data.rsp));
    data.rsp->len = 0U;
    data.group = NULL;

    bt_gatt_foreach_attr(start_handle, end_handle, read_group_cb, &data);

    if (!data.rsp->len)
    {
        // tx_meta_data_free(bt_att_tx_meta_data(data.buf));
        net_buf_unref(data.buf);
        /* Respond here since handle is set */
        send_err_rsp(conn, BT_ATT_OP_READ_GROUP_REQ, start_handle, BT_ATT_ERR_ATTRIBUTE_NOT_FOUND);
        return 0;
    }

    bt_att_chan_send_rsp(conn, data.buf);

    return 0;
}

static uint8_t att_read_group_req(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_att_read_group_req *req;
    uint16_t start_handle, end_handle, err_handle;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_16 u16;
        struct bt_uuid_128 u128;
    } u;
    uint8_t uuid_len = buf->len - sizeof(*req);

    /* Type can only be UUID16 or UUID128 */
    if (uuid_len != 2 && uuid_len != 16)
    {
        return BT_ATT_ERR_INVALID_PDU;
    }

    req = net_buf_pull_mem(buf, sizeof(*req));

    start_handle = sys_le16_to_cpu(req->start_handle);
    end_handle = sys_le16_to_cpu(req->end_handle);

    if (!bt_uuid_create(&u.uuid, req->uuid, uuid_len))
    {
        return BT_ATT_ERR_UNLIKELY;
    }

    // LOG_DBG("start_handle 0x%04x end_handle 0x%04x type %s", start_handle, end_handle,
    //         bt_uuid_str(&u.uuid));
    LOG_DBG("start_handle 0x%04x end_handle 0x%04x", start_handle, end_handle);

    if (!range_is_valid(start_handle, end_handle, &err_handle))
    {
        send_err_rsp(conn, BT_ATT_OP_READ_GROUP_REQ, err_handle, BT_ATT_ERR_INVALID_HANDLE);
        return 0;
    }

    /* Core v4.2, Vol 3, sec 2.5.3 Attribute Grouping:
     * Not all of the grouping attributes can be used in the ATT
     * Read By Group Type Request. The "Primary Service" and "Secondary
     * Service" grouping types may be used in the Read By Group Type
     * Request. The "Characteristic" grouping type shall not be used in
     * the ATT Read By Group Type Request.
     */
    if (bt_uuid_cmp(&u.uuid, BT_UUID_GATT_PRIMARY) && bt_uuid_cmp(&u.uuid, BT_UUID_GATT_SECONDARY))
    {
        send_err_rsp(conn, BT_ATT_OP_READ_GROUP_REQ, start_handle,
                     BT_ATT_ERR_UNSUPPORTED_GROUP_TYPE);
        return 0;
    }

    return att_read_group_rsp(conn, &u.uuid, start_handle, end_handle);
}



struct write_data
{
    struct bt_conn *conn;
    struct net_buf *buf;
    uint8_t req;
    const void *value;
    uint16_t len;
    uint16_t offset;
    uint8_t err;
};

static uint8_t write_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct write_data *data = user_data;
    int write;
    uint8_t flags = 0U;

    LOG_DBG("handle 0x%04x offset %u", handle, data->offset);

    /* Check attribute permissions */
    data->err = bt_gatt_check_perm(data->conn, attr, BT_GATT_PERM_WRITE_MASK);
    if (data->err)
    {
        return BT_GATT_ITER_STOP;
    }

    /* Set command flag if not a request */
    if (!data->req)
    {
        flags |= BT_GATT_WRITE_FLAG_CMD;
    }
    else if (data->req == BT_ATT_OP_EXEC_WRITE_REQ)
    {
        flags |= BT_GATT_WRITE_FLAG_EXECUTE;
    }

    /* Write attribute value */
    write = attr->write(data->conn, attr, data->value, data->len, data->offset, flags);
    if (write < 0 || write != data->len)
    {
        data->err = err_to_att(write);
        return BT_GATT_ITER_STOP;
    }

    data->err = 0U;

    return BT_GATT_ITER_CONTINUE;
}

static uint8_t att_write_rsp(struct bt_conn *conn, uint8_t req, uint8_t rsp, uint16_t handle,
                             uint16_t offset, const void *value, uint16_t len)
{
    struct write_data data;

    // if (!bt_gatt_change_aware(chan->att->conn, req ? true : false))
    // {
    //     if (!atomic_test_and_set_bit(chan->flags, ATT_OUT_OF_SYNC_SENT))
    //     {
    //         return BT_ATT_ERR_DB_OUT_OF_SYNC;
    //     }
    //     else
    //     {
    //         return 0;
    //     }
    // }

    if (!handle)
    {
        return BT_ATT_ERR_INVALID_HANDLE;
    }

    (void)memset(&data, 0, sizeof(data));

    /* Only allocate buf if required to respond */
    if (rsp)
    {
        data.buf = bt_att_create_pdu(rsp, 0);
        if (!data.buf)
        {
            return BT_ATT_ERR_UNLIKELY;
        }
    }

    data.conn = conn;
    data.req = req;
    data.offset = offset;
    data.value = value;
    data.len = len;
    data.err = BT_ATT_ERR_INVALID_HANDLE;

    bt_gatt_foreach_attr(handle, handle, write_cb, &data);

    if (data.err)
    {
        /* In case of error discard data and respond with an error */
        if (rsp)
        {
            // tx_meta_data_free(bt_att_tx_meta_data(data.buf));
            net_buf_unref(data.buf);
            /* Respond here since handle is set */
            send_err_rsp(conn, req, handle, data.err);
        }
        return req == BT_ATT_OP_EXEC_WRITE_REQ ? data.err : 0;
    }

    if (data.buf)
    {
        bt_att_chan_send_rsp(conn, data.buf);
    }

    return 0;
}

static uint8_t att_write_req(struct bt_conn *conn, struct net_buf *buf)
{
    uint16_t handle;

    handle = net_buf_pull_le16(buf);

    LOG_DBG("handle 0x%04x", handle);

    return att_write_rsp(conn, BT_ATT_OP_WRITE_REQ, BT_ATT_OP_WRITE_RSP, handle, 0, buf->data,
                         buf->len);
}



static uint8_t att_confirm(struct bt_conn *conn, struct net_buf *buf)
{
    LOG_DBG("");

    return 0;
    // return att_handle_rsp(conn, buf->data, buf->len, 0);
}



static uint8_t att_write_cmd(struct bt_conn *conn, struct net_buf *buf)
{
    uint16_t handle;

    handle = net_buf_pull_le16(buf);

    LOG_DBG("handle 0x%04x", handle);

    return att_write_rsp(conn, 0, 0, handle, 0, buf->data, buf->len);
}



















static const struct att_handler
{
    uint8_t op;
    uint8_t expect_len;
    att_type_t type;
    uint8_t (*func)(struct bt_conn *conn, struct net_buf *buf);
} handlers[] = {
        {BT_ATT_OP_MTU_REQ, sizeof(struct bt_att_exchange_mtu_req), ATT_REQUEST, att_mtu_req},
        {BT_ATT_OP_FIND_INFO_REQ, sizeof(struct bt_att_find_info_req), ATT_REQUEST,
         att_find_info_req},
        {BT_ATT_OP_FIND_TYPE_REQ, sizeof(struct bt_att_find_type_req), ATT_REQUEST,
         att_find_type_req},
        {BT_ATT_OP_READ_TYPE_REQ, sizeof(struct bt_att_read_type_req), ATT_REQUEST,
         att_read_type_req},
        {BT_ATT_OP_READ_REQ, sizeof(struct bt_att_read_req), ATT_REQUEST, att_read_req},
        // {BT_ATT_OP_READ_BLOB_REQ, sizeof(struct bt_att_read_blob_req), ATT_REQUEST,
        //  att_read_blob_req},
#if defined(CONFIG_BT_GATT_READ_MULTIPLE)
        // {BT_ATT_OP_READ_MULT_REQ, BT_ATT_READ_MULT_MIN_LEN_REQ, ATT_REQUEST, att_read_mult_req},
#endif /* CONFIG_BT_GATT_READ_MULTIPLE */
#if defined(CONFIG_BT_GATT_READ_MULT_VAR_LEN)
        // {BT_ATT_OP_READ_MULT_VL_REQ, BT_ATT_READ_MULT_MIN_LEN_REQ, ATT_REQUEST,
        //  att_read_mult_vl_req},
#endif /* CONFIG_BT_GATT_READ_MULT_VAR_LEN */
        {BT_ATT_OP_READ_GROUP_REQ, sizeof(struct bt_att_read_group_req), ATT_REQUEST,
         att_read_group_req},
        {BT_ATT_OP_WRITE_REQ, sizeof(struct bt_att_write_req), ATT_REQUEST, att_write_req},
        // {BT_ATT_OP_PREPARE_WRITE_REQ, sizeof(struct bt_att_prepare_write_req), ATT_REQUEST,
        //  att_prepare_write_req},
        // {BT_ATT_OP_EXEC_WRITE_REQ, sizeof(struct bt_att_exec_write_req), ATT_REQUEST,
        //  att_exec_write_req},
        {BT_ATT_OP_CONFIRM, 0, ATT_CONFIRMATION, att_confirm},
        {BT_ATT_OP_WRITE_CMD, sizeof(struct bt_att_write_cmd), ATT_COMMAND, att_write_cmd},
#if defined(CONFIG_BT_SIGNING)
        {BT_ATT_OP_SIGNED_WRITE_CMD,
         (sizeof(struct bt_att_write_cmd) + sizeof(struct bt_att_signature)), ATT_COMMAND,
         att_signed_write_cmd},
#endif /* CONFIG_BT_SIGNING */
#if defined(CONFIG_BT_GATT_CLIENT)
        {BT_ATT_OP_ERROR_RSP, sizeof(struct bt_att_error_rsp), ATT_RESPONSE, att_error_rsp},
        {BT_ATT_OP_MTU_RSP, sizeof(struct bt_att_exchange_mtu_rsp), ATT_RESPONSE, att_mtu_rsp},
        {BT_ATT_OP_FIND_INFO_RSP, sizeof(struct bt_att_find_info_rsp), ATT_RESPONSE,
         att_handle_find_info_rsp},
        {BT_ATT_OP_FIND_TYPE_RSP, sizeof(struct bt_att_handle_group), ATT_RESPONSE,
         att_handle_find_type_rsp},
        {BT_ATT_OP_READ_TYPE_RSP, sizeof(struct bt_att_read_type_rsp), ATT_RESPONSE,
         att_handle_read_type_rsp},
        {BT_ATT_OP_READ_RSP, 0, ATT_RESPONSE, att_handle_read_rsp},
        {BT_ATT_OP_READ_BLOB_RSP, 0, ATT_RESPONSE, att_handle_read_blob_rsp},
#if defined(CONFIG_BT_GATT_READ_MULTIPLE)
        {BT_ATT_OP_READ_MULT_RSP, 0, ATT_RESPONSE, att_handle_read_mult_rsp},
#endif /* CONFIG_BT_GATT_READ_MULTIPLE */
#if defined(CONFIG_BT_GATT_READ_MULT_VAR_LEN)
        {BT_ATT_OP_READ_MULT_VL_RSP, sizeof(struct bt_att_read_mult_vl_rsp), ATT_RESPONSE,
         att_handle_read_mult_vl_rsp},
#endif /* CONFIG_BT_GATT_READ_MULT_VAR_LEN */
        {BT_ATT_OP_READ_GROUP_RSP, sizeof(struct bt_att_read_group_rsp), ATT_RESPONSE,
         att_handle_read_group_rsp},
        {BT_ATT_OP_WRITE_RSP, 0, ATT_RESPONSE, att_handle_write_rsp},
        {BT_ATT_OP_PREPARE_WRITE_RSP, sizeof(struct bt_att_prepare_write_rsp), ATT_RESPONSE,
         att_handle_prepare_write_rsp},
        {BT_ATT_OP_EXEC_WRITE_RSP, 0, ATT_RESPONSE, att_handle_exec_write_rsp},
        {BT_ATT_OP_NOTIFY, sizeof(struct bt_att_notify), ATT_NOTIFICATION, att_notify},
        {BT_ATT_OP_INDICATE, sizeof(struct bt_att_indicate), ATT_INDICATION, att_indicate},
        {BT_ATT_OP_NOTIFY_MULT, sizeof(struct bt_att_notify_mult), ATT_NOTIFICATION,
         att_notify_mult},
#endif /* CONFIG_BT_GATT_CLIENT */
};

static att_type_t att_op_get_type(uint8_t op)
{
    switch (op)
    {
    case BT_ATT_OP_MTU_REQ:
    case BT_ATT_OP_FIND_INFO_REQ:
    case BT_ATT_OP_FIND_TYPE_REQ:
    case BT_ATT_OP_READ_TYPE_REQ:
    case BT_ATT_OP_READ_REQ:
    case BT_ATT_OP_READ_BLOB_REQ:
    case BT_ATT_OP_READ_MULT_REQ:
    case BT_ATT_OP_READ_MULT_VL_REQ:
    case BT_ATT_OP_READ_GROUP_REQ:
    case BT_ATT_OP_WRITE_REQ:
    case BT_ATT_OP_PREPARE_WRITE_REQ:
    case BT_ATT_OP_EXEC_WRITE_REQ:
        return ATT_REQUEST;
    case BT_ATT_OP_CONFIRM:
        return ATT_CONFIRMATION;
    case BT_ATT_OP_WRITE_CMD:
    case BT_ATT_OP_SIGNED_WRITE_CMD:
        return ATT_COMMAND;
    case BT_ATT_OP_ERROR_RSP:
    case BT_ATT_OP_MTU_RSP:
    case BT_ATT_OP_FIND_INFO_RSP:
    case BT_ATT_OP_FIND_TYPE_RSP:
    case BT_ATT_OP_READ_TYPE_RSP:
    case BT_ATT_OP_READ_RSP:
    case BT_ATT_OP_READ_BLOB_RSP:
    case BT_ATT_OP_READ_MULT_RSP:
    case BT_ATT_OP_READ_MULT_VL_RSP:
    case BT_ATT_OP_READ_GROUP_RSP:
    case BT_ATT_OP_WRITE_RSP:
    case BT_ATT_OP_PREPARE_WRITE_RSP:
    case BT_ATT_OP_EXEC_WRITE_RSP:
        return ATT_RESPONSE;
    case BT_ATT_OP_NOTIFY:
    case BT_ATT_OP_NOTIFY_MULT:
        return ATT_NOTIFICATION;
    case BT_ATT_OP_INDICATE:
        return ATT_INDICATION;
    }

    // if (op & ATT_CMD_MASK)
    // {
    //     return ATT_COMMAND;
    // }

    return ATT_UNKNOWN;
}

int bt_att_recv(struct bt_conn *conn, struct net_buf *buf)
{
    struct bt_att_hdr *hdr;
    const struct att_handler *handler;
    uint8_t err;
    size_t i;

    if (buf->len < sizeof(*hdr))
    {
        LOG_ERR("Too small ATT PDU received");
        return 0;
    }

    hdr = net_buf_pull_mem(buf, sizeof(*hdr));
    LOG_DBG("Received ATT code 0x%02x len %zu", hdr->code,
            net_buf_frags_len(buf));

    for (i = 0, handler = NULL; i < ARRAY_SIZE(handlers); i++)
    {
        if (hdr->code == handlers[i].op)
        {
            handler = &handlers[i];
            break;
        }
    }

    if (!handler)
    {
        LOG_WRN("Unhandled ATT code 0x%02x", hdr->code);
        if (att_op_get_type(hdr->code) != ATT_COMMAND &&
            att_op_get_type(hdr->code) != ATT_INDICATION)
        {
            send_err_rsp(conn, hdr->code, 0, BT_ATT_ERR_NOT_SUPPORTED);
        }
        return 0;
    }

#if defined(CONFIG_BT_ATT_ENFORCE_FLOW)
    {
        if (handler->type == ATT_REQUEST &&
            atomic_test_and_set_bit(att_chan->flags, ATT_PENDING_RSP))
        {
            LOG_WRN("Ignoring unexpected request");
            return 0;
        }
        else if (handler->type == ATT_INDICATION &&
                 atomic_test_and_set_bit(att_chan->flags, ATT_PENDING_CFM))
        {
            LOG_WRN("Ignoring unexpected indication");
            return 0;
        }
    }
#endif

    if (buf->len < handler->expect_len)
    {
        LOG_ERR("Invalid len %u for code 0x%02x", buf->len, hdr->code);
        err = BT_ATT_ERR_INVALID_PDU;
    }
    else
    {
        err = handler->func(conn, buf);
    }

    if (handler->type == ATT_REQUEST && err)
    {
        LOG_DBG("ATT error 0x%02x", err);
        send_err_rsp(conn, hdr->code, 0, err);
    }

    return 0;
}



