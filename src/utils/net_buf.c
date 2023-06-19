/* buf.c - Buffer management */

/*
 * Copyright (c) 2015-2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "base/byteorder.h"
#include "base/__assert.h"

#include "net_buf.h"

#define LOG_MODULE_NAME net_buf
#include "logging/bt_log.h"


void net_buf_reset(struct net_buf *buf)
{
    __ASSERT_NO_MSG(buf->flags == 0U);
    __ASSERT_NO_MSG(buf->frags == NULL);

    net_buf_simple_reset(&buf->b);
}

struct net_buf *net_buf_alloc(struct spool *pool)
{
    struct net_buf *buf;

    LOG_DBG("%s():%d: pool %p", __FILE__, __LINE__, pool);

    buf = (struct net_buf *)spool_dequeue(pool);
    LOG_DBG("buf %p", buf);
    if (buf == NULL)
    {
        return NULL;
    }

    buf->pool_id = pool;
    buf->__buf = buf->user_data; // default user size is point.

    buf->ref = 1U;
    buf->frags = NULL;
    buf->size = pool->data_size;
    net_buf_reset(buf);

    return buf;
}

void net_buf_simple_init_with_data(struct net_buf_simple *buf, void *data, size_t size)
{
    buf->__buf = data;
    buf->data = data;
    buf->size = size;
    buf->len = size;
}
/*note :The buffer is not expected to contain any data when this API is called, reserve size room
 */
void net_buf_simple_reserve(struct net_buf_simple *buf, size_t reserve)
{
    __ASSERT_NO_MSG(buf);
    __ASSERT_NO_MSG(buf->len == 0U);
    LOG_DBG("buf_simple %p reserve %zu", buf, reserve);

    buf->data = buf->__buf + reserve;
}

void net_buf_slist_put(sys_slist_t *list, struct net_buf *buf)
{
    struct net_buf *tail;

    __ASSERT_NO_MSG(list);
    __ASSERT_NO_MSG(buf);

    for (tail = buf; tail->frags; tail = tail->frags)
    {
        tail->flags |= NET_BUF_FRAGS;
        LOG_DBG("buf %p pool_id %p frags %p", buf, buf->pool_id, buf->frags);
    }
    // LOG_DBG("test_flag %d", buf->flags);

    __ebt_disable_isr();
    sys_slist_append_list(list, &buf->node, &tail->node);
    __ebt_enable_isr();
}

struct net_buf *net_buf_slist_get(sys_slist_t *list)
{
    struct net_buf *buf, *frag;

    __ASSERT_NO_MSG(list);

    __ebt_disable_isr();
    buf = (void *)sys_slist_get(list);

    if (!buf)
    {
        __ebt_enable_isr();
        return NULL;
    }
    // LOG_DBG("test_flag %d", buf->flags);

    /* Get any fragments belonging to this buffer */
    for (frag = buf; (frag->flags & NET_BUF_FRAGS); frag = frag->frags)
    {
        frag->frags = (void *)sys_slist_get(list);

        __ASSERT_NO_MSG(frag->frags);

        /* The fragments flag is only for list-internal usage */
        frag->flags &= ~NET_BUF_FRAGS;
    }

    /* Mark the end of the fragment list */
    frag->frags = NULL;
    __ebt_enable_isr();

    return buf;
}

void net_buf_unref(struct net_buf *buf)
{
    __ASSERT_NO_MSG(buf);

    while (buf)
    {
        struct net_buf *frags = buf->frags;
        struct spool *pool = buf->pool_id;

#if defined(CONFIG_BT_DEBUG)
        if (!buf->ref)
        {
            return;
        }
#endif
        LOG_DBG("buf %p ref %u pool_id %p frags %p", buf, buf->ref, buf->pool_id, buf->frags);
        // LOG_DBG("test_flag %d", buf->flags);

        if (--buf->ref > 0)
        {
            return;
        }

        buf->data = NULL;
        buf->frags = NULL;

        if (pool)
        {
            spool_enqueue(pool, buf);
        }

        buf = frags;
    }
}
/*Increment the reference count of a buffer.*/
struct net_buf *net_buf_ref(struct net_buf *buf)
{
    __ASSERT_NO_MSG(buf);

    LOG_DBG("net_buf_ref, buf %p (old) ref %u pool_id %p", buf, buf->ref, buf->pool_id);
    // LOG_DBG("test_flag %d", buf->flags);
    buf->ref++;
    return buf;
}

struct net_buf *net_buf_frag_last(struct net_buf *buf)
{
    __ASSERT_NO_MSG(buf);

    while (buf->frags)
    {
        buf = buf->frags;
    }

    return buf;
}

void net_buf_frag_insert(struct net_buf *parent, struct net_buf *frag)
{
    __ASSERT_NO_MSG(parent);
    __ASSERT_NO_MSG(frag);

    if (parent->frags)
    {
        net_buf_frag_last(frag)->frags = parent->frags;
    }
    /* Take ownership of the fragment reference */
    parent->frags = frag;
}

struct net_buf *net_buf_frag_add(struct net_buf *head, struct net_buf *frag)
{
    __ASSERT_NO_MSG(frag);

    if (!head)
    {
        return net_buf_ref(frag);
    }

    net_buf_frag_insert(net_buf_frag_last(head), frag);

    return head;
}

struct net_buf *net_buf_frag_del(struct net_buf *parent, struct net_buf *frag)
{
    struct net_buf *next_frag;

    __ASSERT_NO_MSG(frag);

    if (parent)
    {
        __ASSERT_NO_MSG(parent->frags);
        __ASSERT_NO_MSG(parent->frags == frag);
        parent->frags = frag->frags;
    }

    next_frag = frag->frags;

    frag->frags = NULL;

    net_buf_unref(frag);

    return next_frag;
}

void net_buf_simple_clone(const struct net_buf_simple *original, struct net_buf_simple *clone)
{
    memcpy(clone, original, sizeof(struct net_buf_simple));
}

void *net_buf_simple_add(struct net_buf_simple *buf, size_t len)
{
    uint8_t *tail = net_buf_simple_tail(buf);

    LOG_DBG("net_buf_simple_add, buf %p len %zu", buf, len);

    __ASSERT_NO_MSG(net_buf_simple_tailroom(buf) >= len);

    buf->len += len;
    return tail;
}

void *net_buf_simple_add_mem(struct net_buf_simple *buf, const void *mem, size_t len)
{
    LOG_DBG("net_buf_simple_add_mem, buf %p len %zu", buf, len);

    return memcpy(net_buf_simple_add(buf, len), mem, len);
}

uint8_t *net_buf_simple_add_u8(struct net_buf_simple *buf, uint8_t val)
{
    uint8_t *u8;

    LOG_DBG("net_buf_simple_add_u8, buf %p val 0x%02x", buf, val);

    u8 = net_buf_simple_add(buf, 1);
    *u8 = val;

    return u8;
}

void net_buf_simple_add_le16(struct net_buf_simple *buf, uint16_t val)
{
    LOG_DBG("net_buf_simple_add_le16, buf %p val %u", buf, val);

    sys_put_le16(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_be16(struct net_buf_simple *buf, uint16_t val)
{
    LOG_DBG("net_buf_simple_add_be16, buf %p val %u", buf, val);

    sys_put_be16(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_le24(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_add_le24, buf %p val %u", buf, val);

    sys_put_le24(val, net_buf_simple_add(buf, 3));
}

void net_buf_simple_add_be24(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_add_be24, buf %p val %u", buf, val);

    sys_put_be24(val, net_buf_simple_add(buf, 3));
}

void net_buf_simple_add_le32(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_add_le32, buf %p val %u", buf, val);

    sys_put_le32(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_be32(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_add_be32, buf %p val %u", buf, val);

    sys_put_be32(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_le48(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_add_le48, buf %p val %" PRIu64, buf, val);

    sys_put_le48(val, net_buf_simple_add(buf, 6));
}

void net_buf_simple_add_be48(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_add_be48, buf %p val %" PRIu64, buf, val);

    sys_put_be48(val, net_buf_simple_add(buf, 6));
}

void net_buf_simple_add_le64(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_add_le64, buf %p val %" PRIu64, buf, val);

    sys_put_le64(val, net_buf_simple_add(buf, sizeof(val)));
}

void net_buf_simple_add_be64(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_add_be64, buf %p val %" PRIu64, buf, val);

    sys_put_be64(val, net_buf_simple_add(buf, sizeof(val)));
}

void *net_buf_simple_push(struct net_buf_simple *buf, size_t len)
{
    LOG_DBG("net_buf_simple_push, buf %p len %zu", buf, len);

    __ASSERT_NO_MSG(net_buf_simple_headroom(buf) >= len);

    buf->data -= len;
    buf->len += len;
    return buf->data;
}

void net_buf_simple_push_le16(struct net_buf_simple *buf, uint16_t val)
{
    LOG_DBG("net_buf_simple_push_le16, buf %p val %u", buf, val);

    sys_put_le16(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_be16(struct net_buf_simple *buf, uint16_t val)
{
    LOG_DBG("net_buf_simple_push_be16, buf %p val %u", buf, val);

    sys_put_be16(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_u8(struct net_buf_simple *buf, uint8_t val)
{
    uint8_t *data = net_buf_simple_push(buf, 1);

    *data = val;
}

void net_buf_simple_push_le24(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_push_le24, buf %p val %u", buf, val);

    sys_put_le24(val, net_buf_simple_push(buf, 3));
}

void net_buf_simple_push_be24(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_push_be24, buf %p val %u", buf, val);

    sys_put_be24(val, net_buf_simple_push(buf, 3));
}

void net_buf_simple_push_le32(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_push_le32, buf %p val %u", buf, val);

    sys_put_le32(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_be32(struct net_buf_simple *buf, uint32_t val)
{
    LOG_DBG("net_buf_simple_push_be32, buf %p val %u", buf, val);

    sys_put_be32(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_le48(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_push_le48, buf %p val %" PRIu64, buf, val);

    sys_put_le48(val, net_buf_simple_push(buf, 6));
}

void net_buf_simple_push_be48(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_push_be48, buf %p val %" PRIu64, buf, val);

    sys_put_be48(val, net_buf_simple_push(buf, 6));
}

void net_buf_simple_push_le64(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_push_le64, buf %p val %" PRIu64, buf, val);

    sys_put_le64(val, net_buf_simple_push(buf, sizeof(val)));
}

void net_buf_simple_push_be64(struct net_buf_simple *buf, uint64_t val)
{
    // LOG_DBG("net_buf_simple_push_be64, buf %p val %" PRIu64, buf, val);

    sys_put_be64(val, net_buf_simple_push(buf, sizeof(val)));
}

void *net_buf_simple_pull(struct net_buf_simple *buf, size_t len)
{
    LOG_DBG("net_buf_simple_pull, buf %p len %zu", buf, len);

    __ASSERT_NO_MSG(buf->len >= len);

    buf->len -= len;
    return buf->data += len;
}

void *net_buf_simple_pull_mem(struct net_buf_simple *buf, size_t len)
{
    void *data = buf->data;

    LOG_DBG("net_buf_simple_pull_mem, buf %p len %zu", buf, len);

    __ASSERT_NO_MSG(buf->len >= len);

    buf->len -= len;
    buf->data += len;

    return data;
}

uint8_t net_buf_simple_pull_u8(struct net_buf_simple *buf)
{
    uint8_t val;

    val = buf->data[0];
    net_buf_simple_pull(buf, 1);

    return val;
}

uint16_t net_buf_simple_pull_le16(struct net_buf_simple *buf)
{
    uint16_t val;

    val = UNALIGNED_GET((uint16_t *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_le16_to_cpu(val);
}

uint16_t net_buf_simple_pull_be16(struct net_buf_simple *buf)
{
    uint16_t val;

    val = UNALIGNED_GET((uint16_t *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_be16_to_cpu(val);
}

uint32_t net_buf_simple_pull_le24(struct net_buf_simple *buf)
{
    struct uint24
    {
        uint32_t u24 : 24;
    } __packed val;

    val = UNALIGNED_GET((struct uint24 *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_le24_to_cpu(val.u24);
}

uint32_t net_buf_simple_pull_be24(struct net_buf_simple *buf)
{
    struct uint24
    {
        uint32_t u24 : 24;
    } __packed val;

    val = UNALIGNED_GET((struct uint24 *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_be24_to_cpu(val.u24);
}

uint32_t net_buf_simple_pull_le32(struct net_buf_simple *buf)
{
    uint32_t val;

    val = UNALIGNED_GET((uint32_t *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_le32_to_cpu(val);
}

uint32_t net_buf_simple_pull_be32(struct net_buf_simple *buf)
{
    uint32_t val;

    val = UNALIGNED_GET((uint32_t *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_be32_to_cpu(val);
}

uint64_t net_buf_simple_pull_le48(struct net_buf_simple *buf)
{
    struct uint48
    {
        uint64_t u48 : 48;
    } __packed val;

    val = UNALIGNED_GET((struct uint48 *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_le48_to_cpu(val.u48);
}

uint64_t net_buf_simple_pull_be48(struct net_buf_simple *buf)
{
    struct uint48
    {
        uint64_t u48 : 48;
    } __packed val;

    val = UNALIGNED_GET((struct uint48 *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_be48_to_cpu(val.u48);
}

uint64_t net_buf_simple_pull_le64(struct net_buf_simple *buf)
{
    uint64_t val;

    val = UNALIGNED_GET((uint64_t *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_le64_to_cpu(val);
}

uint64_t net_buf_simple_pull_be64(struct net_buf_simple *buf)
{
    uint64_t val;

    val = UNALIGNED_GET((uint64_t *)buf->data);
    net_buf_simple_pull(buf, sizeof(val));

    return sys_be64_to_cpu(val);
}

size_t net_buf_simple_headroom(struct net_buf_simple *buf)
{
    return buf->data - buf->__buf;
}

size_t net_buf_simple_tailroom(struct net_buf_simple *buf)
{
    return buf->size - net_buf_simple_headroom(buf) - buf->len;
}

bool net_buf_check_empty(struct spool *pool)
{
    // uint64_t end = 1; // z_timeout_end_calc(timeout);
    // struct net_buf *buf;

    __ASSERT_NO_MSG(pool);

    return spool_size(pool);
}
