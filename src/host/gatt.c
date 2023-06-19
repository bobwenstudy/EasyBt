/* gatt.c - Generic Attribute Profile handling */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>

#include "easybt_config.h"
#include "gatt_internal.h"

// #include "base/atomic.h"
#include "base/byteorder.h"
#include "base/common.h"

#include "utils/bt_storage_kv.h"
// #include "utils/bt_settings.h"
// #include "settings.h"

#include <bluetooth/hci.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <drivers/hci_driver.h>

#define LOG_MODULE_NAME bt_gatt
#include "logging/bt_log.h"

#include "hci_core.h"
// #include "conn.h"
// #include "keys.h"
#include "l2cap.h"
#include "att_internal.h"
// #include "smp.h"

#if defined(CONFIG_BT_CONN)
#define SC_TIMEOUT      K_MSEC(10)
#define DB_HASH_TIMEOUT K_MSEC(10)

static uint16_t last_static_handle;

static uint16_t gatt_static_service_valid_cnt;

/* Persistent storage format for GATT CCC */
struct ccc_store
{
    uint16_t handle;
    uint16_t value;
};

struct gatt_sub
{
    uint8_t id;
    bt_addr_le_t peer;
    sys_slist_t list;
};

#if defined(CONFIG_BT_GATT_CLIENT)
#define SUB_MAX (CONFIG_BT_MAX_PAIRED + CONFIG_BT_MAX_CONN)
#else
#define SUB_MAX 0
#endif /* CONFIG_BT_GATT_CLIENT */

static struct bt_gatt_cb* gatt_callback;

struct bt_gatt_service_static** _bt_gatt_service_static;



#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
static uint8_t found_attr(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    const struct bt_gatt_attr **found = user_data;

    *found = attr;

    return BT_GATT_ITER_STOP;
}

static const struct bt_gatt_attr *find_attr(uint16_t handle)
{
    const struct bt_gatt_attr *attr = NULL;

    bt_gatt_foreach_attr(handle, handle, found_attr, &attr);

    return attr;
}

static void gatt_insert(struct bt_gatt_service *svc, uint16_t last_handle)
{
    struct bt_gatt_service *tmp, *prev = NULL;

    if (last_handle == 0 || svc->attrs[0].handle > last_handle)
    {
        sys_slist_append(&db, &svc->node);
        return;
    }

    /* DB shall always have its service in ascending order */
    SYS_SLIST_FOR_EACH_CONTAINER (&db, tmp, node)
    {
        if (tmp->attrs[0].handle > svc->attrs[0].handle)
        {
            if (prev)
            {
                sys_slist_insert(&db, &prev->node, &svc->node);
            }
            else
            {
                sys_slist_prepend(&db, &svc->node);
            }
            return;
        }

        prev = tmp;
    }
}

static int gatt_register(struct bt_gatt_service *svc)
{
    struct bt_gatt_service *last;
    uint16_t handle, last_handle;
    struct bt_gatt_attr *attrs = svc->attrs;
    uint16_t count = svc->attr_count;

    if (sys_slist_is_empty(&db))
    {
        handle = last_static_handle;
        last_handle = 0;
        goto populate;
    }

    last = SYS_SLIST_PEEK_TAIL_CONTAINER(&db, last, node);
    handle = last->attrs[last->attr_count - 1].handle;
    last_handle = handle;

populate:
    /* Populate the handles and append them to the list */
    for (; attrs && count; attrs++, count--)
    {
        if (!attrs->handle)
        {
            /* Allocate handle if not set already */
            attrs->handle = ++handle;
        }
        else if (attrs->handle > handle)
        {
            /* Use existing handle if valid */
            handle = attrs->handle;
        }
        else if (find_attr(attrs->handle))
        {
            /* Service has conflicting handles */
            LOG_ERR("Unable to register handle 0x%04x", attrs->handle);
            return -EINVAL;
        }

        LOG_DBG("attr %p handle 0x%04x uuid %s perm 0x%02x", attrs, attrs->handle,
                bt_uuid_str(attrs->uuid), attrs->perm);
    }

    gatt_insert(svc, last_handle);

    return 0;
}
#endif /* CONFIG_BT_GATT_DYNAMIC_DB */


static void clear_ccc_cfg(struct bt_gatt_ccc_cfg *cfg)
{
    bt_addr_le_copy(&cfg->peer, BT_ADDR_LE_ANY);
    cfg->value = 0U;
}

void bt_gatt_init(void)
{
    gatt_callback = NULL;
}

int bt_gatt_service_init(int n, const struct bt_gatt_service_static** service_list)
{
    last_static_handle = 0;
    for (int i = 0; i < n; i++)
    {
        struct bt_gatt_service_static* data = service_list[i];
        last_static_handle += data->attr_count;
    }
    _bt_gatt_service_static = service_list;
    gatt_static_service_valid_cnt = n;

    LOG_DBG("last_static_handle %d gatt_static_service_valid_cnt %d", last_static_handle, gatt_static_service_valid_cnt);
    return 0;
}


void bt_gatt_cb_register(struct bt_gatt_cb *cb)
{
    gatt_callback = cb;
}

#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
static void db_changed(void)
{
#if defined(CONFIG_BT_GATT_CACHING)
    struct bt_conn *conn;
    int i;

    atomic_clear_bit(gatt_sc.flags, DB_HASH_VALID);

    if (IS_ENABLED(CONFIG_BT_LONG_WQ))
    {
        bt_long_wq_reschedule(&db_hash.work, DB_HASH_TIMEOUT);
    }
    else
    {
        k_work_reschedule(&db_hash.work, DB_HASH_TIMEOUT);
    }

    for (i = 0; i < ARRAY_SIZE(cf_cfg); i++)
    {
        struct gatt_cf_cfg *cfg = &cf_cfg[i];

        if (bt_addr_le_eq(&cfg->peer, BT_ADDR_LE_ANY))
        {
            continue;
        }

        // if (CF_ROBUST_CACHING(cfg))
        // {
        //     /* Core Spec 5.1 | Vol 3, Part G, 2.5.2.1 Robust Caching
        //      *... the database changes again before the client
        //      * becomes change-aware in which case the error response
        //      * shall be sent again.
        //      */
        //     conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, &cfg->peer);
        //     if (conn)
        //     {
        //         bt_att_clear_out_of_sync_sent(conn);
        //         // bt_conn_unref(conn);
        //     }

        //     atomic_clear_bit(cfg->flags, CF_DB_HASH_READ);
        //     set_change_aware(cfg, false);
        // }
    }
#endif
}

static void gatt_unregister_ccc(struct _bt_gatt_ccc *ccc)
{
    ccc->value = 0;

    for (size_t i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        struct bt_gatt_ccc_cfg *cfg = &ccc->cfg[i];

        if (!bt_addr_le_eq(&cfg->peer, BT_ADDR_LE_ANY))
        {
            struct bt_conn *conn;
            bool store = true;

            conn = bt_conn_lookup_addr_le(&cfg->peer);
            if (conn)
            {
                if (conn->state == BT_CONN_CONNECTED)
                {
#if defined(CONFIG_BT_SETTINGS_CCC_STORE_ON_WRITE)
                    gatt_delayed_store_enqueue(conn->id, &conn->le.dst, DELAYED_STORE_CCC);
#endif
                    store = false;
                }

                // bt_conn_unref(conn);
            }

            if (IS_ENABLED(CONFIG_BT_SETTINGS) && store &&
                bt_addr_le_is_bonded(cfg->id, &cfg->peer))
            {
                bt_gatt_store_ccc(cfg->id, &cfg->peer);
            }

            clear_ccc_cfg(cfg);
        }
    }
}

static int gatt_unregister(struct bt_gatt_service *svc)
{
    if (!sys_slist_find_and_remove(&db, &svc->node))
    {
        return -ENOENT;
    }

    for (uint16_t i = 0; i < svc->attr_count; i++)
    {
        struct bt_gatt_attr *attr = &svc->attrs[i];

        if (attr->write == bt_gatt_attr_write_ccc)
        {
            gatt_unregister_ccc(attr->user_data);
        }
    }

    return 0;
}

int bt_gatt_service_register(struct bt_gatt_service *svc)
{
    int err;

    __ASSERT(svc, "invalid parameters\n");
    __ASSERT(svc->attrs, "invalid parameters\n");
    __ASSERT(svc->attr_count, "invalid parameters\n");

    /* Init GATT core services */
    // bt_gatt_service_init();

    /* Do no allow to register mandatory services twice */
    if (!bt_uuid_cmp(svc->attrs[0].uuid, BT_UUID_GAP) ||
        !bt_uuid_cmp(svc->attrs[0].uuid, BT_UUID_GATT))
    {
        return -EALREADY;
    }

    // k_sched_lock();

    err = gatt_register(svc);
    if (err < 0)
    {
        // k_sched_unlock();
        return err;
    }

    /* Don't submit any work until the stack is initialized */
    if (!atomic_get(&init))
    {
        // k_sched_unlock();
        return 0;
    }

    sc_indicate(svc->attrs[0].handle, svc->attrs[svc->attr_count - 1].handle);

    db_changed();

    // k_sched_unlock();

    return 0;
}

int bt_gatt_service_unregister(struct bt_gatt_service *svc)
{
    int err;

    __ASSERT(svc, "invalid parameters\n");

    // k_sched_lock();

    err = gatt_unregister(svc);
    if (err)
    {
        // k_sched_unlock();
        return err;
    }

    /* Don't submit any work until the stack is initialized */
    if (!atomic_get(&init))
    {
        // k_sched_unlock();
        return 0;
    }

    sc_indicate(svc->attrs[0].handle, svc->attrs[svc->attr_count - 1].handle);

    db_changed();

    // k_sched_unlock();

    return 0;
}

bool bt_gatt_service_is_registered(const struct bt_gatt_service *svc)
{
    bool registered = false;
    sys_snode_t *node;

    // k_sched_lock();
    SYS_SLIST_FOR_EACH_NODE (&db, node)
    {
        if (&svc->node == node)
        {
            registered = true;
            break;
        }
    }

    // k_sched_unlock();

    return registered;
}
#endif /* CONFIG_BT_GATT_DYNAMIC_DB */

ssize_t bt_gatt_attr_read(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                          uint16_t buf_len, uint16_t offset, const void *value, uint16_t value_len)
{
    uint16_t len;

    if (offset > value_len)
    {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    len = MIN(buf_len, value_len - offset);

    LOG_DBG("handle 0x%04x offset %u length %u", attr->handle, offset, len);

    memcpy(buf, (uint8_t *)value + offset, len);

    return len;
}

ssize_t bt_gatt_attr_read_service(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                                  uint16_t len, uint16_t offset)
{
    struct bt_uuid *uuid = attr->user_data;

    if (uuid->type == BT_UUID_TYPE_16)
    {
        uint16_t uuid16 = sys_cpu_to_le16(BT_UUID_16(uuid)->val);

        return bt_gatt_attr_read(conn, attr, buf, len, offset, &uuid16, 2);
    }

    return bt_gatt_attr_read(conn, attr, buf, len, offset, BT_UUID_128(uuid)->val, 16);
}

struct gatt_incl
{
    uint16_t start_handle;
    uint16_t end_handle;
    uint16_t uuid16;
} __packed;

static uint8_t get_service_handles(const struct bt_gatt_attr *attr, uint16_t handle,
                                   void *user_data)
{
    struct gatt_incl *include = user_data;

    /* Stop if attribute is a service */
    if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_PRIMARY) ||
        !bt_uuid_cmp(attr->uuid, BT_UUID_GATT_SECONDARY))
    {
        return BT_GATT_ITER_STOP;
    }

    include->end_handle = sys_cpu_to_le16(handle);

    return BT_GATT_ITER_CONTINUE;
}

uint16_t bt_gatt_attr_get_handle(const struct bt_gatt_attr *attr)
{
    uint16_t handle = 1;

    if (!attr)
    {
        return 0;
    }

    if (attr->handle)
    {
        return attr->handle;
    }

    for (int index = 0; index < gatt_static_service_valid_cnt; index++)
    {
        struct bt_gatt_service_static *static_svc = _bt_gatt_service_static[index];
        /* Skip ahead if start is not within service attributes array */
        if ((attr < &static_svc->attrs[0]) ||
            (attr > &static_svc->attrs[static_svc->attr_count - 1]))
        {
            handle += static_svc->attr_count;
            continue;
        }

        for (size_t i = 0; i < static_svc->attr_count; i++, handle++)
        {
            if (attr == &static_svc->attrs[i])
            {
                return handle;
            }
        }
    }

    return 0;
}

ssize_t bt_gatt_attr_read_included(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                                   uint16_t len, uint16_t offset)
{
    struct bt_gatt_attr *incl = attr->user_data;
    uint16_t handle = bt_gatt_attr_get_handle(incl);
    struct bt_uuid *uuid = incl->user_data;
    struct gatt_incl pdu;
    uint8_t value_len;

    /* first attr points to the start handle */
    pdu.start_handle = sys_cpu_to_le16(handle);
    value_len = sizeof(pdu.start_handle) + sizeof(pdu.end_handle);

    /*
     * Core 4.2, Vol 3, Part G, 3.2,
     * The Service UUID shall only be present when the UUID is a
     * 16-bit Bluetooth UUID.
     */
    if (uuid->type == BT_UUID_TYPE_16)
    {
        pdu.uuid16 = sys_cpu_to_le16(BT_UUID_16(uuid)->val);
        value_len += sizeof(pdu.uuid16);
    }

    /* Lookup for service end handle */
    bt_gatt_foreach_attr(handle + 1, 0xffff, get_service_handles, &pdu);

    return bt_gatt_attr_read(conn, attr, buf, len, offset, &pdu, value_len);
}

struct gatt_chrc
{
    uint8_t properties;
    uint16_t value_handle;
    union
    {
        uint16_t uuid16;
        uint8_t uuid[16];
    };
} __packed;

uint16_t bt_gatt_attr_value_handle(const struct bt_gatt_attr *attr)
{
    uint16_t handle = 0;

    if (attr != NULL && bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CHRC) == 0)
    {
        struct bt_gatt_chrc *chrc = attr->user_data;

        handle = chrc->value_handle;
        if (handle == 0)
        {
            /* Fall back to Zephyr value handle policy */
            handle = bt_gatt_attr_get_handle(attr) + 1U;
        }
    }

    return handle;
}

ssize_t bt_gatt_attr_read_chrc(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                               uint16_t len, uint16_t offset)
{
    struct bt_gatt_chrc *chrc = attr->user_data;
    struct gatt_chrc pdu;
    uint8_t value_len;

    pdu.properties = chrc->properties;
    /* BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part G] page 534:
     * 3.3.2 Characteristic Value Declaration
     * The Characteristic Value declaration contains the value of the
     * characteristic. It is the first Attribute after the characteristic
     * declaration. All characteristic definitions shall have a
     * Characteristic Value declaration.
     */
    pdu.value_handle = sys_cpu_to_le16(bt_gatt_attr_value_handle(attr));

    value_len = sizeof(pdu.properties) + sizeof(pdu.value_handle);

    if (chrc->uuid->type == BT_UUID_TYPE_16)
    {
        pdu.uuid16 = sys_cpu_to_le16(BT_UUID_16(chrc->uuid)->val);
        value_len += 2U;
    }
    else
    {
        memcpy(pdu.uuid, BT_UUID_128(chrc->uuid)->val, 16);
        value_len += 16U;
    }

    return bt_gatt_attr_read(conn, attr, buf, len, offset, &pdu, value_len);
}

static uint8_t gatt_foreach_iter(const struct bt_gatt_attr *attr, uint16_t handle,
                                 uint16_t start_handle, uint16_t end_handle,
                                 const struct bt_uuid *uuid, const void *attr_data,
                                 uint16_t *num_matches, bt_gatt_attr_func_t func, void *user_data)
{
    uint8_t result;

    /* Stop if over the requested range */
    if (handle > end_handle)
    {
        return BT_GATT_ITER_STOP;
    }

    /* Check if attribute handle is within range */
    if (handle < start_handle)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    /* Match attribute UUID if set */
    if (uuid && bt_uuid_cmp(uuid, attr->uuid))
    {
        return BT_GATT_ITER_CONTINUE;
    }

    /* Match attribute user_data if set */
    if (attr_data && attr_data != attr->user_data)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    *num_matches -= 1;

    result = func(attr, handle, user_data);

    if (!*num_matches)
    {
        return BT_GATT_ITER_STOP;
    }

    return result;
}

static void foreach_attr_type_dyndb(uint16_t start_handle, uint16_t end_handle,
                                    const struct bt_uuid *uuid, const void *attr_data,
                                    uint16_t num_matches, bt_gatt_attr_func_t func, void *user_data)
{
#if defined(CONFIG_BT_GATT_DYNAMIC_DB)
    size_t i;
    struct bt_gatt_service *svc;

    SYS_SLIST_FOR_EACH_CONTAINER (&db, svc, node)
    {
        struct bt_gatt_service *next;

        next = SYS_SLIST_PEEK_NEXT_CONTAINER(svc, node);
        if (next)
        {
            /* Skip ahead if start is not within service handles */
            if (next->attrs[0].handle <= start_handle)
            {
                continue;
            }
        }

        for (i = 0; i < svc->attr_count; i++)
        {
            struct bt_gatt_attr *attr = &svc->attrs[i];

            if (gatt_foreach_iter(attr, attr->handle, start_handle, end_handle, uuid, attr_data,
                                  &num_matches, func, user_data) == BT_GATT_ITER_STOP)
            {
                return;
            }
        }
    }
#endif /* CONFIG_BT_GATT_DYNAMIC_DB */
}

void bt_gatt_foreach_attr_type(uint16_t start_handle, uint16_t end_handle,
                               const struct bt_uuid *uuid, const void *attr_data,
                               uint16_t num_matches, bt_gatt_attr_func_t func, void *user_data)
{
    size_t i;

    if (!num_matches)
    {
        num_matches = UINT16_MAX;
    }

    LOG_DBG("last_static_handle %d gatt_static_service_valid_cnt %d", last_static_handle, gatt_static_service_valid_cnt);
    if (start_handle <= last_static_handle)
    {
        uint16_t handle = 1;

        for (int index = 0; index < gatt_static_service_valid_cnt; index++)
        {
            struct bt_gatt_service_static *static_svc = _bt_gatt_service_static[index];
            LOG_DBG("index %d start_handle %d handle %d static_svc->attr_count %d", index, start_handle, handle, static_svc->attr_count);
            /* Skip ahead if start is not within service handles */
            if (handle + static_svc->attr_count < start_handle)
            {
                handle += static_svc->attr_count;
                continue;
            }

            for (i = 0; i < static_svc->attr_count; i++, handle++)
            {
                if (gatt_foreach_iter(&static_svc->attrs[i], handle, start_handle, end_handle, uuid,
                                        attr_data, &num_matches, func,
                                        user_data) == BT_GATT_ITER_STOP)
                {
                    return;
                }
            }
        }
    }
    /* Iterate over dynamic db */
    foreach_attr_type_dyndb(start_handle, end_handle, uuid, attr_data, num_matches, func,
                            user_data);
}

static uint8_t find_next(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct bt_gatt_attr **next = user_data;

    *next = (struct bt_gatt_attr *)attr;

    return BT_GATT_ITER_STOP;
}

struct bt_gatt_attr *bt_gatt_attr_next(const struct bt_gatt_attr *attr)
{
    struct bt_gatt_attr *next = NULL;
    uint16_t handle = bt_gatt_attr_get_handle(attr);

    bt_gatt_foreach_attr(handle + 1, handle + 1, find_next, &next);

    return next;
}

static struct bt_gatt_ccc_cfg *find_ccc_cfg(const struct bt_conn *conn, struct _bt_gatt_ccc *ccc)
{
    for (size_t i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        struct bt_gatt_ccc_cfg *cfg = &ccc->cfg[i];

        if (conn)
        {
            if (bt_conn_is_peer_addr_le(conn, &cfg->peer))
            {
                return cfg;
            }
        }
        else if (bt_addr_le_eq(&cfg->peer, BT_ADDR_LE_ANY))
        {
            return cfg;
        }
    }

    return NULL;
}

ssize_t bt_gatt_attr_read_ccc(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                              uint16_t len, uint16_t offset)
{
    struct _bt_gatt_ccc *ccc = attr->user_data;
    const struct bt_gatt_ccc_cfg *cfg;
    uint16_t value;

    cfg = find_ccc_cfg(conn, ccc);
    if (cfg)
    {
        value = sys_cpu_to_le16(cfg->value);
    }
    else
    {
        /* Default to disable if there is no cfg for the peer */
        value = 0x0000;
    }

    return bt_gatt_attr_read(conn, attr, buf, len, offset, &value, sizeof(value));
}

static void gatt_ccc_changed(const struct bt_gatt_attr *attr, struct _bt_gatt_ccc *ccc)
{
    int i;
    uint16_t value = 0x0000;

    for (i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        if (ccc->cfg[i].value > value)
        {
            value = ccc->cfg[i].value;
        }
    }

    LOG_DBG("ccc %p value 0x%04x", ccc, value);

    if (value != ccc->value)
    {
        ccc->value = value;
        if (ccc->cfg_changed)
        {
            ccc->cfg_changed(attr, value);
        }
    }
}

ssize_t bt_gatt_attr_write_ccc(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                               const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
    struct _bt_gatt_ccc *ccc = attr->user_data;
    struct bt_gatt_ccc_cfg *cfg;
    bool value_changed;
    uint16_t value;

    if (offset)
    {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    if (!len || len > sizeof(uint16_t))
    {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);
    }

    if (len < sizeof(uint16_t))
    {
        value = *(uint8_t *)buf;
    }
    else
    {
        value = sys_get_le16(buf);
    }

    cfg = find_ccc_cfg(conn, ccc);
    if (!cfg)
    {
        /* If there's no existing entry, but the new value is zero,
         * we don't need to do anything, since a disabled CCC is
         * behaviorally the same as no written CCC.
         */
        if (!value)
        {
            return len;
        }

        cfg = find_ccc_cfg(NULL, ccc);
        if (!cfg)
        {
            LOG_WRN("No space to store CCC cfg");
            return BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES);
        }

        bt_addr_le_copy(&cfg->peer, &conn->le.dst);
    }

    /* Confirm write if cfg is managed by application */
    if (ccc->cfg_write)
    {
        ssize_t write = ccc->cfg_write(conn, attr, value);

        if (write < 0)
        {
            return write;
        }

        /* Accept size=1 for backwards compatibility */
        if (write != sizeof(value) && write != 1)
        {
            return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
        }
    }

    value_changed = cfg->value != value;
    cfg->value = value;

    LOG_DBG("handle 0x%04x value %u", attr->handle, cfg->value);

    /* Update cfg if don't match */
    if (cfg->value != ccc->value)
    {
        gatt_ccc_changed(attr, ccc);
    }

    if (value_changed)
    {
#if defined(CONFIG_BT_SETTINGS_CCC_STORE_ON_WRITE)
        /* Enqueue CCC store if value has changed for the connection */
        gatt_delayed_store_enqueue(conn->id, &conn->le.dst, DELAYED_STORE_CCC);
#endif
    }

    /* Disabled CCC is the same as no configured CCC, so clear the entry */
    if (!value)
    {
        clear_ccc_cfg(cfg);
    }

    return len;
}

ssize_t bt_gatt_attr_read_cep(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                              uint16_t len, uint16_t offset)
{
    const struct bt_gatt_cep *value = attr->user_data;
    uint16_t props = sys_cpu_to_le16(value->properties);

    return bt_gatt_attr_read(conn, attr, buf, len, offset, &props, sizeof(props));
}

ssize_t bt_gatt_attr_read_cud(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                              uint16_t len, uint16_t offset)
{
    const char *value = attr->user_data;

    return bt_gatt_attr_read(conn, attr, buf, len, offset, value, strlen(value));
}

struct gatt_cpf
{
    uint8_t format;
    int8_t exponent;
    uint16_t unit;
    uint8_t name_space;
    uint16_t description;
} __packed;

ssize_t bt_gatt_attr_read_cpf(struct bt_conn *conn, const struct bt_gatt_attr *attr, void *buf,
                              uint16_t len, uint16_t offset)
{
    const struct bt_gatt_cpf *cpf = attr->user_data;
    struct gatt_cpf value;

    value.format = cpf->format;
    value.exponent = cpf->exponent;
    value.unit = sys_cpu_to_le16(cpf->unit);
    value.name_space = cpf->name_space;
    value.description = sys_cpu_to_le16(cpf->description);

    return bt_gatt_attr_read(conn, attr, buf, len, offset, &value, sizeof(value));
}

struct notify_data
{
    const struct bt_gatt_attr *attr;
    uint16_t handle;
    int err;
    uint16_t type;
    union
    {
        struct bt_gatt_notify_params *nfy_params;
        struct bt_gatt_indicate_params *ind_params;
    };
};

static int gatt_notify(struct bt_conn *conn, uint16_t handle, struct bt_gatt_notify_params *params)
{
    struct net_buf *buf;
    struct bt_att_notify *nfy;

    LOG_DBG("4\r\n");
    /* Confirm that the connection has the correct level of security */
    if (bt_gatt_check_perm(conn, params->attr, BT_GATT_PERM_READ_ENCRYPT_MASK))
    {
        LOG_WRN("Link is not encrypted");
        return -EPERM;
    }

#if defined(CONFIG_BT_GATT_ENFORCE_SUBSCRIPTION)
    /* Check if client has subscribed before sending notifications.
        * This is not really required in the Bluetooth specification,
        * but follows its spirit.
        */
    if (!bt_gatt_is_subscribed(conn, params->attr, BT_GATT_CCC_NOTIFY))
    {
        LOG_WRN("Device is not subscribed to characteristic");
        return -EINVAL;
    }
#endif

#if defined(CONFIG_BT_GATT_NOTIFY_MULTIPLE) && (CONFIG_BT_GATT_NOTIFY_MULTIPLE_FLUSH_MS != 0)
    if (gatt_cf_notify_multi(conn))
    {
        return gatt_notify_mult(conn, handle, params);
    }
#endif /* CONFIG_BT_GATT_NOTIFY_MULTIPLE */

    buf = bt_att_create_pdu(BT_ATT_OP_NOTIFY, sizeof(*nfy) + params->len);
    if (!buf)
    {
        LOG_WRN("No buffer available to send notification");
        return -ENOMEM;
    }

    LOG_DBG("conn %p handle 0x%04x", conn, handle);

    nfy = net_buf_add(buf, sizeof(*nfy));
    nfy->handle = sys_cpu_to_le16(handle);

    net_buf_add(buf, params->len);
    memcpy(nfy->value, params->data, params->len);

    // bt_att_set_tx_meta_data(buf, params->func, params->user_data, BT_ATT_CHAN_OPT(params));
    return bt_att_send(conn, buf);
}

static void gatt_indicate_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                              void *user_data)
{
    struct bt_gatt_indicate_params *params = user_data;

    if (params->func)
    {
        params->func(conn, params, err);
    }

    params->_ref--;
    if (params->destroy && (params->_ref == 0))
    {
        params->destroy(params);
    }
}

static struct bt_att_req *gatt_req_alloc(bt_att_func_t func, void *params, bt_att_encode_t encode,
                                         uint8_t op, size_t len)
{
    struct bt_att_req *req;

    /* Allocate new request */
    req = bt_att_req_alloc();
    if (!req)
    {
        return NULL;
    }

#if defined(CONFIG_BT_SMP)
    req->att_op = op;
    req->len = len;
    req->encode = encode;
#endif
    req->func = func;
    req->user_data = params;

    return req;
}

#ifdef CONFIG_BT_GATT_CLIENT
static int gatt_req_send(struct bt_conn *conn, bt_att_func_t func, void *params,
                         bt_att_encode_t encode, uint8_t op, size_t len,
                         enum bt_att_chan_opt chan_opt)

{
    struct bt_att_req *req;
    struct net_buf *buf;
    int err;

    req = gatt_req_alloc(func, params, encode, op, len);
    if (!req)
    {
        return -ENOMEM;
    }

    buf = bt_att_create_pdu(conn, op, len);
    if (!buf)
    {
        bt_att_req_free(req);
        return -ENOMEM;
    }

    // bt_att_set_tx_meta_data(buf, NULL, NULL, chan_opt);

    req->buf = buf;

    err = encode(buf, len, params);
    if (err)
    {
        bt_att_req_free(req);
        return err;
    }

    err = bt_att_req_send(conn, req);
    if (err)
    {
        bt_att_req_free(req);
    }

    return err;
}
#endif

static int gatt_indicate(struct bt_conn *conn, uint16_t handle,
                         struct bt_gatt_indicate_params *params)
{
    struct net_buf *buf;
    struct bt_att_indicate *ind;
    struct bt_att_req *req;
    size_t len;
    int err;

#if defined(CONFIG_BT_GATT_ENFORCE_CHANGE_UNAWARE)
    /* BLUETOOTH CORE SPECIFICATION Version 5.1 | Vol 3, Part G page 2350:
     * Except for the Handle Value indication, the  server shall not send
     * notifications and indications to such a client until it becomes
     * change-aware.
     */
    if (!(params->func && (params->func == sc_indicate_rsp || params->func == sc_restore_rsp)) &&
        !bt_gatt_change_aware(conn, false))
    {
        return -EAGAIN;
    }
#endif

    /* Confirm that the connection has the correct level of security */
    if (bt_gatt_check_perm(conn, params->attr, BT_GATT_PERM_READ_ENCRYPT_MASK))
    {
        LOG_WRN("Link is not encrypted");
        return -EPERM;
    }

#if defined(CONFIG_BT_GATT_ENFORCE_SUBSCRIPTION)
    /* Check if client has subscribed before sending notifications.
        * This is not really required in the Bluetooth specification,
        * but follows its spirit.
        */
    if (!bt_gatt_is_subscribed(conn, params->attr, BT_GATT_CCC_INDICATE))
    {
        LOG_WRN("Device is not subscribed to characteristic");
        return -EINVAL;
    }
#endif

    len = sizeof(*ind) + params->len;

    req = gatt_req_alloc(gatt_indicate_rsp, params, NULL, BT_ATT_OP_INDICATE, len);
    if (!req)
    {
        return -ENOMEM;
    }

    buf = bt_att_create_pdu(BT_ATT_OP_INDICATE, len);
    if (!buf)
    {
        LOG_WRN("No buffer available to send indication");
        bt_att_req_free(req);
        return -ENOMEM;
    }

    // bt_att_set_tx_meta_data(buf, NULL, NULL, BT_ATT_CHAN_OPT(params));

    ind = net_buf_add(buf, sizeof(*ind));
    ind->handle = sys_cpu_to_le16(handle);

    net_buf_add(buf, params->len);
    memcpy(ind->value, params->data, params->len);

    LOG_DBG("conn %p handle 0x%04x", conn, handle);

    req->buf = buf;

    err = bt_att_req_send(conn, req);
    if (err)
    {
        bt_att_req_free(req);
    }

    return err;
}

static uint8_t notify_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct notify_data *data = user_data;
    struct _bt_gatt_ccc *ccc;
    size_t i;

    LOG_DBG("10\r\n");
    /* Check attribute user_data must be of type struct _bt_gatt_ccc */
    if (attr->write != bt_gatt_attr_write_ccc)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    ccc = attr->user_data;

    /* Notify all peers configured */
    for (i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        struct bt_gatt_ccc_cfg *cfg = &ccc->cfg[i];
        struct bt_conn *conn;
        int err;

        /* Check if config value matches data type since consolidated
         * value may be for a different peer.
         */
        if (cfg->value != data->type)
        {
            continue;
        }

    LOG_DBG("11\r\n");
        conn = bt_conn_lookup_addr_le(&cfg->peer);
        if (!conn)
        {
            continue;
        }

    LOG_DBG("12\r\n");
        if (conn->state != BT_CONN_CONNECTED)
        {
            // bt_conn_unref(conn);
            continue;
        }

        /* Confirm match if cfg is managed by application */
        if (ccc->cfg_match && !ccc->cfg_match(conn, attr))
        {
            // bt_conn_unref(conn);
            continue;
        }

        /* Confirm that the connection has the correct level of security */
        if (bt_gatt_check_perm(conn, attr, BT_GATT_PERM_READ_ENCRYPT_MASK))
        {
            LOG_WRN("Link is not encrypted");
            // bt_conn_unref(conn);
            continue;
        }

    LOG_DBG("13\r\n");
        /* Use the Characteristic Value handle discovered since the
         * Client Characteristic Configuration descriptor may occur
         * in any position within the characteristic definition after
         * the Characteristic Value.
         * Only notify or indicate devices which are subscribed.
         */
        if ((data->type == BT_GATT_CCC_INDICATE) && (cfg->value & BT_GATT_CCC_INDICATE))
        {
            err = gatt_indicate(conn, data->handle, data->ind_params);
            if (err == 0)
            {
                data->ind_params->_ref++;
            }
        }
        else if ((data->type == BT_GATT_CCC_NOTIFY) && (cfg->value & BT_GATT_CCC_NOTIFY))
        {
            err = gatt_notify(conn, data->handle, data->nfy_params);
        }
        else
        {
            err = 0;
        }

        // bt_conn_unref(conn);

        if (err < 0)
        {
            return BT_GATT_ITER_STOP;
        }

        data->err = 0;
    }

    return BT_GATT_ITER_CONTINUE;
}

static uint8_t match_uuid(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct notify_data *data = user_data;

    data->attr = attr;
    data->handle = handle;

    return BT_GATT_ITER_STOP;
}

static bool gatt_find_by_uuid(struct notify_data *found, const struct bt_uuid *uuid)
{
    found->attr = NULL;

    bt_gatt_foreach_attr_type(found->handle, 0xffff, uuid, NULL, 1, match_uuid, found);

    return found->attr ? true : false;
}

struct bt_gatt_attr *bt_gatt_find_by_uuid(const struct bt_gatt_attr *attr, uint16_t attr_count,
                                          const struct bt_uuid *uuid)
{
    struct bt_gatt_attr *found = NULL;
    uint16_t start_handle = bt_gatt_attr_value_handle(attr);
    uint16_t end_handle = start_handle && attr_count ? start_handle + attr_count : 0xffff;

    bt_gatt_foreach_attr_type(start_handle, end_handle, uuid, NULL, 1, find_next, &found);

    return found;
}

int bt_gatt_notify_cb(struct bt_conn *conn, struct bt_gatt_notify_params *params)
{
    struct notify_data data;

    __ASSERT(params, "invalid parameters\n");
    __ASSERT(params->attr || params->uuid, "invalid parameters\n");

    // if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY))
    // {
    //     return -EAGAIN;
    // }
    if (conn && conn->state != BT_CONN_CONNECTED)
    {
        LOG_DBG("state: %d\r\n", conn->state);
        return -ENOTCONN;
    }

    data.attr = params->attr;
    data.handle = bt_gatt_attr_get_handle(data.attr);

    LOG_DBG("uuid: %x\r\n", params->uuid);
    /* Lookup UUID if it was given */
    if (params->uuid)
    {
        if (!gatt_find_by_uuid(&data, params->uuid))
        {
            return -ENOENT;
        }

        params->attr = data.attr;
    }
    else
    {
        if (!data.handle)
        {
            return -ENOENT;
        }
    }
    LOG_DBG("1\r\n");

    /* Check if attribute is a characteristic then adjust the handle */
    if (!bt_uuid_cmp(data.attr->uuid, BT_UUID_GATT_CHRC))
    {
        struct bt_gatt_chrc *chrc = data.attr->user_data;

        if (!(chrc->properties & BT_GATT_CHRC_NOTIFY))
        {
            return -EINVAL;
        }

        data.handle = bt_gatt_attr_value_handle(data.attr);
    }

    LOG_DBG("2\r\n");
    if (conn)
    {
        return gatt_notify(conn, data.handle, params);
    }

    data.err = -ENOTCONN;
    data.type = BT_GATT_CCC_NOTIFY;
    data.nfy_params = params;

    bt_gatt_foreach_attr_type(data.handle, 0xffff, BT_UUID_GATT_CCC, NULL, 1, notify_cb, &data);

    return data.err;
}

#if defined(CONFIG_BT_GATT_NOTIFY_MULTIPLE)
static int gatt_notify_multiple_verify_args(struct bt_conn *conn,
                                            struct bt_gatt_notify_params params[],
                                            uint16_t num_params)
{
    __ASSERT(params, "invalid parameters\n");
    __ASSERT(params->attr, "invalid parameters\n");

    CHECKIF(num_params < 2)
    {
        /* Use the standard notification API when sending only one
         * notification.
         */
        return -EINVAL;
    }

    CHECKIF(conn == NULL)
    {
        /* Use the standard notification API to send to all connected
         * peers.
         */
        return -EINVAL;
    }

    if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY))
    {
        return -EAGAIN;
    }

    if (conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

#if defined(CONFIG_BT_GATT_ENFORCE_CHANGE_UNAWARE)
    /* BLUETOOTH CORE SPECIFICATION Version 5.3
     * Vol 3, Part G 2.5.3 (page 1479):
     *
     * Except for a Handle Value indication for the Service Changed
     * characteristic, the server shall not send notifications and
     * indications to such a client until it becomes change-aware.
     */
    if (!bt_gatt_change_aware(conn, false))
    {
        return -EAGAIN;
    }
#endif

    /* This API guarantees an ATT_MULTIPLE_HANDLE_VALUE_NTF over the air. */
    if (!gatt_cf_notify_multi(conn))
    {
        return -EOPNOTSUPP;
    }

    return 0;
}

static int gatt_notify_multiple_verify_params(struct bt_conn *conn,
                                              struct bt_gatt_notify_params params[],
                                              uint16_t num_params, size_t *total_len)
{
    for (uint16_t i = 0; i < num_params; i++)
    {
        /* Compute the total data length. */
        *total_len += params[i].len;

        /* Confirm that the connection has the correct level of security. */
        if (bt_gatt_check_perm(conn, params[i].attr,
                               BT_GATT_PERM_READ_ENCRYPT | BT_GATT_PERM_READ_AUTHEN))
        {
            LOG_WRN("Link is not encrypted");
            return -EPERM;
        }

        /* The current implementation requires the same callbacks and
         * user_data.
         */
        if ((params[0].func != params[i].func) || (params[0].user_data != params[i].user_data))
        {
            return -EINVAL;
        }

        /* This API doesn't support passing UUIDs. */
        if (params[i].uuid)
        {
            return -EINVAL;
        }

        /* Check if the supplied handle is invalid. */
        if (!bt_gatt_attr_get_handle(params[i].attr))
        {
            return -EINVAL;
        }

        /* Check if the characteristic is subscribed. */
        if (!bt_gatt_is_subscribed(conn, params[i].attr, BT_GATT_CCC_NOTIFY))
        {
            LOG_WRN("Device is not subscribed to characteristic");
            return -EINVAL;
        }
    }

    /* PDU length is specified with a 16-bit value. */
    if (*total_len > UINT16_MAX)
    {
        return -ERANGE;
    }

    /* Check there is a bearer with a high enough MTU. */
    if (bt_att_get_mtu(conn) < (sizeof(struct bt_att_notify_mult) + *total_len))
    {
        return -ERANGE;
    }

    return 0;
}

int bt_gatt_notify_multiple(struct bt_conn *conn, uint16_t num_params,
                            struct bt_gatt_notify_params params[])
{
    int err;
    size_t total_len = 0;
    struct net_buf *buf;

    /* Validate arguments, connection state and feature support. */
    err = gatt_notify_multiple_verify_args(conn, params, num_params);
    if (err)
    {
        return err;
    }

    /* Validate all the attributes that we want to notify.
     * Also gets us the total length of the PDU as a side-effect.
     */
    err = gatt_notify_multiple_verify_params(conn, params, num_params, &total_len);
    if (err)
    {
        return err;
    }

    /* Send any outstanding notifications.
     * Frees up buffer space for our PDU.
     */
    gatt_notify_flush(conn);

    /* Build the PDU */
    buf = bt_att_create_pdu(conn, BT_ATT_OP_NOTIFY_MULT,
                            sizeof(struct bt_att_notify_mult) + total_len);
    if (!buf)
    {
        return -ENOMEM;
    }

    /* Register the callback. It will be called num_params times. */
    // bt_att_set_tx_meta_data(buf, params->func, params->user_data, BT_ATT_CHAN_OPT(params));
    // bt_att_increment_tx_meta_data_attr_count(buf, num_params - 1);

    for (uint16_t i = 0; i < num_params; i++)
    {
        struct notify_data data;

        data.attr = params[i].attr;
        data.handle = bt_gatt_attr_get_handle(data.attr);

        /* Check if attribute is a characteristic then adjust the
         * handle
         */
        if (!bt_uuid_cmp(data.attr->uuid, BT_UUID_GATT_CHRC))
        {
            data.handle = bt_gatt_attr_value_handle(data.attr);
        }

        /* Add handle and data to the command buffer. */
        gatt_add_nfy_to_buf(buf, data.handle, &params[i]);
    }

    /* Send the buffer. */
    return gatt_notify_mult_send(conn, buf);
}
#endif /* CONFIG_BT_GATT_NOTIFY_MULTIPLE */

int bt_gatt_indicate(struct bt_conn *conn, struct bt_gatt_indicate_params *params)
{
    struct notify_data data;

    __ASSERT(params, "invalid parameters\n");
    __ASSERT(params->attr || params->uuid, "invalid parameters\n");

    // if (!atomic_test_bit(bt_dev.flags, BT_DEV_READY))
    // {
    //     return -EAGAIN;
    // }

    if (conn && conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

    data.attr = params->attr;
    data.handle = bt_gatt_attr_get_handle(data.attr);

    /* Lookup UUID if it was given */
    if (params->uuid)
    {
        if (!gatt_find_by_uuid(&data, params->uuid))
        {
            return -ENOENT;
        }

        params->attr = data.attr;
    }
    else
    {
        if (!data.handle)
        {
            return -ENOENT;
        }
    }

    /* Check if attribute is a characteristic then adjust the handle */
    if (!bt_uuid_cmp(data.attr->uuid, BT_UUID_GATT_CHRC))
    {
        struct bt_gatt_chrc *chrc = data.attr->user_data;

        if (!(chrc->properties & BT_GATT_CHRC_INDICATE))
        {
            return -EINVAL;
        }

        data.handle = bt_gatt_attr_value_handle(data.attr);
    }

    if (conn)
    {
        params->_ref = 1;
        return gatt_indicate(conn, data.handle, params);
    }

    data.err = -ENOTCONN;
    data.type = BT_GATT_CCC_INDICATE;
    data.ind_params = params;

    params->_ref = 0;
    bt_gatt_foreach_attr_type(data.handle, 0xffff, BT_UUID_GATT_CCC, NULL, 1, notify_cb, &data);

    return data.err;
}

uint16_t bt_gatt_get_mtu(struct bt_conn *conn)
{
    return bt_att_get_mtu(conn);
}

uint8_t bt_gatt_check_perm(struct bt_conn *conn, const struct bt_gatt_attr *attr, uint16_t mask)
{
    if ((mask & BT_GATT_PERM_READ) && (!(attr->perm & BT_GATT_PERM_READ_MASK) || !attr->read))
    {
        return BT_ATT_ERR_READ_NOT_PERMITTED;
    }

    if ((mask & BT_GATT_PERM_WRITE) && (!(attr->perm & BT_GATT_PERM_WRITE_MASK) || !attr->write))
    {
        return BT_ATT_ERR_WRITE_NOT_PERMITTED;
    }

#if 0
#if defined(CONFIG_BT_CONN_DISABLE_SECURITY)
    return 0;
#else
    mask &= attr->perm;

    if (mask & BT_GATT_PERM_LESC_MASK)
    {
        if (!IS_ENABLED(CONFIG_BT_SMP) || !conn->le.keys ||
            (conn->le.keys->flags & BT_KEYS_SC) == 0)
        {
            return BT_ATT_ERR_AUTHENTICATION;
        }
    }

    if (mask & BT_GATT_PERM_AUTHEN_MASK)
    {
        if (bt_conn_get_security(conn) < BT_SECURITY_L3)
        {
            return BT_ATT_ERR_AUTHENTICATION;
        }
    }

    if ((mask & BT_GATT_PERM_ENCRYPT_MASK))
    {
#if defined(CONFIG_BT_SMP)
        if (!conn->encrypt)
        {
            return BT_ATT_ERR_INSUFFICIENT_ENCRYPTION;
        }
#else
        return BT_ATT_ERR_INSUFFICIENT_ENCRYPTION;
#endif /* CONFIG_BT_SMP */
    }
#endif
#endif

    return 0;
}

struct conn_data
{
    struct bt_conn *conn;
    bt_security_t sec;
};

static uint8_t update_ccc(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct conn_data *data = user_data;
    struct bt_conn *conn = data->conn;
    struct _bt_gatt_ccc *ccc;
    size_t i;
    uint8_t err;

    /* Check attribute user_data must be of type struct _bt_gatt_ccc */
    if (attr->write != bt_gatt_attr_write_ccc)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    ccc = attr->user_data;

    for (i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        struct bt_gatt_ccc_cfg *cfg = &ccc->cfg[i];

        /* Ignore configuration for different peer or not active */
        if (!cfg->value || !bt_conn_is_peer_addr_le(conn, &cfg->peer))
        {
            continue;
        }

        /* Check if attribute requires encryption/authentication */
        err = bt_gatt_check_perm(conn, attr, BT_GATT_PERM_WRITE_MASK);
        if (err)
        {
            bt_security_t sec;

            if (err == BT_ATT_ERR_WRITE_NOT_PERMITTED)
            {
                LOG_WRN("CCC %p not writable", attr);
                continue;
            }

            sec = BT_SECURITY_L2;

            if (err == BT_ATT_ERR_AUTHENTICATION)
            {
                sec = BT_SECURITY_L3;
            }

#if defined(CONFIG_BT_SMP)
            /* Check if current security is enough */
            if (bt_conn_get_security(conn) < sec)
            {
                if (data->sec < sec)
                {
                    data->sec = sec;
                }
                continue;
            }
#endif
        }

        gatt_ccc_changed(attr, ccc);

        return BT_GATT_ITER_CONTINUE;
    }

    return BT_GATT_ITER_CONTINUE;
}

static uint8_t disconnected_cb(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{
    struct bt_conn *conn = user_data;
    struct _bt_gatt_ccc *ccc;
    bool value_used;
    size_t i;

    /* Check attribute user_data must be of type struct _bt_gatt_ccc */
    if (attr->write != bt_gatt_attr_write_ccc)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    ccc = attr->user_data;

    /* If already disabled skip */
    if (!ccc->value)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    /* Checking if all values are disabled */
    value_used = false;

    for (i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        struct bt_gatt_ccc_cfg *cfg = &ccc->cfg[i];

        /* Ignore configurations with disabled value */
        if (!cfg->value)
        {
            continue;
        }

        // if (!bt_conn_is_peer_addr_le(conn, cfg->id, &cfg->peer))
        // {
        //     struct bt_conn *tmp;

        //     /* Skip if there is another peer connected */
        //     tmp = bt_conn_lookup_addr_le(cfg->id, &cfg->peer);
        //     if (tmp)
        //     {
        //         if (tmp->state == BT_CONN_CONNECTED)
        //         {
        //             value_used = true;
        //         }

        //         // bt_conn_unref(tmp);
        //     }
        // }
        // else
        // {
        //     /* Clear value if not paired */
        //     if (!bt_addr_le_is_bonded(conn->id, &conn->le.dst))
        //     {
        //         // if (ccc == &sc_ccc)
        //         // {
        //         //     sc_clear(conn);
        //         // }

        //         clear_ccc_cfg(cfg);
        //     }
        //     else
        //     {
        //         /* Update address in case it has changed */
        //         bt_addr_le_copy(&cfg->peer, &conn->le.dst);
        //     }
        // }
    }

    /* If all values are now disabled, reset value while disconnected */
    if (!value_used)
    {
        ccc->value = 0U;
        if (ccc->cfg_changed)
        {
            ccc->cfg_changed(attr, ccc->value);
        }

        LOG_DBG("ccc %p reseted", ccc);
    }

    return BT_GATT_ITER_CONTINUE;
}

bool bt_gatt_is_subscribed(struct bt_conn *conn, const struct bt_gatt_attr *attr, uint16_t ccc_type)
{
    const struct _bt_gatt_ccc *ccc;

    __ASSERT(conn, "invalid parameter\n");
    __ASSERT(attr, "invalid parameter\n");

    if (conn->state != BT_CONN_CONNECTED)
    {
        return false;
    }

    /* Check if attribute is a characteristic declaration */
    if (!bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CHRC))
    {
        struct bt_gatt_chrc *chrc = attr->user_data;

        if (!(chrc->properties & (BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_INDICATE)))
        {
            /* Characteristic doesn't support subscription */
            return false;
        }

        attr = bt_gatt_attr_next(attr);
        __ASSERT(attr, "No more attributes\n");
    }

    /* Check if attribute is a characteristic value */
    if (bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CCC) != 0)
    {
        attr = bt_gatt_attr_next(attr);
        __ASSERT(attr, "No more attributes\n");
    }

    /* Find the CCC Descriptor */
    while (bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CCC) &&
           /* Also stop if we leave the current characteristic definition */
           bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CHRC) &&
           bt_uuid_cmp(attr->uuid, BT_UUID_GATT_PRIMARY) &&
           bt_uuid_cmp(attr->uuid, BT_UUID_GATT_SECONDARY))
    {
        attr = bt_gatt_attr_next(attr);
        if (!attr)
        {
            return false;
        }
    }

    if (bt_uuid_cmp(attr->uuid, BT_UUID_GATT_CCC) != 0)
    {
        return false;
    }

    ccc = attr->user_data;

    /* Check if the connection is subscribed */
    for (size_t i = 0; i < BT_GATT_CCC_MAX; i++)
    {
        const struct bt_gatt_ccc_cfg *cfg = &ccc->cfg[i];

        if (bt_conn_is_peer_addr_le(conn, &cfg->peer) && (ccc_type & ccc->cfg[i].value))
        {
            return true;
        }
    }

    return false;
}

static bool gatt_sub_is_empty(struct gatt_sub *sub)
{
    return sys_slist_is_empty(&sub->list);
}

/** @brief Free sub for reuse.
 */
static void gatt_sub_free(struct gatt_sub *sub)
{
    __ASSERT_NO_MSG(gatt_sub_is_empty(sub));
    bt_addr_le_copy(&sub->peer, BT_ADDR_LE_ANY);
}

static void gatt_sub_remove(struct bt_conn *conn, struct gatt_sub *sub, sys_snode_t *prev,
                            struct bt_gatt_subscribe_params *params)
{
    if (params)
    {
        /* Remove subscription from the list*/
        sys_slist_remove(&sub->list, prev, &params->node);
        /* Notify removal */
        params->notify(conn, params, NULL, 0);
    }

    if (gatt_sub_is_empty(sub))
    {
        gatt_sub_free(sub);
    }
}

#if defined(CONFIG_BT_GATT_CLIENT)
static struct gatt_sub *gatt_sub_find(struct bt_conn *conn)
{
    for (int i = 0; i < ARRAY_SIZE(subscriptions); i++)
    {
        struct gatt_sub *sub = &subscriptions[i];

        if (!conn)
        {
            if (bt_addr_le_eq(&sub->peer, BT_ADDR_LE_ANY))
            {
                return sub;
            }
        }
        else if (bt_conn_is_peer_addr_le(conn, sub->id, &sub->peer))
        {
            return sub;
        }
    }

    return NULL;
}

static struct gatt_sub *gatt_sub_add(struct bt_conn *conn)
{
    struct gatt_sub *sub;

    sub = gatt_sub_find(conn);
    if (!sub)
    {
        sub = gatt_sub_find(NULL);
        if (sub)
        {
            bt_addr_le_copy(&sub->peer, &conn->le.dst);
            sub->id = conn->id;
        }
    }

    return sub;
}

static struct gatt_sub *gatt_sub_find_by_addr(uint8_t id, const bt_addr_le_t *addr)
{
    for (int i = 0; i < ARRAY_SIZE(subscriptions); i++)
    {
        struct gatt_sub *sub = &subscriptions[i];

        if (id == sub->id && bt_addr_le_eq(&sub->peer, addr))
        {
            return sub;
        }
    }

    return NULL;
}

static struct gatt_sub *gatt_sub_add_by_addr(uint8_t id, const bt_addr_le_t *addr)
{
    struct gatt_sub *sub;

    sub = gatt_sub_find_by_addr(id, addr);
    if (!sub)
    {
        sub = gatt_sub_find(NULL);
        if (sub)
        {
            bt_addr_le_copy(&sub->peer, addr);
            sub->id = id;
        }
    }

    return sub;
}

static bool check_subscribe_security_level(struct bt_conn *conn,
                                           const struct bt_gatt_subscribe_params *params)
{
#if defined(CONFIG_BT_SMP)
    return conn->sec_level >= params->min_security;
#endif
    return true;
}

void bt_gatt_notification(struct bt_conn *conn, uint16_t handle, const void *data, uint16_t length)
{
    struct bt_gatt_subscribe_params *params, *tmp;
    struct gatt_sub *sub;

    LOG_DBG("handle 0x%04x length %u", handle, length);

    sub = gatt_sub_find(conn);
    if (!sub)
    {
        return;
    }

    SYS_SLIST_FOR_EACH_CONTAINER_SAFE (&sub->list, params, tmp, node)
    {
        if (handle != params->value_handle)
        {
            continue;
        }

        if (check_subscribe_security_level(conn, params))
        {
            if (params->notify(conn, params, data, length) == BT_GATT_ITER_STOP)
            {
                bt_gatt_unsubscribe(conn, params);
            }
        }
    }
}

void bt_gatt_mult_notification(struct bt_conn *conn, const void *data, uint16_t length)
{
    struct bt_gatt_subscribe_params *params, *tmp;
    const struct bt_att_notify_mult *nfy;
    struct net_buf_simple buf;
    struct gatt_sub *sub;

    LOG_DBG("length %u", length);

    sub = gatt_sub_find(conn);
    if (!sub)
    {
        return;
    }

    /* This is fine since there no write operation to the buffer.  */
    net_buf_simple_init_with_data(&buf, (void *)data, length);

    while (buf.len > sizeof(*nfy))
    {
        uint16_t handle;
        uint16_t len;

        nfy = net_buf_simple_pull_mem(&buf, sizeof(*nfy));
        handle = sys_cpu_to_le16(nfy->handle);
        len = sys_cpu_to_le16(nfy->len);

        LOG_DBG("handle 0x%02x len %u", handle, len);

        if (len > buf.len)
        {
            LOG_ERR("Invalid data len %u > %u", len, length);
            return;
        }

        SYS_SLIST_FOR_EACH_CONTAINER_SAFE (&sub->list, params, tmp, node)
        {
            if (handle != params->value_handle)
            {
                continue;
            }

            if (check_subscribe_security_level(conn, params))
            {
                if (params->notify(conn, params, nfy->value, len) == BT_GATT_ITER_STOP)
                {
                    bt_gatt_unsubscribe(conn, params);
                }
            }
        }

        net_buf_simple_pull_mem(&buf, len);
    }
}

static void gatt_sub_update(struct bt_conn *conn, struct gatt_sub *sub)
{
    if (sub->peer.type == BT_ADDR_LE_PUBLIC)
    {
        return;
    }

    /* Update address */
    bt_addr_le_copy(&sub->peer, &conn->le.dst);
}

static void remove_subscriptions(struct bt_conn *conn)
{
    struct gatt_sub *sub;
    struct bt_gatt_subscribe_params *params, *tmp;
    sys_snode_t *prev = NULL;

    sub = gatt_sub_find(conn);
    if (!sub)
    {
        return;
    }

    /* Lookup existing subscriptions */
    SYS_SLIST_FOR_EACH_CONTAINER_SAFE (&sub->list, params, tmp, node)
    {
        atomic_clear_bit(params->flags, BT_GATT_SUBSCRIBE_FLAG_SENT);

        if (!bt_addr_le_is_bonded(conn->id, &conn->le.dst) ||
            (atomic_test_bit(params->flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE)))
        {
            /* Remove subscription */
            params->value = 0U;
            gatt_sub_remove(conn, sub, prev, params);
        }
        else
        {
            gatt_sub_update(conn, sub);
            prev = &params->node;
        }
    }
}

static void gatt_mtu_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                         void *user_data)
{
    struct bt_gatt_exchange_params *params = user_data;

    params->func(conn, err, params);
}

static int gatt_exchange_mtu_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_att_exchange_mtu_req *req;
    uint16_t mtu;

    mtu = BT_ATT_MTU;

    LOG_DBG("Client MTU %u", mtu);

    req = net_buf_add(buf, sizeof(*req));
    req->mtu = sys_cpu_to_le16(mtu);

    return 0;
}

int bt_gatt_exchange_mtu(struct bt_conn *conn, struct bt_gatt_exchange_params *params)
{
    int err;

    __ASSERT(conn, "invalid parameter\n");
    __ASSERT(params && params->func, "invalid parameters\n");

    if (conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

    /* This request shall only be sent once during a connection by the client. */
    if (atomic_test_and_set_bit(conn->flags, BT_CONN_ATT_MTU_EXCHANGED))
    {
        return -EALREADY;
    }

    err = gatt_req_send(conn, gatt_mtu_rsp, params, gatt_exchange_mtu_encode, BT_ATT_OP_MTU_REQ,
                        sizeof(struct bt_att_exchange_mtu_req), BT_ATT_CHAN_OPT_UNENHANCED_ONLY);
    if (err)
    {
        atomic_clear_bit(conn->flags, BT_CONN_ATT_MTU_EXCHANGED);
    }

    return err;
}

static void gatt_discover_next(struct bt_conn *conn, uint16_t last_handle,
                               struct bt_gatt_discover_params *params)
{
    /* Skip if last_handle is not set */
    if (!last_handle)
        goto discover;

    /* Continue from the last found handle */
    params->start_handle = last_handle;
    if (params->start_handle < UINT16_MAX)
    {
        params->start_handle++;
    }
    else
    {
        goto done;
    }

    /* Stop if over the range or the requests */
    if (params->start_handle > params->end_handle)
    {
        goto done;
    }

discover:
    /* Discover next range */
    if (!bt_gatt_discover(conn, params))
    {
        return;
    }

done:
    params->func(conn, NULL, params);
}

static void gatt_find_type_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                               void *user_data)
{
    const struct bt_att_handle_group *rsp = pdu;
    struct bt_gatt_discover_params *params = user_data;
    uint8_t count;
    uint16_t end_handle = 0U, start_handle;

    LOG_DBG("err 0x%02x", err);

    if (err || (length % sizeof(struct bt_att_handle_group) != 0))
    {
        goto done;
    }

    count = length / sizeof(struct bt_att_handle_group);

    /* Parse attributes found */
    for (uint8_t i = 0U; i < count; i++)
    {
        struct bt_uuid_16 uuid_svc;
        struct bt_gatt_attr attr;
        struct bt_gatt_service_val value;

        start_handle = sys_le16_to_cpu(rsp[i].start_handle);
        end_handle = sys_le16_to_cpu(rsp[i].end_handle);

        LOG_DBG("start_handle 0x%04x end_handle 0x%04x", start_handle, end_handle);

        uuid_svc.uuid.type = BT_UUID_TYPE_16;
        if (params->type == BT_GATT_DISCOVER_PRIMARY)
        {
            uuid_svc.val = BT_UUID_GATT_PRIMARY_VAL;
        }
        else
        {
            uuid_svc.val = BT_UUID_GATT_SECONDARY_VAL;
        }

        value.end_handle = end_handle;
        value.uuid = params->uuid;

        attr = (struct bt_gatt_attr){
                .uuid = &uuid_svc.uuid,
                .user_data = &value,
                .handle = start_handle,
        };

        if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
        {
            return;
        }
    }

    gatt_discover_next(conn, end_handle, params);

    return;
done:
    params->func(conn, NULL, params);
}

static int gatt_find_type_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    struct bt_att_find_type_req *req;
    uint16_t uuid_val;

    req = net_buf_add(buf, sizeof(*req));
    req->start_handle = sys_cpu_to_le16(params->start_handle);
    req->end_handle = sys_cpu_to_le16(params->end_handle);

    if (params->type == BT_GATT_DISCOVER_PRIMARY)
    {
        uuid_val = BT_UUID_GATT_PRIMARY_VAL;
    }
    else
    {
        uuid_val = BT_UUID_GATT_SECONDARY_VAL;
    }

    req->type = sys_cpu_to_le16(uuid_val);

    LOG_DBG("uuid %s start_handle 0x%04x end_handle 0x%04x", bt_uuid_str(params->uuid),
            params->start_handle, params->end_handle);

    switch (params->uuid->type)
    {
    case BT_UUID_TYPE_16:
        net_buf_add_le16(buf, BT_UUID_16(params->uuid)->val);
        break;
    case BT_UUID_TYPE_128:
        net_buf_add_mem(buf, BT_UUID_128(params->uuid)->val, 16);
        break;
    }

    return 0;
}

static int gatt_find_type(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
    size_t len;

    len = sizeof(struct bt_att_find_type_req);

    switch (params->uuid->type)
    {
    case BT_UUID_TYPE_16:
        len += BT_UUID_SIZE_16;
        break;
    case BT_UUID_TYPE_128:
        len += BT_UUID_SIZE_128;
        break;
    default:
        LOG_ERR("Unknown UUID type %u", params->uuid->type);
        return -EINVAL;
    }

    return gatt_req_send(conn, gatt_find_type_rsp, params, gatt_find_type_encode,
                         BT_ATT_OP_FIND_TYPE_REQ, len, BT_ATT_CHAN_OPT(params));
}

static void read_included_uuid_cb(struct bt_conn *conn, uint8_t err, const void *pdu,
                                  uint16_t length, void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    struct bt_gatt_include value;
    struct bt_gatt_attr attr;
    uint16_t handle;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_128 u128;
    } u;

    if (length != 16U)
    {
        LOG_ERR("Invalid data len %u", length);
        params->func(conn, NULL, params);
        return;
    }

    handle = params->_included.attr_handle;
    value.start_handle = params->_included.start_handle;
    value.end_handle = params->_included.end_handle;
    value.uuid = &u.uuid;
    u.uuid.type = BT_UUID_TYPE_128;
    memcpy(u.u128.val, pdu, length);

    LOG_DBG("handle 0x%04x uuid %s start_handle 0x%04x "
            "end_handle 0x%04x\n",
            params->_included.attr_handle, bt_uuid_str(&u.uuid), value.start_handle,
            value.end_handle);

    /* Skip if UUID is set but doesn't match */
    if (params->uuid && bt_uuid_cmp(&u.uuid, params->uuid))
    {
        goto next;
    }

    attr = (struct bt_gatt_attr){
            .uuid = BT_UUID_GATT_INCLUDE,
            .user_data = &value,
            .handle = handle,
    };

    if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
    {
        return;
    }
next:
    gatt_discover_next(conn, params->start_handle, params);

    return;
}

static int read_included_uuid_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    struct bt_att_read_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->handle = sys_cpu_to_le16(params->_included.start_handle);

    return 0;
}

static int read_included_uuid(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
    LOG_DBG("handle 0x%04x", params->_included.start_handle);

    return gatt_req_send(conn, read_included_uuid_cb, params, read_included_uuid_encode,
                         BT_ATT_OP_READ_REQ, sizeof(struct bt_att_read_req),
                         BT_ATT_CHAN_OPT(params));
}

static uint16_t parse_include(struct bt_conn *conn, const void *pdu,
                              struct bt_gatt_discover_params *params, uint16_t length)
{
    const struct bt_att_read_type_rsp *rsp = pdu;
    uint16_t handle = 0U;
    struct bt_gatt_include value;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_16 u16;
        struct bt_uuid_128 u128;
    } u;

    /* Data can be either in UUID16 or UUID128 */
    switch (rsp->len)
    {
    case 8: /* UUID16 */
        u.uuid.type = BT_UUID_TYPE_16;
        break;
    case 6: /* UUID128 */
        /* BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part G] page 550
         * To get the included service UUID when the included service
         * uses a 128-bit UUID, the Read Request is used.
         */
        u.uuid.type = BT_UUID_TYPE_128;
        break;
    default:
        LOG_ERR("Invalid data len %u", rsp->len);
        goto done;
    }

    /* Parse include found */
    for (length--, pdu = rsp->data; length >= rsp->len;
         length -= rsp->len, pdu = (const uint8_t *)pdu + rsp->len)
    {
        struct bt_gatt_attr attr;
        const struct bt_att_data *data = pdu;
        struct gatt_incl *incl = (void *)data->value;

        handle = sys_le16_to_cpu(data->handle);
        /* Handle 0 is invalid */
        if (!handle)
        {
            goto done;
        }

        /* Convert include data, bt_gatt_incl and gatt_incl
         * have different formats so the conversion have to be done
         * field by field.
         */
        value.start_handle = sys_le16_to_cpu(incl->start_handle);
        value.end_handle = sys_le16_to_cpu(incl->end_handle);

        switch (u.uuid.type)
        {
        case BT_UUID_TYPE_16:
            value.uuid = &u.uuid;
            u.u16.val = sys_le16_to_cpu(incl->uuid16);
            break;
        case BT_UUID_TYPE_128:
            params->_included.attr_handle = handle;
            params->_included.start_handle = value.start_handle;
            params->_included.end_handle = value.end_handle;

            return read_included_uuid(conn, params);
        }

        LOG_DBG("handle 0x%04x uuid %s start_handle 0x%04x "
                "end_handle 0x%04x\n",
                handle, bt_uuid_str(&u.uuid), value.start_handle, value.end_handle);

        /* Skip if UUID is set but doesn't match */
        if (params->uuid && bt_uuid_cmp(&u.uuid, params->uuid))
        {
            continue;
        }

        attr = (struct bt_gatt_attr){
                .uuid = BT_UUID_GATT_INCLUDE,
                .user_data = &value,
                .handle = handle,
        };

        if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
        {
            return 0;
        }
    }

    /* Whole PDU read without error */
    if (length == 0U && handle)
    {
        return handle;
    }

done:
    params->func(conn, NULL, params);
    return 0;
}

static uint16_t parse_characteristic(struct bt_conn *conn, const void *pdu,
                                     struct bt_gatt_discover_params *params, uint16_t length)
{
    const struct bt_att_read_type_rsp *rsp = pdu;
    uint16_t handle = 0U;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_16 u16;
        struct bt_uuid_128 u128;
    } u;

    /* Data can be either in UUID16 or UUID128 */
    switch (rsp->len)
    {
    case 7: /* UUID16 */
        u.uuid.type = BT_UUID_TYPE_16;
        break;
    case 21: /* UUID128 */
        u.uuid.type = BT_UUID_TYPE_128;
        break;
    default:
        LOG_ERR("Invalid data len %u", rsp->len);
        goto done;
    }

    /* Parse characteristics found */
    for (length--, pdu = rsp->data; length >= rsp->len;
         length -= rsp->len, pdu = (const uint8_t *)pdu + rsp->len)
    {
        struct bt_gatt_attr attr;
        struct bt_gatt_chrc value;
        const struct bt_att_data *data = pdu;
        struct gatt_chrc *chrc = (void *)data->value;

        handle = sys_le16_to_cpu(data->handle);
        /* Handle 0 is invalid */
        if (!handle)
        {
            goto done;
        }

        switch (u.uuid.type)
        {
        case BT_UUID_TYPE_16:
            u.u16.val = sys_le16_to_cpu(chrc->uuid16);
            break;
        case BT_UUID_TYPE_128:
            memcpy(u.u128.val, chrc->uuid, sizeof(chrc->uuid));
            break;
        }

        LOG_DBG("handle 0x%04x uuid %s properties 0x%02x", handle, bt_uuid_str(&u.uuid),
                chrc->properties);

        /* Skip if UUID is set but doesn't match */
        if (params->uuid && bt_uuid_cmp(&u.uuid, params->uuid))
        {
            continue;
        }

        value = (struct bt_gatt_chrc)BT_GATT_CHRC_INIT(&u.uuid, sys_le16_to_cpu(chrc->value_handle),
                                                       chrc->properties);

        attr = (struct bt_gatt_attr){
                .uuid = BT_UUID_GATT_CHRC,
                .user_data = &value,
                .handle = handle,
        };

        if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
        {
            return 0;
        }
    }

    /* Whole PDU read without error */
    if (length == 0U && handle)
    {
        return handle;
    }

done:
    params->func(conn, NULL, params);
    return 0;
}

static uint16_t parse_read_std_char_desc(struct bt_conn *conn, const void *pdu,
                                         struct bt_gatt_discover_params *params, uint16_t length)
{
    const struct bt_att_read_type_rsp *rsp = pdu;
    uint16_t handle = 0U;
    uint16_t uuid_val;

    if (params->uuid->type != BT_UUID_TYPE_16)
    {
        goto done;
    }

    uuid_val = BT_UUID_16(params->uuid)->val;

    /* Parse characteristics found */
    for (length--, pdu = rsp->data; length >= rsp->len;
         length -= rsp->len, pdu = (const uint8_t *)pdu + rsp->len)
    {
        union
        {
            struct bt_gatt_ccc ccc;
            struct bt_gatt_cpf cpf;
            struct bt_gatt_cep cep;
            struct bt_gatt_scc scc;
        } value;
        const struct bt_att_data *data = pdu;
        struct bt_gatt_attr attr;

        handle = sys_le16_to_cpu(data->handle);
        /* Handle 0 is invalid */
        if (!handle)
        {
            goto done;
        }

        switch (uuid_val)
        {
        case BT_UUID_GATT_CEP_VAL:
            value.cep.properties = sys_get_le16(data->value);
            break;
        case BT_UUID_GATT_CCC_VAL:
            value.ccc.flags = sys_get_le16(data->value);
            break;
        case BT_UUID_GATT_SCC_VAL:
            value.scc.flags = sys_get_le16(data->value);
            break;
        case BT_UUID_GATT_CPF_VAL:
        {
            struct gatt_cpf *cpf = (struct gatt_cpf *)data->value;

            value.cpf.format = cpf->format;
            value.cpf.exponent = cpf->exponent;
            value.cpf.unit = sys_le16_to_cpu(cpf->unit);
            value.cpf.name_space = cpf->name_space;
            value.cpf.description = sys_le16_to_cpu(cpf->description);
            break;
        }
        default:
            goto done;
        }

        attr = (struct bt_gatt_attr){
                .uuid = params->uuid,
                .user_data = &value,
                .handle = handle,
        };

        if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
        {
            return 0;
        }
    }

    /* Whole PDU read without error */
    if (length == 0U && handle)
    {
        return handle;
    }

done:
    params->func(conn, NULL, params);
    return 0;
}

static void gatt_read_type_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                               void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    uint16_t handle;

    LOG_DBG("err 0x%02x", err);

    if (err)
    {
        params->func(conn, NULL, params);
        return;
    }

    if (params->type == BT_GATT_DISCOVER_INCLUDE)
    {
        handle = parse_include(conn, pdu, params, length);
    }
    else if (params->type == BT_GATT_DISCOVER_CHARACTERISTIC)
    {
        handle = parse_characteristic(conn, pdu, params, length);
    }
    else
    {
        handle = parse_read_std_char_desc(conn, pdu, params, length);
    }

    if (!handle)
    {
        return;
    }

    gatt_discover_next(conn, handle, params);
}

static int gatt_read_type_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    struct bt_att_read_type_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->start_handle = sys_cpu_to_le16(params->start_handle);
    req->end_handle = sys_cpu_to_le16(params->end_handle);

    switch (params->type)
    {
    case BT_GATT_DISCOVER_INCLUDE:
        net_buf_add_le16(buf, BT_UUID_GATT_INCLUDE_VAL);
        break;
    case BT_GATT_DISCOVER_CHARACTERISTIC:
        net_buf_add_le16(buf, BT_UUID_GATT_CHRC_VAL);
        break;
    default:
        /* Only 16-bit UUIDs supported */
        net_buf_add_le16(buf, BT_UUID_16(params->uuid)->val);
        break;
    }

    return 0;
}

static int gatt_read_type(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
    LOG_DBG("start_handle 0x%04x end_handle 0x%04x", params->start_handle, params->end_handle);

    return gatt_req_send(conn, gatt_read_type_rsp, params, gatt_read_type_encode,
                         BT_ATT_OP_READ_TYPE_REQ, sizeof(struct bt_att_read_type_req),
                         BT_ATT_CHAN_OPT(params));
}

static uint16_t parse_service(struct bt_conn *conn, const void *pdu,
                              struct bt_gatt_discover_params *params, uint16_t length)
{
    const struct bt_att_read_group_rsp *rsp = pdu;
    uint16_t start_handle, end_handle = 0U;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_16 u16;
        struct bt_uuid_128 u128;
    } u;

    /* Data can be either in UUID16 or UUID128 */
    switch (rsp->len)
    {
    case 6: /* UUID16 */
        u.uuid.type = BT_UUID_TYPE_16;
        break;
    case 20: /* UUID128 */
        u.uuid.type = BT_UUID_TYPE_128;
        break;
    default:
        LOG_ERR("Invalid data len %u", rsp->len);
        goto done;
    }

    /* Parse services found */
    for (length--, pdu = rsp->data; length >= rsp->len;
         length -= rsp->len, pdu = (const uint8_t *)pdu + rsp->len)
    {
        struct bt_uuid_16 uuid_svc;
        struct bt_gatt_attr attr = {};
        struct bt_gatt_service_val value;
        const struct bt_att_group_data *data = pdu;

        start_handle = sys_le16_to_cpu(data->start_handle);
        if (!start_handle)
        {
            goto done;
        }

        end_handle = sys_le16_to_cpu(data->end_handle);
        if (!end_handle || end_handle < start_handle)
        {
            goto done;
        }

        switch (u.uuid.type)
        {
        case BT_UUID_TYPE_16:
            memcpy(&u.u16.val, data->value, sizeof(u.u16.val));
            u.u16.val = sys_le16_to_cpu(u.u16.val);
            break;
        case BT_UUID_TYPE_128:
            memcpy(u.u128.val, data->value, sizeof(u.u128.val));
            break;
        }

        LOG_DBG("start_handle 0x%04x end_handle 0x%04x uuid %s", start_handle, end_handle,
                bt_uuid_str(&u.uuid));

        uuid_svc.uuid.type = BT_UUID_TYPE_16;
        if (params->type == BT_GATT_DISCOVER_PRIMARY)
        {
            uuid_svc.val = BT_UUID_GATT_PRIMARY_VAL;
        }
        else
        {
            uuid_svc.val = BT_UUID_GATT_SECONDARY_VAL;
        }

        value.end_handle = end_handle;
        value.uuid = &u.uuid;

        attr.uuid = &uuid_svc.uuid;
        attr.handle = start_handle;
        attr.user_data = &value;

        if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
        {
            return 0;
        }
    }

    /* Whole PDU read without error */
    if (length == 0U && end_handle)
    {
        return end_handle;
    }

done:
    params->func(conn, NULL, params);
    return 0;
}

static void gatt_read_group_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                                void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    uint16_t handle;

    LOG_DBG("err 0x%02x", err);

    if (err)
    {
        params->func(conn, NULL, params);
        return;
    }

    handle = parse_service(conn, pdu, params, length);
    if (!handle)
    {
        return;
    }

    gatt_discover_next(conn, handle, params);
}

static int gatt_read_group_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    struct bt_att_read_group_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->start_handle = sys_cpu_to_le16(params->start_handle);
    req->end_handle = sys_cpu_to_le16(params->end_handle);

    if (params->type == BT_GATT_DISCOVER_PRIMARY)
    {
        net_buf_add_le16(buf, BT_UUID_GATT_PRIMARY_VAL);
    }
    else
    {
        net_buf_add_le16(buf, BT_UUID_GATT_SECONDARY_VAL);
    }

    return 0;
}

static int gatt_read_group(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
    LOG_DBG("start_handle 0x%04x end_handle 0x%04x", params->start_handle, params->end_handle);

    return gatt_req_send(conn, gatt_read_group_rsp, params, gatt_read_group_encode,
                         BT_ATT_OP_READ_GROUP_REQ, sizeof(struct bt_att_read_group_req),
                         BT_ATT_CHAN_OPT(params));
}

static void gatt_find_info_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                               void *user_data)
{
    const struct bt_att_find_info_rsp *rsp = pdu;
    struct bt_gatt_discover_params *params = user_data;
    uint16_t handle = 0U;
    uint16_t len;
    union
    {
        const struct bt_att_info_16 *i16;
        const struct bt_att_info_128 *i128;
    } info;
    union
    {
        struct bt_uuid uuid;
        struct bt_uuid_16 u16;
        struct bt_uuid_128 u128;
    } u;
    int i;
    bool skip = false;

    LOG_DBG("err 0x%02x", err);

    if (err)
    {
        goto done;
    }

    /* Data can be either in UUID16 or UUID128 */
    switch (rsp->format)
    {
    case BT_ATT_INFO_16:
        u.uuid.type = BT_UUID_TYPE_16;
        len = sizeof(*info.i16);
        break;
    case BT_ATT_INFO_128:
        u.uuid.type = BT_UUID_TYPE_128;
        len = sizeof(*info.i128);
        break;
    default:
        LOG_ERR("Invalid format %u", rsp->format);
        goto done;
    }

    length--;

    /* Check if there is a least one descriptor in the response */
    if (length < len)
    {
        goto done;
    }

    /* Parse descriptors found */
    for (i = length / len, pdu = rsp->info; i != 0; i--, pdu = (const uint8_t *)pdu + len)
    {
        struct bt_gatt_attr attr;

        info.i16 = pdu;
        handle = sys_le16_to_cpu(info.i16->handle);

        if (skip)
        {
            skip = false;
            continue;
        }

        switch (u.uuid.type)
        {
        case BT_UUID_TYPE_16:
            u.u16.val = sys_le16_to_cpu(info.i16->uuid);
            break;
        case BT_UUID_TYPE_128:
            memcpy(u.u128.val, info.i128->uuid, 16);
            break;
        }

        LOG_DBG("handle 0x%04x uuid %s", handle, bt_uuid_str(&u.uuid));

        /* Skip if UUID is set but doesn't match */
        if (params->uuid && bt_uuid_cmp(&u.uuid, params->uuid))
        {
            continue;
        }

        if (params->type == BT_GATT_DISCOVER_DESCRIPTOR)
        {
            /* Skip attributes that are not considered
             * descriptors.
             */
            if (!bt_uuid_cmp(&u.uuid, BT_UUID_GATT_PRIMARY) ||
                !bt_uuid_cmp(&u.uuid, BT_UUID_GATT_SECONDARY) ||
                !bt_uuid_cmp(&u.uuid, BT_UUID_GATT_INCLUDE))
            {
                continue;
            }

            /* If Characteristic Declaration skip ahead as the next
             * entry must be its value.
             */
            if (!bt_uuid_cmp(&u.uuid, BT_UUID_GATT_CHRC))
            {
                skip = true;
                continue;
            }
        }

        /* No user_data in this case */
        attr = (struct bt_gatt_attr){
                .uuid = &u.uuid,
                .handle = handle,
        };

        if (params->func(conn, &attr, params) == BT_GATT_ITER_STOP)
        {
            return;
        }
    }

    gatt_discover_next(conn, handle, params);

    return;

done:
    params->func(conn, NULL, params);
}

static int gatt_find_info_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_discover_params *params = user_data;
    struct bt_att_find_info_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->start_handle = sys_cpu_to_le16(params->start_handle);
    req->end_handle = sys_cpu_to_le16(params->end_handle);

    return 0;
}

static int gatt_find_info(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
    LOG_DBG("start_handle 0x%04x end_handle 0x%04x", params->start_handle, params->end_handle);

    return gatt_req_send(conn, gatt_find_info_rsp, params, gatt_find_info_encode,
                         BT_ATT_OP_FIND_INFO_REQ, sizeof(struct bt_att_find_info_req),
                         BT_ATT_CHAN_OPT(params));
}

int bt_gatt_discover(struct bt_conn *conn, struct bt_gatt_discover_params *params)
{
    __ASSERT(conn, "invalid parameters\n");
    __ASSERT(params && params->func, "invalid parameters\n");
    __ASSERT((params->start_handle && params->end_handle), "invalid parameters\n");
    __ASSERT((params->start_handle <= params->end_handle), "invalid parameters\n");

    if (conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

    switch (params->type)
    {
    case BT_GATT_DISCOVER_PRIMARY:
    case BT_GATT_DISCOVER_SECONDARY:
        if (params->uuid)
        {
            return gatt_find_type(conn, params);
        }
        return gatt_read_group(conn, params);

    case BT_GATT_DISCOVER_STD_CHAR_DESC:
        if (!(params->uuid && params->uuid->type == BT_UUID_TYPE_16 &&
              (!bt_uuid_cmp(params->uuid, BT_UUID_GATT_CEP) ||
               !bt_uuid_cmp(params->uuid, BT_UUID_GATT_CCC) ||
               !bt_uuid_cmp(params->uuid, BT_UUID_GATT_SCC) ||
               !bt_uuid_cmp(params->uuid, BT_UUID_GATT_CPF))))
        {
            return -EINVAL;
        }
        __fallthrough;
    case BT_GATT_DISCOVER_INCLUDE:
    case BT_GATT_DISCOVER_CHARACTERISTIC:
        return gatt_read_type(conn, params);
    case BT_GATT_DISCOVER_DESCRIPTOR:
        /* Only descriptors can be filtered */
        if (params->uuid && (!bt_uuid_cmp(params->uuid, BT_UUID_GATT_PRIMARY) ||
                             !bt_uuid_cmp(params->uuid, BT_UUID_GATT_SECONDARY) ||
                             !bt_uuid_cmp(params->uuid, BT_UUID_GATT_INCLUDE) ||
                             !bt_uuid_cmp(params->uuid, BT_UUID_GATT_CHRC)))
        {
            return -EINVAL;
        }
        __fallthrough;
    case BT_GATT_DISCOVER_ATTRIBUTE:
        return gatt_find_info(conn, params);
    default:
        LOG_ERR("Invalid discovery type: %u", params->type);
    }

    return -EINVAL;
}

static void parse_read_by_uuid(struct bt_conn *conn, struct bt_gatt_read_params *params,
                               const void *pdu, uint16_t length)
{
    const struct bt_att_read_type_rsp *rsp = pdu;

    /* Parse values found */
    for (length--, pdu = rsp->data; length;
         length -= rsp->len, pdu = (const uint8_t *)pdu + rsp->len)
    {
        const struct bt_att_data *data = pdu;
        uint16_t handle;
        uint16_t len;

        handle = sys_le16_to_cpu(data->handle);

        /* Handle 0 is invalid */
        if (!handle)
        {
            LOG_ERR("Invalid handle");
            return;
        }

        len = rsp->len > length ? length - 2 : rsp->len - 2;

        LOG_DBG("handle 0x%04x len %u value %u", handle, rsp->len, len);

        /* Update start_handle */
        params->by_uuid.start_handle = handle;

        if (params->func(conn, 0, params, data->value, len) == BT_GATT_ITER_STOP)
        {
            return;
        }

        /* Check if long attribute */
        if (rsp->len > length)
        {
            break;
        }

        /* Stop if it's the last handle to be read */
        if (params->by_uuid.start_handle == params->by_uuid.end_handle)
        {
            params->func(conn, 0, params, NULL, 0);
            return;
        }

        params->by_uuid.start_handle++;
    }

    /* Continue reading the attributes */
    if (bt_gatt_read(conn, params) < 0)
    {
        params->func(conn, BT_ATT_ERR_UNLIKELY, params, NULL, 0);
    }
}

static void gatt_read_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                          void *user_data)
{
    struct bt_gatt_read_params *params = user_data;

    LOG_DBG("err 0x%02x", err);

    if (err || !length)
    {
        params->func(conn, err, params, NULL, 0);
        return;
    }

    if (!params->handle_count)
    {
        parse_read_by_uuid(conn, params, pdu, length);
        return;
    }

    if (params->func(conn, 0, params, pdu, length) == BT_GATT_ITER_STOP)
    {
        return;
    }

    /*
     * Core Spec 4.2, Vol. 3, Part G, 4.8.1
     * If the Characteristic Value is greater than (ATT_MTU - 1) octets
     * in length, the Read Long Characteristic Value procedure may be used
     * if the rest of the Characteristic Value is required.
     */
    if (length < (bt_att_get_mtu(conn) - 1))
    {
        params->func(conn, 0, params, NULL, 0);
        return;
    }

    params->single.offset += length;

    /* Continue reading the attribute */
    if (bt_gatt_read(conn, params) < 0)
    {
        params->func(conn, BT_ATT_ERR_UNLIKELY, params, NULL, 0);
    }
}

static int gatt_read_blob_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_read_params *params = user_data;
    struct bt_att_read_blob_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->handle = sys_cpu_to_le16(params->single.handle);
    req->offset = sys_cpu_to_le16(params->single.offset);

    return 0;
}

static int gatt_read_blob(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    LOG_DBG("handle 0x%04x offset 0x%04x", params->single.handle, params->single.offset);

    return gatt_req_send(conn, gatt_read_rsp, params, gatt_read_blob_encode,
                         BT_ATT_OP_READ_BLOB_REQ, sizeof(struct bt_att_read_blob_req),
                         BT_ATT_CHAN_OPT(params));
}

static int gatt_read_uuid_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_read_params *params = user_data;
    struct bt_att_read_type_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->start_handle = sys_cpu_to_le16(params->by_uuid.start_handle);
    req->end_handle = sys_cpu_to_le16(params->by_uuid.end_handle);

    if (params->by_uuid.uuid->type == BT_UUID_TYPE_16)
    {
        net_buf_add_le16(buf, BT_UUID_16(params->by_uuid.uuid)->val);
    }
    else
    {
        net_buf_add_mem(buf, BT_UUID_128(params->by_uuid.uuid)->val, 16);
    }

    return 0;
}

static int gatt_read_uuid(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    LOG_DBG("start_handle 0x%04x end_handle 0x%04x uuid %s", params->by_uuid.start_handle,
            params->by_uuid.end_handle, bt_uuid_str(params->by_uuid.uuid));

    return gatt_req_send(conn, gatt_read_rsp, params, gatt_read_uuid_encode,
                         BT_ATT_OP_READ_TYPE_REQ, sizeof(struct bt_att_read_type_req),
                         BT_ATT_CHAN_OPT(params));
}

#if defined(CONFIG_BT_GATT_READ_MULTIPLE)
static void gatt_read_mult_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                               void *user_data)
{
    struct bt_gatt_read_params *params = user_data;

    LOG_DBG("err 0x%02x", err);

    if (err || !length)
    {
        params->func(conn, err, params, NULL, 0);
        return;
    }

    params->func(conn, 0, params, pdu, length);

    /* mark read as complete since read multiple is single response */
    params->func(conn, 0, params, NULL, 0);
}

static int gatt_read_mult_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_read_params *params = user_data;
    uint8_t i;

    for (i = 0U; i < params->handle_count; i++)
    {
        net_buf_add_le16(buf, params->multiple.handles[i]);
    }

    return 0;
}

static int gatt_read_mult(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    LOG_DBG("handle_count %zu", params->handle_count);

    return gatt_req_send(conn, gatt_read_mult_rsp, params, gatt_read_mult_encode,
                         BT_ATT_OP_READ_MULT_REQ, params->handle_count * sizeof(uint16_t),
                         BT_ATT_CHAN_OPT(params));
}

#else
static int gatt_read_mult(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    return -ENOTSUP;
}
#endif /* CONFIG_BT_GATT_READ_MULTIPLE */

#if defined(CONFIG_BT_GATT_READ_MULT_VAR_LEN)
static void gatt_read_mult_vl_rsp(struct bt_conn *conn, uint8_t err, const void *pdu,
                                  uint16_t length, void *user_data)
{
    struct bt_gatt_read_params *params = user_data;
    const struct bt_att_read_mult_vl_rsp *rsp;
    struct net_buf_simple buf;

    LOG_DBG("err 0x%02x", err);

    if (err || !length)
    {
        params->func(conn, err, params, NULL, 0);
        return;
    }

    net_buf_simple_init_with_data(&buf, (void *)pdu, length);

    while (buf.len >= sizeof(*rsp))
    {
        uint16_t len;

        rsp = net_buf_simple_pull_mem(&buf, sizeof(*rsp));
        len = sys_le16_to_cpu(rsp->len);

        /* If a Length Value Tuple is truncated, then the amount of
         * Attribute Value will be less than the value of the Value
         * Length field.
         */
        if (len > buf.len)
        {
            len = buf.len;
        }

        params->func(conn, 0, params, rsp->value, len);

        net_buf_simple_pull_mem(&buf, len);
    }

    /* mark read as complete since read multiple is single response */
    params->func(conn, 0, params, NULL, 0);
}

static int gatt_read_mult_vl_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_read_params *params = user_data;
    uint8_t i;

    for (i = 0U; i < params->handle_count; i++)
    {
        net_buf_add_le16(buf, params->multiple.handles[i]);
    }

    return 0;
}

static int gatt_read_mult_vl(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    LOG_DBG("handle_count %zu", params->handle_count);

    return gatt_req_send(conn, gatt_read_mult_vl_rsp, params, gatt_read_mult_vl_encode,
                         BT_ATT_OP_READ_MULT_VL_REQ, params->handle_count * sizeof(uint16_t),
                         BT_ATT_CHAN_OPT(params));
}

#else
static int gatt_read_mult_vl(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    return -ENOTSUP;
}
#endif /* CONFIG_BT_GATT_READ_MULT_VAR_LEN */

static int gatt_read_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_read_params *params = user_data;
    struct bt_att_read_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->handle = sys_cpu_to_le16(params->single.handle);

    return 0;
}

int bt_gatt_read(struct bt_conn *conn, struct bt_gatt_read_params *params)
{
    __ASSERT(conn, "invalid parameters\n");
    __ASSERT(params && params->func, "invalid parameters\n");

    if (conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

    if (params->handle_count == 0)
    {
        return gatt_read_uuid(conn, params);
    }

    if (params->handle_count > 1)
    {
        if (params->multiple.variable)
        {
            return gatt_read_mult_vl(conn, params);
        }
        else
        {
            return gatt_read_mult(conn, params);
        }
    }

    if (params->single.offset)
    {
        return gatt_read_blob(conn, params);
    }

    LOG_DBG("handle 0x%04x", params->single.handle);

    return gatt_req_send(conn, gatt_read_rsp, params, gatt_read_encode, BT_ATT_OP_READ_REQ,
                         sizeof(struct bt_att_read_req), BT_ATT_CHAN_OPT(params));
}

static void gatt_write_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                           void *user_data)
{
    struct bt_gatt_write_params *params = user_data;

    LOG_DBG("err 0x%02x", err);

    params->func(conn, err, params);
}

int bt_gatt_write_without_response_cb(struct bt_conn *conn, uint16_t handle, const void *data,
                                      uint16_t length, bool sign, bt_gatt_complete_func_t func,
                                      void *user_data)
{
    struct net_buf *buf;
    struct bt_att_write_cmd *cmd;
    size_t write;

    __ASSERT(conn, "invalid parameters\n");
    __ASSERT(handle, "invalid parameters\n");

    if (conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

#if defined(CONFIG_BT_SMP)
    if (conn->encrypt)
    {
        /* Don't need to sign if already encrypted */
        sign = false;
    }
#endif

    if (sign)
    {
        buf = bt_att_create_pdu(conn, BT_ATT_OP_SIGNED_WRITE_CMD, sizeof(*cmd) + length + 12);
    }
    else
    {
        buf = bt_att_create_pdu(conn, BT_ATT_OP_WRITE_CMD, sizeof(*cmd) + length);
    }
    if (!buf)
    {
        return -ENOMEM;
    }

    cmd = net_buf_add(buf, sizeof(*cmd));
    cmd->handle = sys_cpu_to_le16(handle);

    write = net_buf_append_bytes(buf, length, data, K_NO_WAIT, NULL, NULL);
    if (write != length)
    {
        LOG_WRN("Unable to allocate length %u: only %zu written", length, write);
        net_buf_unref(buf);
        return -ENOMEM;
    }

    LOG_DBG("handle 0x%04x length %u", handle, length);

    // bt_att_set_tx_meta_data(buf, func, user_data, BT_ATT_CHAN_OPT_NONE);

    return bt_att_send(conn, buf);
}

static int gatt_exec_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_att_exec_write_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->flags = BT_ATT_FLAG_EXEC;

    return 0;
}

static int gatt_exec_write(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
    LOG_DBG("");

    return gatt_req_send(conn, gatt_write_rsp, params, gatt_exec_encode, BT_ATT_OP_EXEC_WRITE_REQ,
                         sizeof(struct bt_att_exec_write_req), BT_ATT_CHAN_OPT(params));
}

static int gatt_cancel_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_att_exec_write_req *req;

    req = net_buf_add(buf, sizeof(*req));
    req->flags = BT_ATT_FLAG_CANCEL;

    return 0;
}

static int gatt_cancel_all_writes(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
    LOG_DBG("");

    return gatt_req_send(conn, gatt_write_rsp, params, gatt_cancel_encode, BT_ATT_OP_EXEC_WRITE_REQ,
                         sizeof(struct bt_att_exec_write_req), BT_ATT_CHAN_OPT(params));
}

static void gatt_prepare_write_rsp(struct bt_conn *conn, uint8_t err, const void *pdu,
                                   uint16_t length, void *user_data)
{
    struct bt_gatt_write_params *params = user_data;
    const struct bt_att_prepare_write_rsp *rsp = pdu;
    size_t len;
    bool data_valid;

    LOG_DBG("err 0x%02x", err);

    /* Don't continue in case of error */
    if (err)
    {
        params->func(conn, err, params);
        return;
    }

    len = length - sizeof(*rsp);
    if (len > params->length)
    {
        LOG_ERR("Incorrect length, canceling write");
        if (gatt_cancel_all_writes(conn, params))
        {
            goto fail;
        }

        return;
    }

    data_valid = memcmp(params->data, rsp->value, len) == 0;
    if (params->offset != rsp->offset || !data_valid)
    {
        LOG_ERR("Incorrect offset or data in response, canceling write");
        if (gatt_cancel_all_writes(conn, params))
        {
            goto fail;
        }

        return;
    }

    /* Update params */
    params->offset += len;
    params->data = (const uint8_t *)params->data + len;
    params->length -= len;

    /* If there is no more data execute */
    if (!params->length)
    {
        if (gatt_exec_write(conn, params))
        {
            goto fail;
        }

        return;
    }

    /* Write next chunk */
    if (!bt_gatt_write(conn, params))
    {
        /* Success */
        return;
    }

fail:
    /* Notify application that the write operation has failed */
    params->func(conn, BT_ATT_ERR_UNLIKELY, params);
}

static int gatt_prepare_write_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_write_params *params = user_data;
    struct bt_att_prepare_write_req *req;
    size_t write;

    req = net_buf_add(buf, sizeof(*req));
    req->handle = sys_cpu_to_le16(params->handle);
    req->offset = sys_cpu_to_le16(params->offset);

    write = net_buf_append_bytes(buf, len - sizeof(*req), (uint8_t *)params->data, K_NO_WAIT, NULL,
                                 NULL);
    if (write != (len - sizeof(*req)))
    {
        return -ENOMEM;
    }

    return 0;
}

static int gatt_prepare_write(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
    uint16_t len, req_len;

    req_len = sizeof(struct bt_att_prepare_write_req);

    len = bt_att_get_mtu(conn) - req_len - 1;
    len = MIN(params->length, len);
    len += req_len;

    return gatt_req_send(conn, gatt_prepare_write_rsp, params, gatt_prepare_write_encode,
                         BT_ATT_OP_PREPARE_WRITE_REQ, len, BT_ATT_CHAN_OPT(params));
}

static int gatt_write_encode(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_write_params *params = user_data;
    struct bt_att_write_req *req;
    size_t write;

    req = net_buf_add(buf, sizeof(*req));
    req->handle = sys_cpu_to_le16(params->handle);

    write = net_buf_append_bytes(buf, params->length, params->data, K_NO_WAIT, NULL, NULL);
    if (write != params->length)
    {
        return -ENOMEM;
    }

    return 0;
}

int bt_gatt_write(struct bt_conn *conn, struct bt_gatt_write_params *params)
{
    size_t len;

    __ASSERT(conn, "invalid parameters\n");
    __ASSERT(params && params->func, "invalid parameters\n");
    __ASSERT(params->handle, "invalid parameters\n");

    if (conn->state != BT_CONN_CONNECTED)
    {
        return -ENOTCONN;
    }

    len = sizeof(struct bt_att_write_req) + params->length;

    /* Use Prepare Write if offset is set or Long Write is required */
    if (params->offset || len > (bt_att_get_mtu(conn) - 1))
    {
        return gatt_prepare_write(conn, params);
    }

    LOG_DBG("handle 0x%04x length %u", params->handle, params->length);

    return gatt_req_send(conn, gatt_write_rsp, params, gatt_write_encode, BT_ATT_OP_WRITE_REQ, len,
                         BT_ATT_CHAN_OPT(params));
}

static void gatt_write_ccc_rsp(struct bt_conn *conn, uint8_t err, const void *pdu, uint16_t length,
                               void *user_data)
{
    struct bt_gatt_subscribe_params *params = user_data;

    LOG_DBG("err 0x%02x", err);

    atomic_clear_bit(params->flags, BT_GATT_SUBSCRIBE_FLAG_WRITE_PENDING);

    /* if write to CCC failed we remove subscription and notify app */
    if (err)
    {
        struct gatt_sub *sub;
        sys_snode_t *node, *tmp;

        sub = gatt_sub_find(conn);
        if (!sub)
        {
            return;
        }

        SYS_SLIST_FOR_EACH_NODE_SAFE (&sub->list, node, tmp)
        {
            if (node == &params->node)
            {
                gatt_sub_remove(conn, sub, tmp, params);
                break;
            }
        }
    }
    else if (!params->value)
    {
        /* Notify with NULL data to complete unsubscribe */
        params->notify(conn, params, NULL, 0);
    }

    if (params->subscribe)
    {
        params->subscribe(conn, err, params);
    }
    else if (params->write)
    {
        /* TODO: Remove after deprecation */
        LOG_WRN("write callback is deprecated, use subscribe cb instead");
        params->write(conn, err, NULL);
    }
}

static int gatt_write_ccc_buf(struct net_buf *buf, size_t len, void *user_data)
{
    struct bt_gatt_subscribe_params *params = user_data;
    struct bt_att_write_req *write_req;

    write_req = net_buf_add(buf, sizeof(*write_req));
    write_req->handle = sys_cpu_to_le16(params->ccc_handle);
    net_buf_add_le16(buf, params->value);

    atomic_set_bit(params->flags, BT_GATT_SUBSCRIBE_FLAG_WRITE_PENDING);

    return 0;
}

static int gatt_write_ccc(struct bt_conn *conn, struct bt_gatt_subscribe_params *params)
{
    size_t len = sizeof(struct bt_att_write_req) + sizeof(uint16_t);

    LOG_DBG("handle 0x%04x value 0x%04x", params->ccc_handle, params->value);

    /* The value of the params doesn't matter, this is just so we don't
     * repeat CCC writes when the AUTO_RESUBSCRIBE quirk is enabled.
     */
    atomic_set_bit(params->flags, BT_GATT_SUBSCRIBE_FLAG_SENT);

    return gatt_req_send(conn, gatt_write_ccc_rsp, params, gatt_write_ccc_buf, BT_ATT_OP_WRITE_REQ,
                         len, BT_ATT_CHAN_OPT(params));
}

#if defined(CONFIG_BT_GATT_AUTO_DISCOVER_CCC)
static uint8_t gatt_ccc_discover_cb(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                    struct bt_gatt_discover_params *params)
{
    struct bt_gatt_subscribe_params *sub_params = params->sub_params;

    if (!attr)
    {
        memset(params, 0, sizeof(*params));
        sub_params->notify(conn, sub_params, NULL, 0);
        return BT_GATT_ITER_STOP;
    }

    if (params->type == BT_GATT_DISCOVER_DESCRIPTOR)
    {
        memset(params, 0, sizeof(*params));
        sub_params->ccc_handle = attr->handle;

        if (bt_gatt_subscribe(conn, sub_params))
        {
            sub_params->notify(conn, sub_params, NULL, 0);
        }
        /* else if no error occurred, then `bt_gatt_subscribe` will
         * call the notify function once subscribed.
         */

        return BT_GATT_ITER_STOP;
    }

    return BT_GATT_ITER_CONTINUE;
}

static int gatt_ccc_discover(struct bt_conn *conn, struct bt_gatt_subscribe_params *params)
{
    int err;
    static struct bt_uuid_16 ccc_uuid = BT_UUID_INIT_16(0);

    memcpy(&ccc_uuid, BT_UUID_GATT_CCC, sizeof(ccc_uuid));
    memset(params->disc_params, 0, sizeof(*params->disc_params));

    params->disc_params->sub_params = params;
    params->disc_params->uuid = &ccc_uuid.uuid;
    params->disc_params->type = BT_GATT_DISCOVER_DESCRIPTOR;
    params->disc_params->start_handle = params->value_handle;
    params->disc_params->end_handle = params->end_handle;
    params->disc_params->func = gatt_ccc_discover_cb;
#if defined(CONFIG_BT_EATT)
    params->disc_params->chan_opt = params->chan_opt;
#endif /* CONFIG_BT_EATT */

    err = bt_gatt_discover(conn, params->disc_params);
    if (err)
    {
        LOG_DBG("CCC Discovery failed (err %d)", err);
        return err;
    }
    return 0;
}
#endif /* CONFIG_BT_GATT_AUTO_DISCOVER_CCC */


void bt_gatt_cancel(struct bt_conn *conn, void *params)
{
    struct bt_att_req *req;
    bt_att_func_t func = NULL;

    // k_sched_lock();

    req = bt_att_find_req_by_user_data(conn, params);
    if (req)
    {
        func = req->func;
        bt_att_req_cancel(conn, req);
    }

    // k_sched_unlock();

    if (func)
    {
        func(conn, BT_ATT_ERR_UNLIKELY, NULL, 0, params);
    }
}

#if defined(CONFIG_BT_GATT_AUTO_UPDATE_MTU)
static void gatt_exchange_mtu_func(struct bt_conn *conn, uint8_t err,
                                   struct bt_gatt_exchange_params *params)
{
    if (err)
    {
        LOG_WRN("conn %p err 0x%02x", conn, err);
    }
}

static struct bt_gatt_exchange_params gatt_exchange_params = {
        .func = gatt_exchange_mtu_func,
};
#endif /* CONFIG_BT_GATT_AUTO_UPDATE_MTU */
#endif /* CONFIG_BT_GATT_CLIENT */

#define CCC_STORE_MAX 48

static struct bt_gatt_ccc_cfg *ccc_find_cfg(struct _bt_gatt_ccc *ccc, const bt_addr_le_t *addr)
{
    for (size_t i = 0; i < ARRAY_SIZE(ccc->cfg); i++)
    {
        if (bt_addr_le_eq(&ccc->cfg[i].peer, addr))
        {
            return &ccc->cfg[i];
        }
    }

    return NULL;
}


void bt_gatt_connected(struct bt_conn *conn)
{
    struct conn_data data;

    LOG_DBG("conn %p", conn);

    data.conn = conn;
    data.sec = BT_SECURITY_L1;

    bt_gatt_foreach_attr(0x0001, 0xffff, update_ccc, &data);

#if 0
    /* BLUETOOTH CORE SPECIFICATION Version 5.1 | Vol 3, Part C page 2192:
     *
     * 10.3.1.1 Handling of GATT indications and notifications
     *
     * A client "requests" a server to send indications and notifications
     * by appropriately configuring the server via a Client Characteristic
     * Configuration Descriptor. Since the configuration is persistent
     * across a disconnection and reconnection, security requirements must
     * be checked against the configuration upon a reconnection before
     * sending indications or notifications. When a server reconnects to a
     * client to send an indication or notification for which security is
     * required, the server shall initiate or request encryption with the
     * client prior to sending an indication or notification. If the client
     * does not have an LTK indicating that the client has lost the bond,
     * enabling encryption will fail.
     */
    if (IS_ENABLED(CONFIG_BT_SMP) &&
        (conn->role == BT_HCI_ROLE_CENTRAL || IS_ENABLED(CONFIG_BT_GATT_AUTO_SEC_REQ)) &&
        bt_conn_get_security(conn) < data.sec)
    {
        int err = bt_conn_set_security(conn, data.sec);

        if (err)
        {
            LOG_WRN("Failed to set security for bonded peer (%d)", err);
        }
    }
#endif

#if defined(CONFIG_BT_GATT_AUTO_UPDATE_MTU)
    int err;

    err = bt_gatt_exchange_mtu(conn, &gatt_exchange_params);
    if (err)
    {
        LOG_WRN("MTU Exchange failed (err %d)", err);
    }
#endif /* CONFIG_BT_GATT_AUTO_UPDATE_MTU */
}

void bt_gatt_att_max_mtu_changed(struct bt_conn *conn, uint16_t tx, uint16_t rx)
{
    struct bt_gatt_cb *cb = gatt_callback;

    if (cb && cb->att_mtu_updated)
    {
        cb->att_mtu_updated(conn, tx, rx);
    }
}

void bt_gatt_encrypt_change(struct bt_conn *conn)
{
    struct conn_data data;

    LOG_DBG("conn %p", conn);

    data.conn = conn;
    data.sec = BT_SECURITY_L1;

    bt_gatt_foreach_attr(0x0001, 0xffff, update_ccc, &data);
}

bool bt_gatt_change_aware(struct bt_conn *conn, bool req)
{
#if defined(CONFIG_BT_GATT_CACHING)
    struct gatt_cf_cfg *cfg;

    cfg = find_cf_cfg(conn);
    if (!cfg || !CF_ROBUST_CACHING(cfg))
    {
        return true;
    }

    if (atomic_test_bit(cfg->flags, CF_CHANGE_AWARE))
    {
        return true;
    }

    /* BLUETOOTH CORE SPECIFICATION Version 5.1 | Vol 3, Part G page 2350:
     * If a change-unaware client sends an ATT command, the server shall
     * ignore it.
     */
    if (!req)
    {
        return false;
    }

    /* BLUETOOTH CORE SPECIFICATION Version 5.3 | Vol 3, Part G page 1475:
     * 2.5.2.1 Robust Caching
     * A change-unaware connected client becomes change-aware when it reads
     * the Database Hash characteristic and then the server receives another
     * ATT request from the client.
     */
    if (atomic_test_and_clear_bit(cfg->flags, CF_DB_HASH_READ))
    {
        bt_att_clear_out_of_sync_sent(conn);
        set_change_aware(cfg, true);
        return true;
    }

    /* BLUETOOTH CORE SPECIFICATION Version 5.3 | Vol 3, Part G page 1476:
     * 2.5.2.1 Robust Caching
     * ... a change-unaware connected client using exactly one ATT bearer
     * becomes change-aware when ...
     * The server sends the client a response with the Error Code parameter
     * set to Database Out Of Sync (0x12) and then the server receives
     * another ATT request from the client.
     */
    if (bt_att_fixed_chan_only(conn) && bt_att_out_of_sync_sent_on_fixed(conn))
    {
        atomic_clear_bit(cfg->flags, CF_DB_HASH_READ);
        bt_att_clear_out_of_sync_sent(conn);
        set_change_aware(cfg, true);
        return true;
    }

    return false;
#else
    return true;
#endif
}

static struct gatt_cf_cfg *find_cf_cfg_by_addr(uint8_t id, const bt_addr_le_t *addr)
{
    return NULL;
}

static uint8_t remove_peer_from_attr(const struct bt_gatt_attr *attr, uint16_t handle,
                                     void *user_data)
{
    const struct bt_addr_le_t *addr = user_data;
    struct _bt_gatt_ccc *ccc;
    struct bt_gatt_ccc_cfg *cfg;

    /* Check if attribute is a CCC */
    if (attr->write != bt_gatt_attr_write_ccc)
    {
        return BT_GATT_ITER_CONTINUE;
    }

    ccc = attr->user_data;

    /* Check if there is a cfg for the peer */
    cfg = ccc_find_cfg(ccc, addr);
    if (cfg)
    {
        memset(cfg, 0, sizeof(*cfg));
    }

    return BT_GATT_ITER_CONTINUE;
}

static int bt_gatt_clear_ccc(uint8_t id, const bt_addr_le_t *addr)
{
    bt_gatt_foreach_attr(0x0001, 0xffff, remove_peer_from_attr, addr);

    return 0;
}

static int bt_gatt_clear_cf(uint8_t id, const bt_addr_le_t *addr)
{
    struct gatt_cf_cfg *cfg;

    // cfg = find_cf_cfg_by_addr(id, addr);
    // if (cfg)
    // {
    //     clear_cf_cfg(cfg);
    // }

    return 0;
}

int bt_gatt_clear(uint8_t id, const bt_addr_le_t *addr)
{
    int err;

    err = bt_gatt_clear_ccc(id, addr);
    if (err < 0)
    {
        return err;
    }

    return 0;
}

void bt_gatt_disconnected(struct bt_conn *conn)
{
    LOG_DBG("conn %p", conn);
    // bt_gatt_foreach_attr(0x0001, 0xffff, disconnected_cb, conn);
}
#endif /* defined(CONFIG_BT_CONN) */