/** @file
 *  @brief Buffer management.
 */

/*
 * Copyright (c) 2015 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ZEPHYR_POLLING_COMMON_NET_BUF_H_
#define _ZEPHYR_POLLING_COMMON_NET_BUF_H_

#include <stddef.h>

#include "bt_config.h"

#include "base/types.h"
#include "base/gcc.h"
#include "base/util.h"

#include "utils/slist.h"
#include "utils/spool.h"

#ifndef CONFIG_NET_BUF_USER_DATA_SIZE
#define CONFIG_NET_BUF_USER_DATA_SIZE 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Network buffer library
 * @defgroup net_buf Network Buffer Library
 * @ingroup networking
 * @{
 */

/* Alignment needed for various parts of the buffer definition */
#define __net_buf_align __aligned(sizeof(void *))

/**
 *  @def NET_BUF_SIMPLE_DEFINE
 *  @brief Define a net_buf_simple stack variable.
 *
 *  This is a helper macro which is used to define a net_buf_simple object
 *  on the stack.
 *
 *  @param _name Name of the net_buf_simple object.
 *  @param _size Maximum data storage for the buffer.
 */
#define NET_BUF_SIMPLE_DEFINE(_name, _size)                                                        \
    uint8_t net_buf_data_##_name[_size];                                                           \
    struct net_buf_simple _name = {                                                                \
            .data = net_buf_data_##_name,                                                          \
            .len = 0,                                                                              \
            .size = _size,                                                                         \
            .__buf = net_buf_data_##_name,                                                         \
    }

/**
 * @def NET_BUF_SIMPLE_DEFINE_STATIC
 * @brief Define a static net_buf_simple variable.
 *
 * This is a helper macro which is used to define a static net_buf_simple
 * object.
 *
 * @param _name Name of the net_buf_simple object.
 * @param _size Maximum data storage for the buffer.
 */
#define NET_BUF_SIMPLE_DEFINE_STATIC(_name, _size)                                                 \
    static __noinit uint8_t net_buf_data_##_name[_size];                                           \
    static struct net_buf_simple _name = {                                                         \
            .data = net_buf_data_##_name,                                                          \
            .len = 0,                                                                              \
            .size = _size,                                                                         \
            .__buf = net_buf_data_##_name,                                                         \
    }

/**
 * @brief Simple network buffer representation.
 *
 * This is a simpler variant of the net_buf object (in fact net_buf uses
 * net_buf_simple internally). It doesn't provide any kind of reference
 * counting, user data, dynamic allocation, or in general the ability to
 * pass through kernel objects such as FIFOs.
 *
 * The main use of this is for scenarios where the meta-data of the normal
 * net_buf isn't needed and causes too much overhead. This could be e.g.
 * when the buffer only needs to be allocated on the stack or when the
 * access to and lifetime of the buffer is well controlled and constrained.
 */
struct net_buf_simple
{
    /** Pointer to the start of data in the buffer. */
    uint8_t *data;

    /** Length of the data behind the data pointer. */
    uint16_t len;

    /** Amount of data that this buffer can store. */
    uint16_t size;

    /** Start of the data storage. Not to be accessed directly
     *  (the data pointer should be used instead).
     */
    uint8_t *__buf;
};

/**
 * @def NET_BUF_SIMPLE
 * @brief Define a net_buf_simple stack variable and get a pointer to it.
 *
 * This is a helper macro which is used to define a net_buf_simple object on
 * the stack and the get a pointer to it as follows:
 *
 * struct net_buf_simple *my_buf = NET_BUF_SIMPLE(10);
 *
 * After creating the object it needs to be initialized by calling
 * net_buf_simple_init().
 *
 * @param _size Maximum data storage for the buffer.
 *
 * @return Pointer to stack-allocated net_buf_simple object.
 */
#define NET_BUF_SIMPLE(_size)                                                                      \
    ((struct net_buf_simple *)(&(struct {                                                          \
        struct net_buf_simple buf;                                                                 \
        uint8_t data[_size];                                                                       \
    }){                                                                                            \
            .buf.size = _size,                                                                     \
    }))

/**
 * @brief Initialize a net_buf_simple object.
 *
 * This needs to be called after creating a net_buf_simple object using
 * the NET_BUF_SIMPLE macro.
 *
 * @param buf Buffer to initialize.
 * @param reserve_head Headroom to reserve.
 */
static inline void net_buf_simple_init(struct net_buf_simple *buf, size_t reserve_head)
{
    if (!buf->__buf)
    {
        buf->__buf = (uint8_t *)buf + sizeof(*buf);
    }

    buf->data = buf->__buf + reserve_head;
    buf->len = 0U;
}

/**
 * @brief Initialize a net_buf_simple object with data.
 *
 * Initialized buffer object with external data.
 *
 * @param buf Buffer to initialize.
 * @param data External data pointer
 * @param size Amount of data the pointed data buffer if able to fit.
 */
void net_buf_simple_init_with_data(struct net_buf_simple *buf, void *data, size_t size);

/**
 * @brief Reset buffer
 *
 * Reset buffer data so it can be reused for other purposes.
 *
 * @param buf Buffer to reset.
 */
static inline void net_buf_simple_reset(struct net_buf_simple *buf)
{
    buf->len = 0U;
    buf->data = buf->__buf;
}

/**
 * Clone buffer state, using the same data buffer.
 *
 * Initializes a buffer to point to the same data as an existing buffer.
 * Allows operations on the same data without altering the length and
 * offset of the original.
 *
 * @param original Buffer to clone.
 * @param clone The new clone.
 */
void net_buf_simple_clone(const struct net_buf_simple *original, struct net_buf_simple *clone);

/**
 * @brief Prepare data to be added at the end of the buffer
 *
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to increment the length with.
 *
 * @return The original tail of the buffer.
 */
void *net_buf_simple_add(struct net_buf_simple *buf, size_t len);

/**
 * @brief Copy given number of bytes from memory to the end of the buffer
 *
 * Increments the data length of the  buffer to account for more data at the
 * end.
 *
 * @param buf Buffer to update.
 * @param mem Location of data to be added.
 * @param len Length of data to be added
 *
 * @return The original tail of the buffer.
 */
void *net_buf_simple_add_mem(struct net_buf_simple *buf, const void *mem, size_t len);

/**
 * @brief Add (8-bit) byte at the end of the buffer
 *
 * Increments the data length of the  buffer to account for more data at the
 * end.
 *
 * @param buf Buffer to update.
 * @param val byte value to be added.
 *
 * @return Pointer to the value added
 */
uint8_t *net_buf_simple_add_u8(struct net_buf_simple *buf, uint8_t val);

/**
 * @brief Add 16-bit value at the end of the buffer
 *
 * Adds 16-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be added.
 */
void net_buf_simple_add_le16(struct net_buf_simple *buf, uint16_t val);

/**
 * @brief Add 16-bit value at the end of the buffer
 *
 * Adds 16-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be added.
 */
void net_buf_simple_add_be16(struct net_buf_simple *buf, uint16_t val);

/**
 * @brief Add 24-bit value at the end of the buffer
 *
 * Adds 24-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be added.
 */
void net_buf_simple_add_le24(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Add 24-bit value at the end of the buffer
 *
 * Adds 24-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be added.
 */
void net_buf_simple_add_be24(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Add 32-bit value at the end of the buffer
 *
 * Adds 32-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be added.
 */
void net_buf_simple_add_le32(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Add 32-bit value at the end of the buffer
 *
 * Adds 32-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be added.
 */
void net_buf_simple_add_be32(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Add 48-bit value at the end of the buffer
 *
 * Adds 48-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be added.
 */
void net_buf_simple_add_le48(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Add 48-bit value at the end of the buffer
 *
 * Adds 48-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be added.
 */
void net_buf_simple_add_be48(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Add 64-bit value at the end of the buffer
 *
 * Adds 64-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be added.
 */
void net_buf_simple_add_le64(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Add 64-bit value at the end of the buffer
 *
 * Adds 64-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be added.
 */
void net_buf_simple_add_be64(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Push data to the beginning of the buffer.
 *
 * Modifies the data pointer and buffer length to account for more data
 * in the beginning of the buffer.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to add to the beginning.
 *
 * @return The new beginning of the buffer data.
 */
void *net_buf_simple_push(struct net_buf_simple *buf, size_t len);

/**
 * @brief Push 16-bit value to the beginning of the buffer
 *
 * Adds 16-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_le16(struct net_buf_simple *buf, uint16_t val);

/**
 * @brief Push 16-bit value to the beginning of the buffer
 *
 * Adds 16-bit value in big endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_be16(struct net_buf_simple *buf, uint16_t val);

/**
 * @brief Push 8-bit value to the beginning of the buffer
 *
 * Adds 8-bit value the beginning of the buffer.
 *
 * @param buf Buffer to update.
 * @param val 8-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_u8(struct net_buf_simple *buf, uint8_t val);

/**
 * @brief Push 24-bit value to the beginning of the buffer
 *
 * Adds 24-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_le24(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Push 24-bit value to the beginning of the buffer
 *
 * Adds 24-bit value in big endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_be24(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Push 32-bit value to the beginning of the buffer
 *
 * Adds 32-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_le32(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Push 32-bit value to the beginning of the buffer
 *
 * Adds 32-bit value in big endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_be32(struct net_buf_simple *buf, uint32_t val);

/**
 * @brief Push 48-bit value to the beginning of the buffer
 *
 * Adds 48-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_le48(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Push 48-bit value to the beginning of the buffer
 *
 * Adds 48-bit value in big endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_be48(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Push 64-bit value to the beginning of the buffer
 *
 * Adds 64-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_le64(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Push 64-bit value to the beginning of the buffer
 *
 * Adds 64-bit value in big endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be pushed to the buffer.
 */
void net_buf_simple_push_be64(struct net_buf_simple *buf, uint64_t val);

/**
 * @brief Remove data from the beginning of the buffer.
 *
 * Removes data from the beginning of the buffer by modifying the data
 * pointer and buffer length.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to remove.
 *
 * @return New beginning of the buffer data.
 */
void *net_buf_simple_pull(struct net_buf_simple *buf, size_t len);

/**
 * @brief Remove data from the beginning of the buffer.
 *
 * Removes data from the beginning of the buffer by modifying the data
 * pointer and buffer length.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to remove.
 *
 * @return Pointer to the old location of the buffer data.
 */
void *net_buf_simple_pull_mem(struct net_buf_simple *buf, size_t len);

/**
 * @brief Remove a 8-bit value from the beginning of the buffer
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 8-bit values.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return The 8-bit removed value
 */
uint8_t net_buf_simple_pull_u8(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 16 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 16-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 16-bit value converted from little endian to host endian.
 */
uint16_t net_buf_simple_pull_le16(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 16 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 16-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 16-bit value converted from big endian to host endian.
 */
uint16_t net_buf_simple_pull_be16(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 24 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 24-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 24-bit value converted from little endian to host endian.
 */
uint32_t net_buf_simple_pull_le24(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 24 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 24-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 24-bit value converted from big endian to host endian.
 */
uint32_t net_buf_simple_pull_be24(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 32 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 32-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 32-bit value converted from little endian to host endian.
 */
uint32_t net_buf_simple_pull_le32(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 32 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 32-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 32-bit value converted from big endian to host endian.
 */
uint32_t net_buf_simple_pull_be32(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 48 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 48-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 48-bit value converted from little endian to host endian.
 */
uint64_t net_buf_simple_pull_le48(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 48 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 48-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 48-bit value converted from big endian to host endian.
 */
uint64_t net_buf_simple_pull_be48(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 64 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 64-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 64-bit value converted from little endian to host endian.
 */
uint64_t net_buf_simple_pull_le64(struct net_buf_simple *buf);

/**
 * @brief Remove and convert 64 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_simple_pull(), but a helper for operating
 * on 64-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 64-bit value converted from big endian to host endian.
 */
uint64_t net_buf_simple_pull_be64(struct net_buf_simple *buf);

/**
 * @brief Get the tail pointer for a buffer.
 *
 * Get a pointer to the end of the data in a buffer.
 *
 * @param buf Buffer.
 *
 * @return Tail pointer for the buffer.
 */
static inline uint8_t *net_buf_simple_tail(struct net_buf_simple *buf)
{
    return buf->data + buf->len;
}

/**
 * @brief Check buffer headroom.
 *
 * Check how much free space there is in the beginning of the buffer.
 *
 * buf A valid pointer on a buffer
 *
 * @return Number of bytes available in the beginning of the buffer.
 */
size_t net_buf_simple_headroom(struct net_buf_simple *buf);

/**
 * @brief Check buffer tailroom.
 *
 * Check how much free space there is at the end of the buffer.
 *
 * @param buf A valid pointer on a buffer
 *
 * @return Number of bytes available at the end of the buffer.
 */
size_t net_buf_simple_tailroom(struct net_buf_simple *buf);

/**
 * @brief Parsing state of a buffer.
 *
 * This is used for temporarily storing the parsing state of a buffer
 * while giving control of the parsing to a routine which we don't
 * control.
 */
struct net_buf_simple_state
{
    /** Offset of the data pointer from the beginning of the storage */
    uint16_t offset;
    /** Length of data */
    uint16_t len;
};

/**
 * @brief Save the parsing state of a buffer.
 *
 * Saves the parsing state of a buffer so it can be restored later.
 *
 * @param buf Buffer from which the state should be saved.
 * @param state Storage for the state.
 */
static inline void net_buf_simple_save(struct net_buf_simple *buf,
                                       struct net_buf_simple_state *state)
{
    state->offset = net_buf_simple_headroom(buf);
    state->len = buf->len;
}

/**
 * @brief Restore the parsing state of a buffer.
 *
 * Restores the parsing state of a buffer from a state previously stored
 * by net_buf_simple_save().
 *
 * @param buf Buffer to which the state should be restored.
 * @param state Stored state.
 */
static inline void net_buf_simple_restore(struct net_buf_simple *buf,
                                          struct net_buf_simple_state *state)
{
    buf->data = buf->__buf + state->offset;
    buf->len = state->len;
}

/**
 * Flag indicating that the buffer has associated fragments. Only used
 * internally by the buffer handling code while the buffer is inside a
 * FIFO, meaning this never needs to be explicitly set or unset by the
 * net_buf API user. As long as the buffer is outside of a FIFO, i.e.
 * in practice always for the user for this API, the buf->frags pointer
 * should be used instead.
 */
#define NET_BUF_FRAGS         BIT(0)
/**
 * Flag indicating that the buffer's associated data pointer, points to
 * externally allocated memory. Therefore once ref goes down to zero, the
 * pointed data will not need to be deallocated. This never needs to be
 * explicitly set or unet by the net_buf API user. Such net_buf is
 * exclusively instantiated via net_buf_alloc_with_data() function.
 * Reference count mechanism however will behave the same way, and ref
 * count going to 0 will free the net_buf but no the data pointer in it.
 */
#define NET_BUF_EXTERNAL_DATA BIT(1)

/**
 * @brief Network buffer representation.
 *
 * This struct is used to represent network buffers. Such buffers are
 * normally defined through the NET_BUF_POOL_*_DEFINE() APIs and allocated
 * using the net_buf_alloc() API.
 */
struct net_buf
{
    union
    {
        /** Allow placing the buffer into sys_slist_t */
        sys_snode_t node;

        /** Fragments associated with this buffer. */
        struct net_buf *frags;
    };

    /** Bit-field of buffer flags. */
    uint8_t flags;

    /** Buffer type. */
    uint8_t type;

    /** Reference count. */
    uint8_t ref;

    /** Where the buffer should go when freed up. */
    struct spool *pool_id;

    /* Union for convenience access to the net_buf_simple members, also
     * preserving the old API.
     */
    union
    {
        /* The ABI of this struct must match net_buf_simple */
        struct
        {
            /** Pointer to the start of data in the buffer. */
            uint8_t *data;

            /** Length of the data behind the data pointer. */
            uint16_t len;

            /** Amount of data that this buffer can store. */
            uint16_t size;

            /** Start of the data storage. Not to be accessed
             *  directly (the data pointer should be used
             *  instead).
             */
            uint8_t *__buf;
        };

        struct net_buf_simple b;
    };

    /** System metadata for this buffer. */
    uint8_t user_data[] __net_buf_align;
};

struct net_buf *net_buf_alloc(struct spool *pool);

/**
 * @brief Destroy buffer from custom destroy callback
 *
 * This helper is only intended to be used from custom destroy callbacks.
 * If no custom destroy callback is given to NET_BUF_POOL_*_DEFINE() then
 * there is no need to use this API.
 *
 * @param buf Buffer to destroy.
 */
static inline void net_buf_destroy(struct net_buf *buf)
{
    struct spool *pool = buf->pool_id;

    spool_enqueue(pool, buf);
}

/**
 * @brief Reset buffer
 *
 * Reset buffer data and flags so it can be reused for other purposes.
 *
 * @param buf Buffer to reset.
 */
void net_buf_reset(struct net_buf *buf);

/**
 * @brief Initialize buffer with the given headroom.
 *
 * The buffer is not expected to contain any data when this API is called.
 *
 * @param buf Buffer to initialize.
 * @param reserve How much headroom to reserve.
 */
void net_buf_simple_reserve(struct net_buf_simple *buf, size_t reserve);

/**
 * @brief Put a buffer into a list
 *
 * If the buffer contains follow-up fragments this function will take care of
 * inserting them as well into the list.
 *
 * @param list Which list to append the buffer to.
 * @param buf Buffer.
 */
void net_buf_slist_put(sys_slist_t *list, struct net_buf *buf);

/**
 * @brief Get a buffer from a list.
 *
 * If the buffer had any fragments, these will automatically be recovered from
 * the list as well and be placed to the buffer's fragment list.
 *
 * @param list Which list to take the buffer from.
 *
 * @return New buffer or NULL if the FIFO is empty.
 */
struct net_buf *net_buf_slist_get(sys_slist_t *list);


/**
 * @def net_buf_reserve
 * @brief Initialize buffer with the given headroom.
 *
 * The buffer is not expected to contain any data when this API is called.
 *
 * @param buf Buffer to initialize.
 * @param reserve How much headroom to reserve.
 */
#define net_buf_reserve(buf, reserve) net_buf_simple_reserve(&(buf)->b, reserve)

/**
 * @def net_buf_add
 * @brief Prepare data to be added at the end of the buffer
 *
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to increment the length with.
 *
 * @return The original tail of the buffer.
 */
#define net_buf_add(buf, len) net_buf_simple_add(&(buf)->b, len)

/**
 * @def net_buf_add_mem
 * @brief Copies the given number of bytes to the end of the buffer
 *
 * Increments the data length of the  buffer to account for more data at
 * the end.
 *
 * @param buf Buffer to update.
 * @param mem Location of data to be added.
 * @param len Length of data to be added
 *
 * @return The original tail of the buffer.
 */
#define net_buf_add_mem(buf, mem, len) net_buf_simple_add_mem(&(buf)->b, mem, len)

/**
 * @def net_buf_add_u8
 * @brief Add (8-bit) byte at the end of the buffer
 *
 * Increments the data length of the  buffer to account for more data at
 * the end.
 *
 * @param buf Buffer to update.
 * @param val byte value to be added.
 *
 * @return Pointer to the value added
 */
#define net_buf_add_u8(buf, val) net_buf_simple_add_u8(&(buf)->b, val)

/**
 * @def net_buf_add_le16
 * @brief Add 16-bit value at the end of the buffer
 *
 * Adds 16-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be added.
 */
#define net_buf_add_le16(buf, val) net_buf_simple_add_le16(&(buf)->b, val)

/**
 * @def net_buf_add_be16
 * @brief Add 16-bit value at the end of the buffer
 *
 * Adds 16-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be added.
 */
#define net_buf_add_be16(buf, val) net_buf_simple_add_be16(&(buf)->b, val)

/**
 * @def net_buf_add_le24
 * @brief Add 24-bit value at the end of the buffer
 *
 * Adds 24-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be added.
 */
#define net_buf_add_le24(buf, val) net_buf_simple_add_le24(&(buf)->b, val)

/**
 * @def net_buf_add_be24
 * @brief Add 24-bit value at the end of the buffer
 *
 * Adds 24-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be added.
 */
#define net_buf_add_be24(buf, val) net_buf_simple_add_be24(&(buf)->b, val)

/**
 * @def net_buf_add_le32
 * @brief Add 32-bit value at the end of the buffer
 *
 * Adds 32-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be added.
 */
#define net_buf_add_le32(buf, val) net_buf_simple_add_le32(&(buf)->b, val)

/**
 * @def net_buf_add_be32
 * @brief Add 32-bit value at the end of the buffer
 *
 * Adds 32-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be added.
 */
#define net_buf_add_be32(buf, val) net_buf_simple_add_be32(&(buf)->b, val)

/**
 * @def net_buf_add_le48
 * @brief Add 48-bit value at the end of the buffer
 *
 * Adds 48-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be added.
 */
#define net_buf_add_le48(buf, val) net_buf_simple_add_le48(&(buf)->b, val)

/**
 * @def net_buf_add_be48
 * @brief Add 48-bit value at the end of the buffer
 *
 * Adds 48-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be added.
 */
#define net_buf_add_be48(buf, val) net_buf_simple_add_be48(&(buf)->b, val)

/**
 * @def net_buf_add_le64
 * @brief Add 64-bit value at the end of the buffer
 *
 * Adds 64-bit value in little endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be added.
 */
#define net_buf_add_le64(buf, val) net_buf_simple_add_le64(&(buf)->b, val)

/**
 * @def net_buf_add_be64
 * @brief Add 64-bit value at the end of the buffer
 *
 * Adds 64-bit value in big endian format at the end of buffer.
 * Increments the data length of a buffer to account for more data
 * at the end.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be added.
 */
#define net_buf_add_be64(buf, val) net_buf_simple_add_be64(&(buf)->b, val)

/**
 * @def net_buf_push
 * @brief Push data to the beginning of the buffer.
 *
 * Modifies the data pointer and buffer length to account for more data
 * in the beginning of the buffer.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to add to the beginning.
 *
 * @return The new beginning of the buffer data.
 */
#define net_buf_push(buf, len) net_buf_simple_push(&(buf)->b, len)

/**
 * @def net_buf_push_le16
 * @brief Push 16-bit value to the beginning of the buffer
 *
 * Adds 16-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be pushed to the buffer.
 */
#define net_buf_push_le16(buf, val) net_buf_simple_push_le16(&(buf)->b, val)

/**
 * @def net_buf_push_be16
 * @brief Push 16-bit value to the beginning of the buffer
 *
 * Adds 16-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 16-bit value to be pushed to the buffer.
 */
#define net_buf_push_be16(buf, val) net_buf_simple_push_be16(&(buf)->b, val)

/**
 * @def net_buf_push_u8
 * @brief Push 8-bit value to the beginning of the buffer
 *
 * Adds 8-bit value the beginning of the buffer.
 *
 * @param buf Buffer to update.
 * @param val 8-bit value to be pushed to the buffer.
 */
#define net_buf_push_u8(buf, val) net_buf_simple_push_u8(&(buf)->b, val)

/**
 * @def net_buf_push_le24
 * @brief Push 24-bit value to the beginning of the buffer
 *
 * Adds 24-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be pushed to the buffer.
 */
#define net_buf_push_le24(buf, val) net_buf_simple_push_le24(&(buf)->b, val)

/**
 * @def net_buf_push_be24
 * @brief Push 24-bit value to the beginning of the buffer
 *
 * Adds 24-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 24-bit value to be pushed to the buffer.
 */
#define net_buf_push_be24(buf, val) net_buf_simple_push_be24(&(buf)->b, val)

/**
 * @def net_buf_push_le32
 * @brief Push 32-bit value to the beginning of the buffer
 *
 * Adds 32-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be pushed to the buffer.
 */
#define net_buf_push_le32(buf, val) net_buf_simple_push_le32(&(buf)->b, val)

/**
 * @def net_buf_push_be32
 * @brief Push 32-bit value to the beginning of the buffer
 *
 * Adds 32-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 32-bit value to be pushed to the buffer.
 */
#define net_buf_push_be32(buf, val) net_buf_simple_push_be32(&(buf)->b, val)

/**
 * @def net_buf_push_le48
 * @brief Push 48-bit value to the beginning of the buffer
 *
 * Adds 48-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be pushed to the buffer.
 */
#define net_buf_push_le48(buf, val) net_buf_simple_push_le48(&(buf)->b, val)

/**
 * @def net_buf_push_be48
 * @brief Push 48-bit value to the beginning of the buffer
 *
 * Adds 48-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 48-bit value to be pushed to the buffer.
 */
#define net_buf_push_be48(buf, val) net_buf_simple_push_be48(&(buf)->b, val)

/**
 * @def net_buf_push_le64
 * @brief Push 64-bit value to the beginning of the buffer
 *
 * Adds 64-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be pushed to the buffer.
 */
#define net_buf_push_le64(buf, val) net_buf_simple_push_le64(&(buf)->b, val)

/**
 * @def net_buf_push_be64
 * @brief Push 64-bit value to the beginning of the buffer
 *
 * Adds 64-bit value in little endian format to the beginning of the
 * buffer.
 *
 * @param buf Buffer to update.
 * @param val 64-bit value to be pushed to the buffer.
 */
#define net_buf_push_be64(buf, val) net_buf_simple_push_be64(&(buf)->b, val)

/**
 * @def net_buf_pull
 * @brief Remove data from the beginning of the buffer.
 *
 * Removes data from the beginning of the buffer by modifying the data
 * pointer and buffer length.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to remove.
 *
 * @return New beginning of the buffer data.
 */
#define net_buf_pull(buf, len) net_buf_simple_pull(&(buf)->b, len)

/**
 * @def net_buf_pull_mem
 * @brief Remove data from the beginning of the buffer.
 *
 * Removes data from the beginning of the buffer by modifying the data
 * pointer and buffer length.
 *
 * @param buf Buffer to update.
 * @param len Number of bytes to remove.
 *
 * @return Pointer to the old beginning of the buffer data.
 */
#define net_buf_pull_mem(buf, len) net_buf_simple_pull_mem(&(buf)->b, len)

/**
 * @def net_buf_pull_u8
 * @brief Remove a 8-bit value from the beginning of the buffer
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 8-bit values.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return The 8-bit removed value
 */
#define net_buf_pull_u8(buf) net_buf_simple_pull_u8(&(buf)->b)

/**
 * @def net_buf_pull_le16
 * @brief Remove and convert 16 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 16-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 16-bit value converted from little endian to host endian.
 */
#define net_buf_pull_le16(buf) net_buf_simple_pull_le16(&(buf)->b)

/**
 * @def net_buf_pull_be16
 * @brief Remove and convert 16 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 16-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 16-bit value converted from big endian to host endian.
 */
#define net_buf_pull_be16(buf) net_buf_simple_pull_be16(&(buf)->b)

/**
 * @def net_buf_pull_le24
 * @brief Remove and convert 24 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 24-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 24-bit value converted from little endian to host endian.
 */
#define net_buf_pull_le24(buf) net_buf_simple_pull_le24(&(buf)->b)

/**
 * @def net_buf_pull_be24
 * @brief Remove and convert 24 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 24-bit big endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 24-bit value converted from big endian to host endian.
 */
#define net_buf_pull_be24(buf) net_buf_simple_pull_be24(&(buf)->b)

/**
 * @def net_buf_pull_le32
 * @brief Remove and convert 32 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 32-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 32-bit value converted from little endian to host endian.
 */
#define net_buf_pull_le32(buf) net_buf_simple_pull_le32(&(buf)->b)

/**
 * @def net_buf_pull_be32
 * @brief Remove and convert 32 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 32-bit big endian data.
 *
 * @param buf A valid pointer on a buffer
 *
 * @return 32-bit value converted from big endian to host endian.
 */
#define net_buf_pull_be32(buf) net_buf_simple_pull_be32(&(buf)->b)

/**
 * @def net_buf_pull_le48
 * @brief Remove and convert 48 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 48-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 48-bit value converted from little endian to host endian.
 */
#define net_buf_pull_le48(buf) net_buf_simple_pull_le48(&(buf)->b)

/**
 * @def net_buf_pull_be48
 * @brief Remove and convert 48 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 48-bit big endian data.
 *
 * @param buf A valid pointer on a buffer
 *
 * @return 48-bit value converted from big endian to host endian.
 */
#define net_buf_pull_be48(buf) net_buf_simple_pull_be48(&(buf)->b)

/**
 * @def net_buf_pull_le64
 * @brief Remove and convert 64 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 64-bit little endian data.
 *
 * @param buf A valid pointer on a buffer.
 *
 * @return 64-bit value converted from little endian to host endian.
 */
#define net_buf_pull_le64(buf) net_buf_simple_pull_le64(&(buf)->b)

/**
 * @def net_buf_pull_be64
 * @brief Remove and convert 64 bits from the beginning of the buffer.
 *
 * Same idea as with net_buf_pull(), but a helper for operating on
 * 64-bit big endian data.
 *
 * @param buf A valid pointer on a buffer
 *
 * @return 64-bit value converted from big endian to host endian.
 */
#define net_buf_pull_be64(buf) net_buf_simple_pull_be64(&(buf)->b)

/**
 * @def net_buf_tailroom
 * @brief Check buffer tailroom.
 *
 * Check how much free space there is at the end of the buffer.
 *
 * @param buf A valid pointer on a buffer
 *
 * @return Number of bytes available at the end of the buffer.
 */
#define net_buf_tailroom(buf) net_buf_simple_tailroom(&(buf)->b)

/**
 * @def net_buf_headroom
 * @brief Check buffer headroom.
 *
 * Check how much free space there is in the beginning of the buffer.
 *
 * buf A valid pointer on a buffer
 *
 * @return Number of bytes available in the beginning of the buffer.
 */
#define net_buf_headroom(buf) net_buf_simple_headroom(&(buf)->b)

/**
 * @def net_buf_tail
 * @brief Get the tail pointer for a buffer.
 *
 * Get a pointer to the end of the data in a buffer.
 *
 * @param buf Buffer.
 *
 * @return Tail pointer for the buffer.
 */
#define net_buf_tail(buf) net_buf_simple_tail(&(buf)->b)

/**
 * @brief Find the last fragment in the fragment list.
 *
 * @return Pointer to last fragment in the list.
 */
struct net_buf *net_buf_frag_last(struct net_buf *frags);

/**
 * @brief Insert a new fragment to a chain of bufs.
 *
 * Insert a new fragment into the buffer fragments list after the parent.
 *
 * Note: This function takes ownership of the fragment reference so the
 * caller is not required to unref.
 *
 * @param parent Parent buffer/fragment.
 * @param frag Fragment to insert.
 */
void net_buf_frag_insert(struct net_buf *parent, struct net_buf *frag);

/**
 * @brief Add a new fragment to the end of a chain of bufs.
 *
 * Append a new fragment into the buffer fragments list.
 *
 * Note: This function takes ownership of the fragment reference so the
 * caller is not required to unref.
 *
 * @param head Head of the fragment chain.
 * @param frag Fragment to add.
 *
 * @return New head of the fragment chain. Either head (if head
 *         was non-NULL) or frag (if head was NULL).
 */
struct net_buf *net_buf_frag_add(struct net_buf *head, struct net_buf *frag);

/**
 * @brief Delete existing fragment from a chain of bufs.
 *
 * @param parent Parent buffer/fragment, or NULL if there is no parent.
 * @param frag Fragment to delete.
 *
 * @return Pointer to the buffer following the fragment, or NULL if it
 *         had no further fragments.
 */
struct net_buf *net_buf_frag_del(struct net_buf *parent, struct net_buf *frag);

/**
 * @brief Skip N number of bytes in a net_buf
 *
 * @details Skip N number of bytes starting from fragment's offset. If the total
 * length of data is placed in multiple fragments, this function will skip from
 * all fragments until it reaches N number of bytes.  Any fully skipped buffers
 * are removed from the net_buf list.
 *
 * @param buf Network buffer.
 * @param len Total length of data to be skipped.
 *
 * @return Pointer to the fragment or
 *         NULL and pos is 0 after successful skip,
 *         NULL and pos is 0xffff otherwise.
 */
static inline struct net_buf *net_buf_skip(struct net_buf *buf, size_t len)
{
    while (buf && len--)
    {
        net_buf_pull_u8(buf);
        if (!buf->len)
        {
            buf = net_buf_frag_del(NULL, buf);
        }
    }

    return buf;
}

/**
 * @brief Calculate amount of bytes stored in fragments.
 *
 * Calculates the total amount of data stored in the given buffer and the
 * fragments linked to it.
 *
 * @param buf Buffer to start off with.
 *
 * @return Number of bytes in the buffer and its fragments.
 */
static inline size_t net_buf_frags_len(struct net_buf *buf)
{
    size_t bytes = 0;

    while (buf)
    {
        bytes += buf->len;
        buf = buf->frags;
    }

    return bytes;
}

bool net_buf_check_empty(struct spool *pool);

void net_buf_unref(struct net_buf *buf);
/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _ZEPHYR_POLLING_COMMON_NET_BUF_H_ */