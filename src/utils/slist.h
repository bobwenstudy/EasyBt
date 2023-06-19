/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 *
 * @brief Single-linked list implementation
 *
 * Single-linked list implementation using inline macros/functions.
 * This API is not thread safe, and thus if a list is used across threads,
 * calls to functions must be protected with synchronization primitives.
 */

#ifndef _ZEPHYR_POLLING_UTILS_SLIST_H_
#define _ZEPHYR_POLLING_UTILS_SLIST_H_

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct _snode
{
    struct _snode *next;
};

typedef struct _snode sys_snode_t;

struct _slist
{
    sys_snode_t *head;
    sys_snode_t *tail;
};

typedef struct _slist sys_slist_t;

/*
 * Required function definitions for the list_gen.h interface
 *
 * These are the only functions that do not treat the list/node pointers
 * as completely opaque types.
 */

/**
 * @brief Initialize a list
 *
 * @param list A pointer on the list to initialize
 */
static inline void sys_slist_init(sys_slist_t *list)
{
    list->head = NULL;
    list->tail = NULL;
}

#define SYS_SLIST_STATIC_INIT(ptr_to_list)                                                         \
    {                                                                                              \
        NULL, NULL                                                                                 \
    }

static inline sys_snode_t *z_snode_next_peek(sys_snode_t *node)
{
    return node->next;
}

static inline void z_snode_next_set(sys_snode_t *parent, sys_snode_t *child)
{
    parent->next = child;
}

static inline void z_slist_head_set(sys_slist_t *list, sys_snode_t *node)
{
    list->head = node;
}

static inline void z_slist_tail_set(sys_slist_t *list, sys_snode_t *node)
{
    list->tail = node;
}

/**
 * @brief Peek the first node from the list
 *
 * @param list A point on the list to peek the first node from
 *
 * @return A pointer on the first node of the list (or NULL if none)
 */
static inline sys_snode_t *sys_slist_peek_head(sys_slist_t *list)
{
    return list->head;
}

/**
 * @brief Peek the last node from the list
 *
 * @param list A point on the list to peek the last node from
 *
 * @return A pointer on the last node of the list (or NULL if none)
 */
static inline sys_snode_t *sys_slist_peek_tail(sys_slist_t *list)
{
    return list->tail;
}

/*
 * Derived, generated APIs
 */

/**
 * @brief Test if the given list is empty
 *
 * @param list A pointer on the list to test
 *
 * @return a boolean, true if it's empty, false otherwise
 */
static inline bool sys_slist_is_empty(sys_slist_t *list)
{
    return (sys_slist_peek_head(list) == NULL);
}

/**
 * @brief Peek the next node from current node, node is not NULL
 *
 * Faster then sys_slist_peek_next() if node is known not to be NULL.
 *
 * @param node A pointer on the node where to peek the next node
 *
 * @return a pointer on the next node (or NULL if none)
 */
static inline sys_snode_t *sys_slist_peek_next_no_check(sys_snode_t *node)
{
    return z_snode_next_peek(node);
}

/**
 * @brief Peek the next node from current node
 *
 * @param node A pointer on the node where to peek the next node
 *
 * @return a pointer on the next node (or NULL if none)
 */
static inline sys_snode_t *sys_slist_peek_next(sys_snode_t *node)
{
    return node != NULL ? sys_slist_peek_next_no_check(node) : NULL;
}

/**
 * @brief Prepend a node to the given list
 *
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 * @param node A pointer on the node to prepend
 */
static inline void sys_slist_prepend(sys_slist_t *list, sys_snode_t *node)
{
    z_snode_next_set(node, sys_slist_peek_head(list));
    z_slist_head_set(list, node);

    if (sys_slist_peek_tail(list) == NULL)
    {
        z_slist_tail_set(list, sys_slist_peek_head(list));
    }
}

/**
 * @brief Append a node to the given list
 *
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 * @param node A pointer on the node to append
 */
static inline void sys_slist_append(sys_slist_t *list, sys_snode_t *node)
{
    z_snode_next_set(node, NULL);

    if (sys_slist_peek_tail(list) == NULL)
    {
        z_slist_tail_set(list, node);
        z_slist_head_set(list, node);
    }
    else
    {
        z_snode_next_set(sys_slist_peek_tail(list), node);
        z_slist_tail_set(list, node);
    }
}

/**
 * @brief Append a list to the given list
 *
 * Append a singly-linked, NULL-terminated list consisting of nodes containing
 * the pointer to the next node as the first element of a node, to @a list.
 * This and other sys_slist_*() functions are not thread safe.
 *
 * FIXME: Why are the element parameters void *?
 *
 * @param list A pointer on the list to affect
 * @param head A pointer to the first element of the list to append
 * @param tail A pointer to the last element of the list to append
 */
static inline void sys_slist_append_list(sys_slist_t *list, void *head, void *tail)
{
    if (sys_slist_peek_tail(list) == NULL)
    {
        z_slist_head_set(list, (sys_snode_t *)head);
    }
    else
    {
        z_snode_next_set(sys_slist_peek_tail(list), (sys_snode_t *)head);
    }
    z_slist_tail_set(list, (sys_snode_t *)tail);
}

/**
 * @brief merge two slists, appending the second one to the first
 *
 * When the operation is completed, the appending list is empty.
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 * @param list_to_append A pointer to the list to append.
 */
static inline void sys_slist_merge_slist(sys_slist_t *list, sys_slist_t *list_to_append)
{
    sys_snode_t *head, *tail;
    head = sys_slist_peek_head(list_to_append);
    tail = sys_slist_peek_tail(list_to_append);
    sys_slist_append_list(list, head, tail);
    sys_slist_init(list_to_append);
}

/**
 * @brief Insert a node to the given list
 *
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 * @param prev A pointer on the previous node
 * @param node A pointer on the node to insert
 */
static inline void sys_slist_insert(sys_slist_t *list, sys_snode_t *prev, sys_snode_t *node)
{
    if (prev == NULL)
    {
        sys_slist_prepend(list, node);
    }
    else if (z_snode_next_peek(prev) == NULL)
    {
        sys_slist_append(list, node);
    }
    else
    {
        z_snode_next_set(node, z_snode_next_peek(prev));
        z_snode_next_set(prev, node);
    }
}

/**
 * @brief Fetch and remove the first node of the given list
 *
 * List must be known to be non-empty.
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 *
 * @return A pointer to the first node of the list
 */
static inline sys_snode_t *sys_slist_get_not_empty(sys_slist_t *list)
{
    sys_snode_t *node = sys_slist_peek_head(list);

    z_slist_head_set(list, z_snode_next_peek(node));
    if (sys_slist_peek_tail(list) == node)
    {
        z_slist_tail_set(list, sys_slist_peek_head(list));
    }

    return node;
}

/**
 * @brief Fetch and remove the first node of the given list
 *
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 *
 * @return A pointer to the first node of the list (or NULL if empty)
 */
static inline sys_snode_t *sys_slist_get(sys_slist_t *list)
{
    return sys_slist_is_empty(list) ? NULL : sys_slist_get_not_empty(list);
}

/**
 * @brief Remove a node
 *
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 * @param prev_node A pointer on the previous node
 *        (can be NULL, which means the node is the list's head)
 * @param node A pointer on the node to remove
 */
static inline void sys_slist_remove(sys_slist_t *list, sys_snode_t *prev_node, sys_snode_t *node)
{
    if (prev_node == NULL)
    {
        z_slist_head_set(list, z_snode_next_peek(node));

        /* Was node also the tail? */
        if (sys_slist_peek_tail(list) == node)
        {
            z_slist_tail_set(list, sys_slist_peek_head(list));
        }
    }
    else
    {
        z_snode_next_set(prev_node, z_snode_next_peek(node));

        /* Was node the tail? */
        if (sys_slist_peek_tail(list) == node)
        {
            z_slist_tail_set(list, prev_node);
        }
    }

    z_snode_next_set(node, NULL);
}

/**
 * @brief Find and remove a node from a list
 *
 * This and other sys_slist_*() functions are not thread safe.
 *
 * @param list A pointer on the list to affect
 * @param node A pointer on the node to remove from the list
 *
 * @return true if node was removed
 */
static inline bool sys_slist_find_and_remove(sys_slist_t *list, sys_snode_t *node)
{
    sys_snode_t *prev = NULL;
    sys_snode_t *test;

    for (test = sys_slist_peek_head(list); test != NULL; test = sys_slist_peek_next(test))
    {
        if (test == node)
        {
            sys_slist_remove(list, prev, node);
            return true;
        }

        prev = test;
    }

    return false;
}

/**
 * @brief get list size
 *
 * @param list A pointer on the list to affect
 *
 * @return the list size
 */
static inline int sys_slist_size(sys_slist_t *list)
{
    int cnt = 0;
    sys_snode_t *test;

    for (test = sys_slist_peek_head(list); test != NULL; test = sys_slist_peek_next(test))
    {
        cnt++;
    }

    return cnt;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEPHYR_POLLING_UTILS_SLIST_H_ */