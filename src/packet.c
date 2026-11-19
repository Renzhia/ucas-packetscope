/*
 * packet.c - 数据包存储管理与格式化工具
 */
#include "packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdarg.h>

/* 全局存储 */
packet_store_t g_store;

void store_init(void)
{
    memset(&g_store, 0, sizeof(g_store));
    pthread_mutex_init(&g_store.lock, NULL);
}

void store_clear(void)
{
    pthread_mutex_lock(&g_store.lock);
    for (int i = 0; i < MAX_PACKETS; i++) {
        if (g_store.packets[i].raw) {
            free(g_store.packets[i].raw);
            g_store.packets[i].raw = NULL;
        }
    }
    memset(g_store.packets, 0, sizeof(g_store.packets));
    g_store.count = 0;
    g_store.head  = 0;
    pthread_mutex_unlock(&g_store.lock);
}

int store_add(packet_t *pkt)
{
    pthread_mutex_lock(&g_store.lock);
    int idx = g_store.head;
    packet_t *slot = &g_store.packets[idx];

    /* 释放旧数据 */
    if (slot->raw) {
        free(slot->raw);
    }

    /* 拷贝（浅拷贝 raw 指针所有权转移） */
    *slot = *pkt;
    slot->seq = g_store.count + 1;

    g_store.count++;
    g_store.head = (g_store.head + 1) % MAX_PACKETS;
    pthread_mutex_unlock(&g_store.lock);
    return slot->seq;
}

packet_t *store_get(int logical_index)
{
    if (logical_index < 0 || logical_index >= g_store.count)
        return NULL;

    int total = g_store.count;
    int start;
    if (total <= MAX_PACKETS) {
        start = 0;
    } else {
        start = g_store.head; /* head 指向最旧之后的位置 */
    }
    int phys = (start + logical_index) % MAX_PACKETS;
    return &g_store.packets[phys];
}

int store_visible_count(void)
{
    return g_store.count < MAX_PACKETS ? g_store.count : MAX_PACKETS;
}

/* ---------- 格式化工具 ---------- */

void mac_to_str(const uint8_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, len);
}

void ipv6_to_str(const uint8_t *addr, char *buf, size_t len)
{
    inet_ntop(AF_INET6, addr, buf, len);
}

/* ---------- 字段树工具 ---------- */

void tree_init(packet_t *pkt)
{
    pkt->node_count = 0;
}

int tree_add_node(packet_t *pkt, int parent, const char *name, const char *value)
{
    if (pkt->node_count >= MAX_NODES)
        return -1;
    int idx = pkt->node_count++;
    tree_node_t *n = &pkt->nodes[idx];
    strncpy(n->name, name, NODE_NAME_LEN - 1);
    n->name[NODE_NAME_LEN - 1] = '\0';
    if (value) {
        strncpy(n->value, value, NODE_VAL_LEN - 1);
        n->value[NODE_VAL_LEN - 1] = '\0';
    } else {
        n->value[0] = '\0';
    }
    n->child_count = 0;
    n->first_child = -1;
    n->next_sibling = -1;
    n->parent = (parent >= 0 && parent < pkt->node_count - 1) ? parent : -1;

    if (parent >= 0 && parent < pkt->node_count - 1) {
        tree_node_t *p = &pkt->nodes[parent];
        p->child_count++;
        if (p->first_child < 0) {
            p->first_child = idx;
        } else {
            /* 找到最后一个兄弟 */
            int sib = p->first_child;
            while (pkt->nodes[sib].next_sibling >= 0)
                sib = pkt->nodes[sib].next_sibling;
            pkt->nodes[sib].next_sibling = idx;
        }
    }
    return idx;
}

void tree_add_fmt(packet_t *pkt, int parent, const char *name, const char *fmt, ...)
{
    char value[NODE_VAL_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(value, NODE_VAL_LEN, fmt, ap);
    va_end(ap);
    tree_add_node(pkt, parent, name, value);
}
