/*
 * stream.c - TCP 流重组实现
 *
 * 以四元组(src_ip, src_port, dst_ip, dst_port)标识流，
 * 按 TCP 序号偏移写入重组缓冲，还原完整应用层会话。
 */
#include "stream.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static tcp_stream_t g_streams[MAX_STREAMS];

void stream_init_all(void)
{
    memset(g_streams, 0, sizeof(g_streams));
}

void stream_clear_all(void)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].data) {
            free(g_streams[i].data);
            g_streams[i].data = NULL;
        }
    }
    memset(g_streams, 0, sizeof(g_streams));
}

/* 规范化四元组：使方向一致（小端点为源） */
static void normalize_key(stream_key_t *key)
{
    /* 比较 (src_ip, src_port) 和 (dst_ip, dst_port)，确保 src < dst */
    uint64_t a = ((uint64_t)key->src_ip << 16) | key->src_port;
    uint64_t b = ((uint64_t)key->dst_ip << 16) | key->dst_port;
    if (a > b) {
        uint32_t tmp_ip = key->src_ip;
        uint16_t tmp_port = key->src_port;
        key->src_ip = key->dst_ip;
        key->src_port = key->dst_port;
        key->dst_ip = tmp_ip;
        key->dst_port = tmp_port;
    }
}

int stream_find(const packet_t *pkt)
{
    if (!pkt->is_tcp || !pkt->is_ipv4)
        return -1;

    stream_key_t key;
    key.src_ip   = pkt->ipv4.src;
    key.dst_ip   = pkt->ipv4.dst;
    key.src_port = pkt->tcp.src_port;
    key.dst_port = pkt->tcp.dst_port;
    normalize_key(&key);

    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!g_streams[i].active)
            continue;
        tcp_stream_t *s = &g_streams[i];
        if (s->key.src_ip == key.src_ip &&
            s->key.dst_ip == key.dst_ip &&
            s->key.src_port == key.src_port &&
            s->key.dst_port == key.dst_port)
            return i;
    }
    return -1;
}

static int stream_create(const stream_key_t *key, const char *src_ip, const char *dst_ip)
{
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (!g_streams[i].active) {
            tcp_stream_t *s = &g_streams[i];
            s->key = *key;
            s->active = 1;
            s->have_init_seq = 0;
            s->init_seq = 0;
            s->data_cap = 8192;
            s->data = (uint8_t *)malloc(s->data_cap);
            s->data_len = 0;
            strncpy(s->src_ip_str, src_ip, sizeof(s->src_ip_str) - 1);
            strncpy(s->dst_ip_str, dst_ip, sizeof(s->dst_ip_str) - 1);
            return i;
        }
    }
    return -1;
}

void stream_process_packet(const packet_t *pkt)
{
    if (!pkt->is_tcp || !pkt->is_ipv4)
        return;

    stream_key_t key;
    key.src_ip   = pkt->ipv4.src;
    key.dst_ip   = pkt->ipv4.dst;
    key.src_port = pkt->tcp.src_port;
    key.dst_port = pkt->tcp.dst_port;
    normalize_key(&key);

    int idx = stream_find(pkt);
    tcp_stream_t *s = NULL;

    if (idx < 0) {
        /* SYN 包创建新流 */
        if (pkt->tcp.flags & TCP_SYN) {
            idx = stream_create(&key, pkt->src_addr, pkt->dst_addr);
            if (idx < 0) return;
            s = &g_streams[idx];
            s->init_seq = pkt->tcp.seq;
            s->have_init_seq = 1;
        }
        return;
    }

    s = &g_streams[idx];

    /* SYN 包更新初始序列号 */
    if ((pkt->tcp.flags & TCP_SYN) && !s->have_init_seq) {
        s->init_seq = pkt->tcp.seq;
        s->have_init_seq = 1;
    }

    /* 重组 payload */
    if (pkt->payload && pkt->payload_len > 0 && s->have_init_seq) {
        /* 计算相对偏移 */
        uint32_t rel_seq = pkt->tcp.seq - s->init_seq;
        /* SYN 占一个序号，所以实际数据偏移 = rel_seq - 1 */
        if (rel_seq > 0)
            rel_seq--;

        int offset = (int)rel_seq;
        int end = offset + pkt->payload_len;

        /* 扩容 */
        if (end > s->data_cap) {
            int new_cap = s->data_cap;
            while (new_cap < end && new_cap < MAX_STREAM_DATA)
                new_cap *= 2;
            if (new_cap > MAX_STREAM_DATA)
                new_cap = MAX_STREAM_DATA;
            if (end > new_cap)
                return; /* 超出限制 */
            uint8_t *new_data = (uint8_t *)realloc(s->data, new_cap);
            if (!new_data)
                return;
            /* 填充间隙 */
            if (offset > s->data_len) {
                memset(new_data + s->data_len, 0, offset - s->data_len);
            }
            s->data = new_data;
            s->data_cap = new_cap;
        }

        /* 写入数据 */
        memcpy(s->data + offset, pkt->payload, pkt->payload_len);
        if (end > s->data_len)
            s->data_len = end;
    }
}

int stream_get_active(int *indices, int max)
{
    int count = 0;
    for (int i = 0; i < MAX_STREAMS && count < max; i++) {
        if (g_streams[i].active)
            indices[count++] = i;
    }
    return count;
}

tcp_stream_t *stream_get(int index)
{
    if (index < 0 || index >= MAX_STREAMS)
        return NULL;
    if (!g_streams[index].active)
        return NULL;
    return &g_streams[index];
}
