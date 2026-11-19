/*
 * stream.h - TCP 流重组（加分项）
 */
#ifndef STREAM_H
#define STREAM_H

#include "packet.h"

#define MAX_STREAMS 256
#define MAX_STREAM_DATA (256 * 1024)  /* 每流最多保存 256KB 重组数据 */

/* 流标识四元组 */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} stream_key_t;

/* 单个 TCP 流 */
typedef struct {
    stream_key_t key;
    int          active;
    uint32_t     init_seq;       /* 初始序列号（SYN 包） */
    int          have_init_seq;
    uint8_t     *data;           /* 重组缓冲 */
    int          data_len;       /* 已重组数据长度 */
    int          data_cap;
    char         src_ip_str[64];
    char         dst_ip_str[64];
} tcp_stream_t;

void stream_init_all(void);
void stream_clear_all(void);

/* 处理一个 TCP 包，归入对应流并尝试重组 */
void stream_process_packet(const packet_t *pkt);

/* 获取流的索引列表（活跃流），返回数量 */
int  stream_get_active(int *indices, int max);

/* 获取指定流 */
tcp_stream_t *stream_get(int index);

/* 判断一个包属于哪个流（返回流索引或 -1） */
int  stream_find(const packet_t *pkt);

#endif /* STREAM_H */
