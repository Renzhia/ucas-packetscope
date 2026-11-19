/*
 * packet.h - 核心数据结构与协议头定义
 * 网络嗅探器 1A - 数据包结构与全局存储
 */
#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <pthread.h>

/* ---------- 常量 ---------- */
#define MAX_PACKETS   10000          /* 环形缓冲容量 */
#define MAX_INFO_LEN  256
#define SNAPLEN       65535

/* ---------- 协议头部结构 ---------- */

/* Ethernet II (14 字节) */
typedef struct {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;              /* 已转为主机序 */
} eth_hdr_t;

#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD

/* ARP (28 字节) */
typedef struct {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;                 /* 1=请求, 2=应答 */
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
} arp_hdr_t;

/* IPv4 (20 字节，无选项) */
typedef struct {
    uint8_t  version_ihl;            /* 高4位版本, 低4位头长(以4字节为单位) */
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;             /* 高3位标志, 低13位片偏移 */
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} ipv4_hdr_t;

/* IPv6 (40 字节) */
typedef struct {
    uint32_t vtc_flow;               /* 版本+流量类+流标签 */
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} ipv6_hdr_t;

/* TCP (20 字节，无选项) */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;            /* 仅高4位有效 */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_hdr_t;

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

/* UDP (8 字节) */
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} udp_hdr_t;

/* ICMP (4 字节头) */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
} icmp_hdr_t;

/* ---------- 应用层协议标识 ---------- */
typedef enum {
    APP_NONE   = 0,
    APP_HTTP   = 1 << 0,
    APP_DNS    = 1 << 1,
    APP_HTTPS  = 1 << 2,
} app_proto_t;

/* ---------- 字段树节点（用于UI详情展示）---------- */
#define MAX_NODES     128
#define NODE_NAME_LEN 64
#define NODE_VAL_LEN  160

typedef struct tree_node {
    char     name[NODE_NAME_LEN];
    char     value[NODE_VAL_LEN];
    int      child_count;
    int      first_child;            /* 在节点数组中的索引 */
    int      next_sibling;           /* 在节点数组中的索引 */
} tree_node_t;

/* ---------- 数据包结构 ---------- */
typedef struct {
    int            seq;              /* 序号 (从1开始) */
    struct timeval ts;               /* 时间戳 */
    int            caplen;           /* 实际捕获长度 */
    int            origlen;          /* 原始长度 */

    uint8_t       *raw;              /* 原始字节副本 (malloc) */
    int            raw_len;          /* raw 长度 */

    /* L2 */
    eth_hdr_t      eth;
    int            have_eth;
    int            is_arp;
    arp_hdr_t      arp;

    /* L3 */
    int            is_ipv4;
    int            is_ipv6;
    ipv4_hdr_t     ipv4;
    ipv6_hdr_t     ipv6;
    int            is_icmp;
    icmp_hdr_t     icmp;
    int            l3_proto;         /* EtherType 或 next_header */

    /* L4 */
    int            is_tcp;
    int            is_udp;
    tcp_hdr_t      tcp;
    udp_hdr_t      udp;
    int            l4_proto;         /* IPPROTO_TCP/UDP/ICMP */

    /* 应用层 */
    int            app_proto;        /* app_proto_t 位掩码 */
    char           app_info[256];    /* 应用层摘要 */

    /* 载荷指针与长度 */
    const uint8_t *payload;          /* 指向 raw 中的应用层载荷 */
    int            payload_len;

    /* 展示用字符串 */
    char           src_addr[64];
    char           dst_addr[64];
    char           protocol[16];
    char           info[MAX_INFO_LEN];

    /* 字段树 */
    tree_node_t    nodes[MAX_NODES];
    int            node_count;
} packet_t;

/* ---------- 全局数据包存储（环形缓冲）---------- */
typedef struct {
    packet_t      packets[MAX_PACKETS];
    int           count;             /* 已捕获总数 */
    int           head;              /* 下一个写入位置 */
    pthread_mutex_t lock;
} packet_store_t;

extern packet_store_t g_store;

/* ---------- 接口函数 ---------- */
void        store_init(void);
int         store_add(packet_t *pkt);      /* 返回分配的序号 */
packet_t   *store_get(int logical_index);  /* 逻辑索引 0..count-1 */
void        store_clear(void);
int         store_visible_count(void);

/* 格式化工具 */
void mac_to_str(const uint8_t *mac, char *buf, size_t len);
void ip_to_str(uint32_t ip, char *buf, size_t len);
void ipv6_to_str(const uint8_t *addr, char *buf, size_t len);

/* 字段树工具 */
void tree_init(packet_t *pkt);
int  tree_add_node(packet_t *pkt, int parent, const char *name, const char *value);
void tree_add_fmt(packet_t *pkt, int parent, const char *name, const char *fmt, ...);

#endif /* PACKET_H */
