/*
 * dissect.c - 协议解析统一入口：自底向上逐层调用
 */
#include "dissect.h"
#include "../packet.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* 各层解析函数声明 */
int  dissect_ethernet(packet_t *pkt, const uint8_t *data, int len);
int  dissect_arp(packet_t *pkt, const uint8_t *data, int len);
int  dissect_ipv4(packet_t *pkt, const uint8_t *data, int len);
int  dissect_ipv6(packet_t *pkt, const uint8_t *data, int len);
int  dissect_icmp(packet_t *pkt, const uint8_t *data, int len);
int  dissect_tcp(packet_t *pkt, const uint8_t *data, int len);
int  dissect_udp(packet_t *pkt, const uint8_t *data, int len);
void dissect_http(packet_t *pkt, const uint8_t *data, int len, int src_port, int dst_port);
void dissect_dns(packet_t *pkt, const uint8_t *data, int len, int src_port, int dst_port);

void dissect_packet(packet_t *pkt)
{
    tree_init(pkt);

    if (!pkt->raw || pkt->raw_len < 14) {
        strncpy(pkt->protocol, "N/A", sizeof(pkt->protocol));
        strncpy(pkt->info, "包太短", sizeof(pkt->info));
        return;
    }

    /* L2: Ethernet */
    int offset = dissect_ethernet(pkt, pkt->raw, pkt->raw_len);
    if (offset < 0)
        return;

    /* L3 */
    if (pkt->is_arp) {
        dissect_arp(pkt, pkt->raw + offset, pkt->raw_len - offset);
        return; /* ARP 不再有上层 */
    }

    if (pkt->is_ipv4) {
        int ret = dissect_ipv4(pkt, pkt->raw + offset, pkt->raw_len - offset);
        if (ret < 0) return;
        offset += ret;
    } else if (pkt->is_ipv6) {
        int ret = dissect_ipv6(pkt, pkt->raw + offset, pkt->raw_len - offset);
        if (ret < 0) return;
        offset += ret;
    } else {
        /* 未知 EtherType */
        if (pkt->protocol[0] == '\0')
            strncpy(pkt->protocol, "ETH", sizeof(pkt->protocol));
        return;
    }

    /* L4 */
    if (pkt->is_icmp) {
        dissect_icmp(pkt, pkt->raw + offset, pkt->raw_len - offset);
    } else if (pkt->l4_proto == IPPROTO_TCP) {
        int ret = dissect_tcp(pkt, pkt->raw + offset, pkt->raw_len - offset);
        if (ret < 0) return;
        offset += ret;
        /* 应用层 */
        if (pkt->payload && pkt->payload_len > 0) {
            dissect_http(pkt, pkt->payload, pkt->payload_len,
                         pkt->tcp.src_port, pkt->tcp.dst_port);
            dissect_dns(pkt, pkt->payload, pkt->payload_len,
                        pkt->tcp.src_port, pkt->tcp.dst_port);
        }
    } else if (pkt->l4_proto == IPPROTO_UDP) {
        int ret = dissect_udp(pkt, pkt->raw + offset, pkt->raw_len - offset);
        if (ret < 0) return;
        offset += ret;
        /* 应用层 */
        if (pkt->payload && pkt->payload_len > 0) {
            dissect_dns(pkt, pkt->payload, pkt->payload_len,
                        pkt->udp.src_port, pkt->udp.dst_port);
            dissect_http(pkt, pkt->payload, pkt->payload_len,
                         pkt->udp.src_port, pkt->udp.dst_port);
        }
    }

    /* 若未设置 info，设置默认 */
    if (pkt->info[0] == '\0') {
        snprintf(pkt->info, sizeof(pkt->info), "len=%d", pkt->origlen);
    }
}
