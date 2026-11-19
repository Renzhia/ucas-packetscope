/*
 * ethernet.c - Ethernet II 帧解析
 */
#include "../packet.h"
#include <string.h>

int dissect_ethernet(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 14)
        return -1;

    memcpy(pkt->eth.dst, data, 6);
    memcpy(pkt->eth.src, data + 6, 6);
    pkt->eth.ethertype = (data[12] << 8) | data[13];
    pkt->have_eth = 1;

    /* 字段树 */
    int root = tree_add_node(pkt, -1, "Ethernet II", NULL);
    char buf[64];
    mac_to_str(pkt->eth.dst, buf, sizeof(buf));
    tree_add_node(pkt, root, "Destination", buf);
    mac_to_str(pkt->eth.src, buf, sizeof(buf));
    tree_add_node(pkt, root, "Source", buf);
    snprintf(buf, sizeof(buf), "0x%04x", pkt->eth.ethertype);
    tree_add_node(pkt, root, "Type", buf);

    /* 判断上层协议 */
    switch (pkt->eth.ethertype) {
    case 0x0800:
        pkt->is_ipv4 = 1;
        strncpy(pkt->protocol, "IPv4", sizeof(pkt->protocol));
        break;
    case 0x0806:
        pkt->is_arp = 1;
        strncpy(pkt->protocol, "ARP", sizeof(pkt->protocol));
        break;
    case 0x86DD:
        pkt->is_ipv6 = 1;
        strncpy(pkt->protocol, "IPv6", sizeof(pkt->protocol));
        break;
    default:
        snprintf(pkt->protocol, sizeof(pkt->protocol), "ETH(0x%04x)", pkt->eth.ethertype);
        break;
    }

    return 14; /* Ethernet 头长度 */
}
