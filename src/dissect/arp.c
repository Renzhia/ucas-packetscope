/*
 * arp.c - ARP 协议解析
 */
#include "../packet.h"
#include <string.h>
#include <arpa/inet.h>

int dissect_arp(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 28)
        return -1;

    pkt->arp.hw_type    = (data[0] << 8) | data[1];
    pkt->arp.proto_type = (data[2] << 8) | data[3];
    pkt->arp.hw_len     = data[4];
    pkt->arp.proto_len  = data[5];
    pkt->arp.opcode     = (data[6] << 8) | data[7];
    memcpy(pkt->arp.sender_mac, data + 8, 6);
    memcpy(&pkt->arp.sender_ip, data + 14, 4);
    memcpy(pkt->arp.target_mac, data + 18, 6);
    memcpy(&pkt->arp.target_ip, data + 24, 4);

    int root = tree_add_node(pkt, -1, "Address Resolution Protocol", NULL);
    char buf[128];
    snprintf(buf, sizeof(buf), "%d", pkt->arp.hw_type);
    tree_add_node(pkt, root, "Hardware type", buf);
    snprintf(buf, sizeof(buf), "0x%04x", pkt->arp.proto_type);
    tree_add_node(pkt, root, "Protocol type", buf);
    snprintf(buf, sizeof(buf), "%d", pkt->arp.hw_len);
    tree_add_node(pkt, root, "Hardware size", buf);
    snprintf(buf, sizeof(buf), "%d", pkt->arp.proto_len);
    tree_add_node(pkt, root, "Protocol size", buf);
    snprintf(buf, sizeof(buf), "%s (%d)",
             pkt->arp.opcode == 1 ? "request" : pkt->arp.opcode == 2 ? "reply" : "unknown",
             pkt->arp.opcode);
    tree_add_node(pkt, root, "Opcode", buf);

    mac_to_str(pkt->arp.sender_mac, buf, sizeof(buf));
    tree_add_node(pkt, root, "Sender MAC", buf);
    ip_to_str(pkt->arp.sender_ip, buf, sizeof(buf));
    tree_add_node(pkt, root, "Sender IP", buf);
    mac_to_str(pkt->arp.target_mac, buf, sizeof(buf));
    tree_add_node(pkt, root, "Target MAC", buf);
    ip_to_str(pkt->arp.target_ip, buf, sizeof(buf));
    tree_add_node(pkt, root, "Target IP", buf);

    /* 设置地址与 Info */
    ip_to_str(pkt->arp.sender_ip, pkt->src_addr, sizeof(pkt->src_addr));
    ip_to_str(pkt->arp.target_ip, pkt->dst_addr, sizeof(pkt->dst_addr));

    snprintf(pkt->info, sizeof(pkt->info), "ARP %s: Who has %s? Tell %s",
             pkt->arp.opcode == 1 ? "Request" : "Reply",
             pkt->dst_addr, pkt->src_addr);

    return 28;
}
