/*
 * udp.c - UDP 协议解析
 */
#include "../packet.h"
#include <string.h>
#include <arpa/inet.h>

int dissect_udp(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 8)
        return -1;

    udp_hdr_t *udp = &pkt->udp;
    udp->src_port = ntohs(*(uint16_t *)(data + 0));
    udp->dst_port = ntohs(*(uint16_t *)(data + 2));
    udp->len      = ntohs(*(uint16_t *)(data + 4));
    udp->checksum = ntohs(*(uint16_t *)(data + 6));

    /* 载荷 */
    if (len > 8) {
        pkt->payload = data + 8;
        pkt->payload_len = len - 8;
    }

    /* 字段树 */
    int root = tree_add_node(pkt, -1, "User Datagram Protocol", NULL);
    char buf[128];

    snprintf(buf, sizeof(buf), "%d", udp->src_port);
    tree_add_node(pkt, root, "Source Port", buf);
    snprintf(buf, sizeof(buf), "%d", udp->dst_port);
    tree_add_node(pkt, root, "Destination Port", buf);
    snprintf(buf, sizeof(buf), "%d", udp->len);
    tree_add_node(pkt, root, "Length", buf);
    snprintf(buf, sizeof(buf), "0x%04x", udp->checksum);
    tree_add_node(pkt, root, "Checksum", buf);

    /* Info */
    snprintf(pkt->info, sizeof(pkt->info), "%d → %d Len=%d",
             udp->src_port, udp->dst_port, pkt->payload_len);

    return 8;
}
