/*
 * ip.c - IPv4 / IPv6 解析
 */
#include "../packet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int dissect_ipv4(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 20)
        return -1;

    ipv4_hdr_t *ip = &pkt->ipv4;
    ip->version_ihl = data[0];
    ip->tos          = data[1];
    ip->total_len    = ntohs(*(uint16_t *)(data + 2));
    ip->id           = ntohs(*(uint16_t *)(data + 4));
    ip->flags_frag   = ntohs(*(uint16_t *)(data + 6));
    ip->ttl          = data[8];
    ip->protocol     = data[9];
    ip->checksum     = ntohs(*(uint16_t *)(data + 10));
    memcpy(&ip->src, data + 12, 4);
    memcpy(&ip->dst, data + 16, 4);

    int ihl = (ip->version_ihl & 0x0F) * 4;  /* 头长(字节) */
    if (ihl < 20 || ihl > len)
        return -1;

    /* 设置 L4 协议 */
    pkt->l4_proto = ip->protocol;
    if (ip->protocol == IPPROTO_TCP) {
        pkt->is_tcp = 1;
        strncpy(pkt->protocol, "TCP", sizeof(pkt->protocol));
    } else if (ip->protocol == IPPROTO_UDP) {
        pkt->is_udp = 1;
        strncpy(pkt->protocol, "UDP", sizeof(pkt->protocol));
    } else if (ip->protocol == IPPROTO_ICMP) {
        pkt->is_icmp = 1;
        strncpy(pkt->protocol, "ICMP", sizeof(pkt->protocol));
    }

    /* 地址字符串 */
    ip_to_str(ip->src, pkt->src_addr, sizeof(pkt->src_addr));
    ip_to_str(ip->dst, pkt->dst_addr, sizeof(pkt->dst_addr));

    /* 字段树 */
    int root = tree_add_node(pkt, -1, "Internet Protocol Version 4", NULL);
    char buf[128];

    int ver_node = tree_add_node(pkt, root, "Version", "4");
    (void)ver_node;

    snprintf(buf, sizeof(buf), "%d (%d bytes)", ip->version_ihl & 0x0F, ihl);
    tree_add_node(pkt, root, "Header Length", buf);
    snprintf(buf, sizeof(buf), "0x%02x", ip->tos);
    tree_add_node(pkt, root, "Differentiated Services", buf);
    snprintf(buf, sizeof(buf), "%d", ip->total_len);
    tree_add_node(pkt, root, "Total Length", buf);
    snprintf(buf, sizeof(buf), "0x%04x (%d)", ip->id, ip->id);
    tree_add_node(pkt, root, "Identification", buf);

    int flags = (ip->flags_frag >> 13) & 0x7;
    int frag_off = ip->flags_frag & 0x1FFF;
    snprintf(buf, sizeof(buf), "0x%x %s%s%s, offset: %d",
             flags,
             (flags & 0x4) ? ", Don't fragment" : "",
             (flags & 0x2) ? ", More fragments" : "",
             (flags & 0x1) ? ", Reserved" : "",
             frag_off);
    tree_add_node(pkt, root, "Flags", buf);

    snprintf(buf, sizeof(buf), "%d", ip->ttl);
    tree_add_node(pkt, root, "Time to Live", buf);

    const char *proto_name = "Unknown";
    switch (ip->protocol) {
    case IPPROTO_TCP:  proto_name = "TCP (6)"; break;
    case IPPROTO_UDP:  proto_name = "UDP (17)"; break;
    case IPPROTO_ICMP: proto_name = "ICMP (1)"; break;
    default: snprintf(buf, sizeof(buf), "Unknown (%d)", ip->protocol); proto_name = buf; break;
    }
    tree_add_node(pkt, root, "Protocol", proto_name);
    snprintf(buf, sizeof(buf), "0x%04x", ip->checksum);
    tree_add_node(pkt, root, "Header Checksum", buf);

    ip_to_str(ip->src, buf, sizeof(buf));
    tree_add_node(pkt, root, "Source", buf);
    ip_to_str(ip->dst, buf, sizeof(buf));
    tree_add_node(pkt, root, "Destination", buf);

    return ihl;
}

int dissect_ipv6(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 40)
        return -1;

    ipv6_hdr_t *ip6 = &pkt->ipv6;
    memcpy(&ip6->vtc_flow, data, 4);
    ip6->vtc_flow = ntohl(ip6->vtc_flow);
    ip6->payload_len = ntohs(*(uint16_t *)(data + 4));
    ip6->next_header = data[6];
    ip6->hop_limit   = data[7];
    memcpy(ip6->src, data + 8, 16);
    memcpy(ip6->dst, data + 24, 16);

    pkt->l4_proto = ip6->next_header;
    if (ip6->next_header == IPPROTO_TCP) {
        pkt->is_tcp = 1;
        strncpy(pkt->protocol, "TCP", sizeof(pkt->protocol));
    } else if (ip6->next_header == IPPROTO_UDP) {
        pkt->is_udp = 1;
        strncpy(pkt->protocol, "UDP", sizeof(pkt->protocol));
    } else if (ip6->next_header == IPPROTO_ICMPV6) {
        pkt->is_icmp = 1;
        strncpy(pkt->protocol, "ICMPv6", sizeof(pkt->protocol));
    }

    ipv6_to_str(ip6->src, pkt->src_addr, sizeof(pkt->src_addr));
    ipv6_to_str(ip6->dst, pkt->dst_addr, sizeof(pkt->dst_addr));

    int root = tree_add_node(pkt, -1, "Internet Protocol Version 6", NULL);
    char buf[128];

    snprintf(buf, sizeof(buf), "%d", (ip6->vtc_flow >> 28) & 0xF);
    tree_add_node(pkt, root, "Version", buf);
    snprintf(buf, sizeof(buf), "0x%05x", (ip6->vtc_flow >> 8) & 0xFFFFF);
    tree_add_node(pkt, root, "Flow Label", buf);
    snprintf(buf, sizeof(buf), "%d", ip6->payload_len);
    tree_add_node(pkt, root, "Payload Length", buf);
    snprintf(buf, sizeof(buf), "%d", ip6->next_header);
    tree_add_node(pkt, root, "Next Header", buf);
    snprintf(buf, sizeof(buf), "%d", ip6->hop_limit);
    tree_add_node(pkt, root, "Hop Limit", buf);

    char addrbuf[64];
    ipv6_to_str(ip6->src, addrbuf, sizeof(addrbuf));
    tree_add_node(pkt, root, "Source", addrbuf);
    ipv6_to_str(ip6->dst, addrbuf, sizeof(addrbuf));
    tree_add_node(pkt, root, "Destination", addrbuf);

    return 40;
}
