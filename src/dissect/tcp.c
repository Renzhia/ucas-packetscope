/*
 * tcp.c - TCP 协议解析
 */
#include "../packet.h"
#include <string.h>
#include <arpa/inet.h>

int dissect_tcp(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 20)
        return -1;

    tcp_hdr_t *tcp = &pkt->tcp;
    tcp->src_port    = ntohs(*(uint16_t *)(data + 0));
    tcp->dst_port    = ntohs(*(uint16_t *)(data + 2));
    tcp->seq         = ntohl(*(uint32_t *)(data + 4));
    tcp->ack         = ntohl(*(uint32_t *)(data + 8));
    tcp->data_offset = data[12];
    tcp->flags       = data[13];
    tcp->window      = ntohs(*(uint16_t *)(data + 14));
    tcp->checksum    = ntohs(*(uint16_t *)(data + 16));
    tcp->urgent      = ntohs(*(uint16_t *)(data + 18));

    int hdr_len = (tcp->data_offset >> 4) * 4;  /* data offset 以 4 字节为单位 */
    if (hdr_len < 20 || hdr_len > len)
        return -1;

    /* 设置载荷指针 */
    if (len > hdr_len) {
        pkt->payload = data + hdr_len;
        pkt->payload_len = len - hdr_len;
    }

    /* 字段树 */
    int root = tree_add_node(pkt, -1, "Transmission Control Protocol", NULL);
    char buf[128];

    snprintf(buf, sizeof(buf), "%d", tcp->src_port);
    tree_add_node(pkt, root, "Source Port", buf);
    snprintf(buf, sizeof(buf), "%d", tcp->dst_port);
    tree_add_node(pkt, root, "Destination Port", buf);
    snprintf(buf, sizeof(buf), "%u", tcp->seq);
    tree_add_node(pkt, root, "Sequence Number", buf);

    if (tcp->flags & TCP_ACK) {
        snprintf(buf, sizeof(buf), "%u", tcp->ack);
        tree_add_node(pkt, root, "Acknowledgment Number", buf);
    }

    int doff = (tcp->data_offset >> 4) * 4;
    snprintf(buf, sizeof(buf), "%d (%d bytes)", tcp->data_offset >> 4, doff);
    tree_add_node(pkt, root, "Header Length", buf);

    /* Flags */
    char flags_str[128] = "";
    if (tcp->flags & TCP_URG) strcat(flags_str, "URG, ");
    if (tcp->flags & TCP_ACK) strcat(flags_str, "ACK, ");
    if (tcp->flags & TCP_PSH) strcat(flags_str, "PSH, ");
    if (tcp->flags & TCP_RST) strcat(flags_str, "RST, ");
    if (tcp->flags & TCP_SYN) strcat(flags_str, "SYN, ");
    if (tcp->flags & TCP_FIN) strcat(flags_str, "FIN, ");
    /* 去掉末尾 ", " */
    size_t fl = strlen(flags_str);
    if (fl >= 2) flags_str[fl - 2] = '\0';
    snprintf(buf, sizeof(buf), "0x%02x (%s)", tcp->flags, flags_str[0] ? flags_str : "None");
    tree_add_node(pkt, root, "Flags", buf);

    snprintf(buf, sizeof(buf), "%d", tcp->window);
    tree_add_node(pkt, root, "Window", buf);
    snprintf(buf, sizeof(buf), "0x%04x", tcp->checksum);
    tree_add_node(pkt, root, "Checksum", buf);

    /* Info */
    char info[256];
    const char *flag_info = "";
    if (tcp->flags & TCP_SYN) flag_info = "[SYN]";
    else if (tcp->flags & (TCP_SYN | TCP_ACK)) flag_info = "[SYN, ACK]";
    else if (tcp->flags & TCP_FIN) flag_info = "[FIN]";
    else if (tcp->flags & TCP_RST) flag_info = "[RST]";
    else if (tcp->flags & TCP_PSH) flag_info = "[PSH]";
    else if (tcp->flags & TCP_ACK) flag_info = "[ACK]";

    snprintf(info, sizeof(info), "%d → %d %s Seq=%u Ack=%u Win=%d Len=%d",
             tcp->src_port, tcp->dst_port, flag_info, tcp->seq, tcp->ack,
             tcp->window, pkt->payload_len);
    strncpy(pkt->info, info, sizeof(pkt->info) - 1);

    return hdr_len;
}
