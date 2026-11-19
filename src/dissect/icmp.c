/*
 * icmp.c - ICMP 协议解析
 */
#include "../packet.h"
#include <string.h>

static const char *icmp_type_name(uint8_t type)
{
    switch (type) {
    case 0:  return "Echo Reply";
    case 3:  return "Destination Unreachable";
    case 8:  return "Echo Request";
    case 11: return "Time Exceeded";
    case 5:  return "Redirect";
    default: return "Unknown";
    }
}

int dissect_icmp(packet_t *pkt, const uint8_t *data, int len)
{
    if (len < 4)
        return -1;

    icmp_hdr_t *icmp = &pkt->icmp;
    icmp->type     = data[0];
    icmp->code     = data[1];
    icmp->checksum = (data[2] << 8) | data[3];

    int root = tree_add_node(pkt, -1, "Internet Control Message Protocol", NULL);
    char buf[128];

    snprintf(buf, sizeof(buf), "%d (%s)", icmp->type, icmp_type_name(icmp->type));
    tree_add_node(pkt, root, "Type", buf);
    snprintf(buf, sizeof(buf), "%d", icmp->code);
    tree_add_node(pkt, root, "Code", buf);
    snprintf(buf, sizeof(buf), "0x%04x", icmp->checksum);
    tree_add_node(pkt, root, "Checksum", buf);

    /* Echo Request / Reply 有 id 和 seq */
    if (len >= 8 && (icmp->type == 8 || icmp->type == 0)) {
        uint16_t id  = (data[4] << 8) | data[5];
        uint16_t seq = (data[6] << 8) | data[7];
        snprintf(buf, sizeof(buf), "%d", id);
        tree_add_node(pkt, root, "Identifier", buf);
        snprintf(buf, sizeof(buf), "%d", seq);
        tree_add_node(pkt, root, "Sequence", buf);

        snprintf(pkt->info, sizeof(pkt->info), "ICMP %s id=%d seq=%d",
                 icmp_type_name(icmp->type), id, seq);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "ICMP %s (type=%d code=%d)",
                 icmp_type_name(icmp->type), icmp->type, icmp->code);
    }

    return 4;
}
