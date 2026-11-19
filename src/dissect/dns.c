/*
 * dns.c - DNS 协议解析
 * 基于端口(53) 解析 DNS 查询/响应
 */
#include "../packet.h"
#include <string.h>

/* 解析 DNS 域名（可能含压缩指针） */
static int parse_dns_name(const uint8_t *data, int data_len, int offset,
                          char *name, int name_size)
{
    int name_pos = 0;
    int jumped = 0;
    int original_offset = offset;
    int jumps = 0;

    while (offset < data_len && jumps < 10) {
        uint8_t label_len = data[offset];
        if (label_len == 0) {
            if (!jumped) offset++;
            break;
        }
        if ((label_len & 0xC0) == 0xC0) {
            /* 压缩指针 */
            if (offset + 1 >= data_len)
                break;
            int ptr = ((label_len & 0x3F) << 8) | data[offset + 1];
            if (!jumped)
                original_offset = offset + 2;
            offset = ptr;
            jumped = 1;
            jumps++;
            continue;
        }
        offset++;
        if (offset + label_len > data_len)
            break;
        if (name_pos + label_len + 1 >= name_size)
            break;
        memcpy(name + name_pos, data + offset, label_len);
        name_pos += label_len;
        name[name_pos++] = '.';
        offset += label_len;
    }

    if (name_pos > 0 && name[name_pos - 1] == '.')
        name[name_pos - 1] = '\0';
    else
        name[name_pos] = '\0';

    return jumped ? original_offset : offset;
}

static const char *dns_type_name(uint16_t type)
{
    switch (type) {
    case 1:  return "A";
    case 2:  return "NS";
    case 5:  return "CNAME";
    case 6:  return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    default: return "UNKNOWN";
    }
}

void dissect_dns(packet_t *pkt, const uint8_t *data, int len, int src_port, int dst_port)
{
    if (!data || len < 12)
        return;

    if (src_port != 53 && dst_port != 53)
        return;

    pkt->app_proto |= APP_DNS;

    uint16_t txn_id  = (data[0] << 8) | data[1];
    uint16_t flags   = (data[2] << 8) | data[3];
    uint16_t qd_count = (data[4] << 8) | data[5];
    uint16_t an_count = (data[6] << 8) | data[7];
    (void)(data[8] << 8 | data[9]);   /* ns_count 未使用 */
    (void)(data[10] << 8 | data[11]); /* ar_count 未使用 */

    int is_response = (flags & 0x8000) ? 1 : 0;

    /* 字段树 */
    int root = tree_add_node(pkt, -1, "Domain Name System", NULL);
    char buf[256];

    snprintf(buf, sizeof(buf), "0x%04x", txn_id);
    tree_add_node(pkt, root, "Transaction ID", buf);
    snprintf(buf, sizeof(buf), "0x%04x (%s)", flags, is_response ? "response" : "query");
    tree_add_node(pkt, root, "Flags", buf);
    snprintf(buf, sizeof(buf), "%d", qd_count);
    tree_add_node(pkt, root, "Questions", buf);
    snprintf(buf, sizeof(buf), "%d", an_count);
    tree_add_node(pkt, root, "Answer RRs", buf);

    /* 解析查询段 */
    if (qd_count > 0 && len > 12) {
        char qname[256];
        int next = parse_dns_name(data, len, 12, qname, sizeof(qname));
        if (next + 4 <= len) {
            uint16_t qtype = (data[next] << 8) | data[next + 1];
            uint16_t qclass = (data[next + 2] << 8) | data[next + 3];

            int q_node = tree_add_node(pkt, root, "Queries", NULL);
            tree_add_node(pkt, q_node, "Name", qname);
            snprintf(buf, sizeof(buf), "%s (%d)", dns_type_name(qtype), qtype);
            tree_add_node(pkt, q_node, "Type", buf);
            snprintf(buf, sizeof(buf), "%s (%d)", qclass == 1 ? "IN" : "??", qclass);
            tree_add_node(pkt, q_node, "Class", buf);

            /* Info */
            snprintf(pkt->info, sizeof(pkt->info), "Standard query 0x%04x %s %s",
                     txn_id, dns_type_name(qtype), qname);
        }
    }

    if (is_response && an_count > 0) {
        snprintf(pkt->info, sizeof(pkt->info),
                 "Standard response 0x%04x %d answers", txn_id, an_count);
    }

    strncpy(pkt->protocol, "DNS", sizeof(pkt->protocol));
}
