/*
 * http.c - HTTP 应用层识别
 * 基于端口(80) + 文本特征识别 HTTP 请求/响应
 */
#include "../packet.h"
#include <string.h>
#include <ctype.h>

/* 检查 payload 是否以已知 HTTP 方法/响应开头 */
static int is_http_text(const uint8_t *data, int len)
{
    if (len < 4)
        return 0;
    /* 请求方法 */
    static const char *methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "TRAC", "CONN", "PATC", NULL};
    for (int i = 0; methods[i]; i++) {
        if (len >= 4 && strncmp((const char *)data, methods[i], 4) == 0)
            return 1;
    }
    /* 响应: HTTP/1.x */
    if (len >= 5 && strncmp((const char *)data, "HTTP/", 5) == 0)
        return 2;
    return 0;
}

void dissect_http(packet_t *pkt, const uint8_t *data, int len, int src_port, int dst_port)
{
    if (!data || len <= 0)
        return;

    /* 端口判断：80 或 8080 */
    int is_http_port = (src_port == 80 || dst_port == 80 ||
                        src_port == 8080 || dst_port == 8080);
    if (!is_http_port)
        return;

    int kind = is_http_text(data, len);
    if (!kind)
        return;

    pkt->app_proto |= APP_HTTP;

    /* 提取第一行（请求行或状态行） */
    char first_line[256] = "";
    int i;
    for (i = 0; i < len && i < 255; i++) {
        if (data[i] == '\r' || data[i] == '\n')
            break;
        first_line[i] = data[i];
    }
    first_line[i] = '\0';

    /* 应用层摘要 */
    snprintf(pkt->app_info, sizeof(pkt->app_info), "%s", first_line);

    /* 更新 Info 列 */
    if (kind == 1) {
        snprintf(pkt->info, sizeof(pkt->info), "HTTP %s", first_line);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "HTTP %s", first_line);
    }

    /* 更新协议名 */
    strncpy(pkt->protocol, "HTTP", sizeof(pkt->protocol));

    /* 字段树 */
    int root = tree_add_node(pkt, -1, "Hypertext Transfer Protocol", NULL);
    tree_add_node(pkt, root, kind == 1 ? "Request" : "Response", first_line);

    /* 提取关键头部字段 */
    int pos = 0;
    while (pos < len) {
        /* 找行结束 */
        int line_start = pos;
        while (pos < len && data[pos] != '\n') pos++;
        int line_len = pos - line_start;
        if (pos < len) pos++; /* 跳过 \n */

        if (line_len <= 1)
            break; /* 空行表示头部结束 */

        char line[256];
        int copy_len = line_len > 255 ? 255 : line_len;
        memcpy(line, data + line_start, copy_len);
        line[copy_len] = '\0';
        /* 去掉 \r */
        if (copy_len > 0 && line[copy_len - 1] == '\r')
            line[copy_len - 1] = '\0';

        /* 提取 Host, Content-Type 等关键头 */
        if (strncasecmp(line, "Host:", 5) == 0 ||
            strncasecmp(line, "Content-Type:", 13) == 0 ||
            strncasecmp(line, "Content-Length:", 15) == 0 ||
            strncasecmp(line, "User-Agent:", 11) == 0) {
            tree_add_node(pkt, root, "Header", line);
        }
    }
}
