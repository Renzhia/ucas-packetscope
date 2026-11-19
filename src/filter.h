/*
 * filter.h - 显示过滤表达式引擎
 *
 * 支持：
 *   协议名: tcp, udp, http, dns, icmp, arp, ipv4, ipv6
 *   字段比较: ip.addr == 1.2.3.4, tcp.port == 80, tcp.flags.syn == 1
 *   逻辑运算: and / or / not / 括号
 */
#ifndef FILTER_H
#define FILTER_H

#include "packet.h"

/* 编译过滤表达式。成功返回 0，失败返回 -1 并设置 errmsg */
int  filter_compile(const char *expr, char *errmsg, int errlen);

/* 释放已编译的过滤表达式 */
void filter_free(void);

/* 对单个数据包求值。返回 1=匹配, 0=不匹配 */
int  filter_match(const packet_t *pkt);

/* 是否有已编译的过滤器 */
int  filter_active(void);

#endif /* FILTER_H */
