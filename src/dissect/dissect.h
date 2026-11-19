/*
 * dissect.h - 协议解析统一入口
 */
#ifndef DISSECT_H
#define DISSECT_H

#include "packet.h"

/* 解析完整协议栈：Ethernet -> IP -> TCP/UDP -> 应用层 */
void dissect_packet(packet_t *pkt);

#endif /* DISSECT_H */
