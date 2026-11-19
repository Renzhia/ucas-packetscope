/*
 * main.c - 网络嗅探器入口
 *
 * UCAS 软件与系统安全 实验 1A
 * 基于 libpcap + ncurses 的网络嗅探器
 * 功能：NPS 抓包 + NPA 多层协议分析 + BPF捕获过滤 + 显示过滤 + TCP流重组
 *
 * 用法:
 *   ./ucassniffer              默认 TUI 交互模式
 *   ./ucassniffer --list       列出可用网卡
 *   ./ucassniffer --cli <dev> [count]  命令行抓包模式（抓 count 个包后退出，默认20）
 *   ./ucassniffer --cli <dev> --bpf "tcp" [count]  带 BPF 过滤
 */
#include "packet.h"
#include "capture.h"
#include "filter.h"
#include "stream.h"
#include "dissect/dissect.h"
#include "ui/ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* ---- 命令行模式：列出网卡 ---- */
static int cmd_list_devs(void)
{
    pcap_if_t *devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (capture_list_devs(&devs, errbuf) != 0) {
        fprintf(stderr, "无法获取网卡列表: %s\n", errbuf);
        return 1;
    }
    printf("可用网卡列表:\n");
    printf("%-4s %-30s %s\n", "序号", "名称", "描述");
    printf("----------------------------------------------\n");
    pcap_if_t *d = devs;
    int idx = 0;
    while (d) {
        printf("[%-2d] %-28s %s\n", idx, d->name,
               d->description ? d->description : "");
        idx++;
        d = d->next;
    }
    pcap_freealldevs(devs);
    printf("\n共 %d 个网卡\n", idx);
    return 0;
}

/* ---- 命令行抓包回调 ---- */
static volatile int g_cli_count = 0;
static int g_cli_max = 20;

static void cli_print_packet(packet_t *pkt)
{
    char tbuf[32];
    struct tm *tm = localtime(&pkt->ts.tv_sec);
    snprintf(tbuf, sizeof(tbuf), "%02d:%02d:%02d.%03d",
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             (int)(pkt->ts.tv_usec / 1000));

    printf("%-4d %-13s %-18s %-18s %-6s %-5d %s\n",
           pkt->seq, tbuf,
           pkt->src_addr[0] ? pkt->src_addr : "?",
           pkt->dst_addr[0] ? pkt->dst_addr : "?",
           pkt->protocol, pkt->origlen, pkt->info);

    /* 打印字段树（缩进） */
    for (int i = 0; i < pkt->node_count; i++) {
        /* 只打印根节点和一级子节点的简要信息 */
        int is_root = 1;
        for (int j = 0; j < i; j++) {
            if (pkt->nodes[j].first_child == i) {
                is_root = 0;
                break;
            }
        }
        if (is_root && pkt->nodes[i].child_count > 0) {
            printf("       └─ %s\n", pkt->nodes[i].name);
        }
    }
    printf("\n");
}

/* ---- 命令行抓包模式 ---- */
static int cmd_cli_capture(const char *dev, int count, const char *bpf)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (bpf && *bpf) {
        capture_set_bpf(bpf);
        printf("BPF 捕获过滤: %s\n", bpf);
    }

    printf("在网卡 [%s] 上抓包，抓取 %d 个包后退出...\n\n", dev, count);
    g_cli_max = count;

    /* 打印表头 */
    printf("%-4s %-13s %-18s %-18s %-6s %-5s %s\n",
           "No.", "Time", "Source", "Destination", "Proto", "Len", "Info");
    printf("--------------------------------------------------------------------------------\n");

    /* 启动抓包 */
    if (capture_start(dev, errbuf) != 0) {
        fprintf(stderr, "启动抓包失败: %s\n", errbuf);
        return 1;
    }

    /* 轮询等待抓到足够的包 */
    while (g_cli_count < g_cli_max) {
        usleep(100000); /* 100ms */

        /* 检查新包 */
        int total = store_visible_count();
        while (g_cli_count < total) {
            packet_t *pkt = store_get(g_cli_count);
            if (pkt) {
                cli_print_packet(pkt);
                /* TCP 流重组 */
                stream_process_packet(pkt);
            }
            g_cli_count++;
        }

        if (!capture_is_running()) {
            fprintf(stderr, "抓包已停止\n");
            break;
        }
    }

    capture_stop();

    /* 打印 TCP 流统计 */
    int stream_indices[MAX_STREAMS];
    int stream_count = stream_get_active(stream_indices, MAX_STREAMS);
    if (stream_count > 0) {
        printf("\n==== TCP 流重组统计 ====\n");
        for (int i = 0; i < stream_count; i++) {
            tcp_stream_t *s = stream_get(stream_indices[i]);
            if (s) {
                printf("流 %d: %s:%d → %s:%d  重组数据 %d 字节\n",
                       i, s->src_ip_str, s->key.src_port,
                       s->dst_ip_str, s->key.dst_port, s->data_len);
            }
        }
    }

    printf("\n共抓取 %d 个包\n", g_cli_count);
    return 0;
}

/* ---- 协议解析自测：构造模拟包验证解析正确性 ---- */
#include <arpa/inet.h>
#include <netinet/in.h>

static void print_packet_detail(const packet_t *pkt)
{
    printf("  协议: %s | 源: %s | 目的: %s | 长度: %d\n",
           pkt->protocol, pkt->src_addr, pkt->dst_addr, pkt->origlen);
    printf("  Info: %s\n", pkt->info);

    /* 打印字段树（深度优先） */
    for (int i = 0; i < pkt->node_count; i++) {
        int is_root = 1;
        for (int j = 0; j < i; j++) {
            if (pkt->nodes[j].first_child == i) { is_root = 0; break; }
        }
        if (!is_root) continue;

        printf("  └─ %s\n", pkt->nodes[i].name);
        int child = pkt->nodes[i].first_child;
        while (child >= 0) {
            if (pkt->nodes[child].value[0])
                printf("     ├─ %s: %s\n", pkt->nodes[child].name, pkt->nodes[child].value);
            else
                printf("     ├─ %s\n", pkt->nodes[child].name);
            child = pkt->nodes[child].next_sibling;
        }
    }
}

static int cmd_test(void)
{
    printf("==== 协议解析自测 ====\n\n");
    store_init();
    stream_init_all();

    int passed = 0, total = 0;

    /* 测试1: TCP SYN 包 (192.168.1.100:54321 → 93.184.216.34:80) */
    {
        total++;
        uint8_t raw[] = {
            /* Ethernet */
            0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef,  /* dst MAC */
            0x00, 0x50, 0x56, 0xc0, 0x00, 0x01,  /* src MAC */
            0x08, 0x00,                            /* EtherType: IPv4 */
            /* IPv4 */
            0x45, 0x00, 0x00, 0x3c,               /* ver/ihl, tos, total_len */
            0x1a, 0x2b, 0x40, 0x00,               /* id, flags/frag */
            0x40, 0x06, 0x00, 0x00,               /* ttl=64, proto=TCP, checksum */
            0xc0, 0xa8, 0x01, 0x64,               /* src: 192.168.1.100 */
            0x5d, 0xb8, 0xd8, 0x22,               /* dst: 93.184.216.34 */
            /* TCP */
            0xd4, 0x31,                           /* src port: 54321 */
            0x00, 0x50,                           /* dst port: 80 */
            0x00, 0x00, 0x00, 0x01,               /* seq */
            0x00, 0x00, 0x00, 0x00,               /* ack */
            0x50, 0x02,                           /* data offset=5, flags=SYN */
            0xff, 0xff,                           /* window */
            0x00, 0x00,                           /* checksum */
            0x00, 0x00,                           /* urgent */
        };

        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.caplen = pkt.origlen = pkt.raw_len = sizeof(raw);
        pkt.raw = (uint8_t *)malloc(sizeof(raw));
        memcpy(pkt.raw, raw, sizeof(raw));
        pkt.ts.tv_sec = 1731234567;
        pkt.ts.tv_usec = 123456;

        dissect_packet(&pkt);

        printf("测试1: TCP SYN 包 (192.168.1.100:54321 → 93.184.216.34:80)\n");
        print_packet_detail(&pkt);

        /* 验证 */
        int ok = (pkt.is_tcp && pkt.is_ipv4 &&
                  pkt.tcp.src_port == 54321 && pkt.tcp.dst_port == 80 &&
                  (pkt.tcp.flags & TCP_SYN) && !(pkt.tcp.flags & TCP_ACK));
        printf("  结果: %s\n\n", ok ? "✓ PASS" : "✗ FAIL");
        if (ok) passed++;
        free(pkt.raw);
    }

    /* 测试2: HTTP GET 请求 */
    {
        total++;
        const char *http_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        int payload_len = (int)strlen(http_payload);
        int tcp_hdr_len = 20;
        int ip_total = 20 + tcp_hdr_len + payload_len;
        int pkt_len = 14 + ip_total;

        uint8_t *raw = (uint8_t *)malloc(pkt_len);
        memset(raw, 0, pkt_len);

        /* Ethernet */
        raw[12] = 0x08; raw[13] = 0x00; /* IPv4 */
        /* IPv4 */
        raw[14] = 0x45; /* ver=4, ihl=5 */
        raw[16] = (ip_total >> 8) & 0xff; raw[17] = ip_total & 0xff;
        raw[22] = 64; /* ttl */
        raw[23] = 6;  /* proto=TCP */
        raw[26] = 0xc0; raw[27] = 0xa8; raw[28] = 0x01; raw[29] = 0x64; /* 192.168.1.100 */
        raw[30] = 0x5d; raw[31] = 0xb8; raw[32] = 0xd8; raw[33] = 0x22; /* 93.184.216.34 */
        /* TCP */
        raw[34] = 0xd4; raw[35] = 0x31; /* src port 54321 */
        raw[36] = 0x00; raw[37] = 0x50; /* dst port 80 */
        raw[46] = 0x50; raw[47] = 0x18; /* data offset=5, flags=PSH|ACK */
        raw[48] = 0xff; raw[49] = 0xff; /* window */
        /* HTTP payload */
        memcpy(raw + 14 + 20 + tcp_hdr_len, http_payload, payload_len);

        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.caplen = pkt.origlen = pkt.raw_len = pkt_len;
        pkt.raw = raw;
        pkt.ts.tv_sec = 1731234568;
        pkt.ts.tv_usec = 234567;

        dissect_packet(&pkt);

        printf("测试2: HTTP GET 请求\n");
        print_packet_detail(&pkt);

        int ok = (pkt.app_proto & APP_HTTP) && (pkt.tcp.dst_port == 80);
        printf("  结果: %s\n\n", ok ? "✓ PASS" : "✗ FAIL");
        if (ok) passed++;
        free(pkt.raw);
    }

    /* 测试3: DNS 查询 (UDP) */
    {
        total++;
        uint8_t dns_query[] = {
            0x12, 0x34,  /* Transaction ID */
            0x01, 0x00,  /* Flags: standard query */
            0x00, 0x01,  /* Questions: 1 */
            0x00, 0x00,  /* Answer RRs: 0 */
            0x00, 0x00,  /* Authority RRs: 0 */
            0x00, 0x00,  /* Additional RRs: 0 */
            /* Query: example.com, Type A, Class IN */
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,        /* root label */
            0x00, 0x01,  /* Type: A */
            0x00, 0x01,  /* Class: IN */
        };
        int dns_len = (int)sizeof(dns_query);
        int udp_len = 8 + dns_len;
        int ip_total = 20 + udp_len;
        int pkt_len = 14 + ip_total;

        uint8_t *raw = (uint8_t *)malloc(pkt_len);
        memset(raw, 0, pkt_len);

        /* Ethernet */
        raw[12] = 0x08; raw[13] = 0x00;
        /* IPv4 */
        raw[14] = 0x45;
        raw[16] = (ip_total >> 8) & 0xff; raw[17] = ip_total & 0xff;
        raw[22] = 64; raw[23] = 17; /* TTL=64, proto=UDP */
        raw[26] = 0xc0; raw[27] = 0xa8; raw[28] = 0x01; raw[29] = 0x64;
        raw[30] = 0x08; raw[31] = 0x08; raw[32] = 0x08; raw[33] = 0x08; /* 8.8.8.8 */
        /* UDP */
        raw[34] = 0xc0; raw[35] = 0x00; /* src port 49152 */
        raw[36] = 0x00; raw[37] = 0x35; /* dst port 53 */
        raw[38] = (udp_len >> 8) & 0xff; raw[39] = udp_len & 0xff;
        /* DNS payload */
        memcpy(raw + 14 + 20 + 8, dns_query, dns_len);

        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.caplen = pkt.origlen = pkt.raw_len = pkt_len;
        pkt.raw = raw;
        pkt.ts.tv_sec = 1731234569;
        pkt.ts.tv_usec = 345678;

        dissect_packet(&pkt);

        printf("测试3: DNS 查询 (example.com, Type A)\n");
        print_packet_detail(&pkt);

        int ok = (pkt.app_proto & APP_DNS) && (pkt.udp.dst_port == 53);
        printf("  结果: %s\n\n", ok ? "✓ PASS" : "✗ FAIL");
        if (ok) passed++;
        free(pkt.raw);
    }

    /* 测试4: ARP 请求 */
    {
        total++;
        uint8_t raw[] = {
            /* Ethernet */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* dst: broadcast */
            0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef,  /* src MAC */
            0x08, 0x06,                            /* EtherType: ARP */
            /* ARP */
            0x00, 0x01,  /* Hardware type: Ethernet */
            0x08, 0x00,  /* Protocol type: IPv4 */
            0x06,        /* Hardware size: 6 */
            0x04,        /* Protocol size: 4 */
            0x00, 0x01,  /* Opcode: request */
            0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef,  /* Sender MAC */
            0xc0, 0xa8, 0x01, 0x64,               /* Sender IP: 192.168.1.100 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* Target MAC: unknown */
            0xc0, 0xa8, 0x01, 0x01,               /* Target IP: 192.168.1.1 */
        };

        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.caplen = pkt.origlen = pkt.raw_len = sizeof(raw);
        pkt.raw = (uint8_t *)malloc(sizeof(raw));
        memcpy(pkt.raw, raw, sizeof(raw));
        pkt.ts.tv_sec = 1731234570;
        pkt.ts.tv_usec = 456789;

        dissect_packet(&pkt);

        printf("测试4: ARP 请求 (Who has 192.168.1.1?)\n");
        print_packet_detail(&pkt);

        int ok = (pkt.is_arp && pkt.arp.opcode == 1);
        printf("  结果: %s\n\n", ok ? "✓ PASS" : "✗ FAIL");
        if (ok) passed++;
        free(pkt.raw);
    }

    /* 测试5: 显示过滤引擎 */
    {
        total++;
        printf("测试5: 显示过滤引擎\n");

        /* 构造一个 TCP 包用于过滤测试 */
        uint8_t raw[] = {
            0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef,
            0x00, 0x50, 0x56, 0xc0, 0x00, 0x01,
            0x08, 0x00,
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0xc0, 0xa8, 0x01, 0x64,
            0x5d, 0xb8, 0xd8, 0x22,
            0x00, 0x50, 0xd4, 0x31,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00,
        };

        packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.caplen = pkt.origlen = pkt.raw_len = sizeof(raw);
        pkt.raw = (uint8_t *)malloc(sizeof(raw));
        memcpy(pkt.raw, raw, sizeof(raw));
        dissect_packet(&pkt);

        char errmsg[256];
        int ok = 1;

        /* 测试: tcp */
        filter_compile("tcp", errmsg, sizeof(errmsg));
        ok &= filter_match(&pkt);
        printf("  filter \"tcp\" → %s\n", ok ? "匹配 ✓" : "不匹配 ✗");

        /* 测试: udp (应该不匹配) */
        filter_compile("udp", errmsg, sizeof(errmsg));
        int not_match = !filter_match(&pkt);
        ok &= not_match;
        printf("  filter \"udp\" → %s\n", not_match ? "不匹配 ✓" : "匹配 ✗");

        /* 测试: tcp and tcp.port == 80 */
        filter_compile("tcp and tcp.port == 80", errmsg, sizeof(errmsg));
        int m = filter_match(&pkt);
        ok &= m;
        printf("  filter \"tcp and tcp.port == 80\" → %s\n", m ? "匹配 ✓" : "不匹配 ✗");

        /* 测试: tcp and not tcp.port == 80 (应该不匹配) */
        filter_compile("tcp and not tcp.port == 80", errmsg, sizeof(errmsg));
        int nm = !filter_match(&pkt);
        ok &= nm;
        printf("  filter \"tcp and not tcp.port == 80\" → %s\n", nm ? "不匹配 ✓" : "匹配 ✗");

        /* 测试: ip.addr == 192.168.1.100 */
        filter_compile("ip.addr == 192.168.1.100", errmsg, sizeof(errmsg));
        int m2 = filter_match(&pkt);
        ok &= m2;
        printf("  filter \"ip.addr == 192.168.1.100\" → %s\n", m2 ? "匹配 ✓" : "不匹配 ✗");

        filter_free();
        printf("  结果: %s\n\n", ok ? "✓ PASS" : "✗ FAIL");
        if (ok) passed++;
        free(pkt.raw);
    }

    printf("==== 测试总结: %d/%d 通过 ====\n", passed, total);
    return (passed == total) ? 0 : 1;
}

/* ---- 用法说明 ---- */
static void print_usage(const char *prog)
{
    printf("UCAS 网络嗅探器 - 软件与系统安全实验 1A\n\n");
    printf("用法:\n");
    printf("  %s                      TUI 交互模式（默认）\n", prog);
    printf("  %s --list               列出可用网卡\n", prog);
    printf("  %s --cli <dev> [count]  命令行抓包模式\n", prog);
    printf("  %s --test               协议解析自测（构造模拟包验证解析）\n", prog);
    printf("  %s --cli <dev> --bpf \"tcp port 80\" [count]  带 BPF 过滤\n", prog);
    printf("\n交互模式快捷键:\n");
    printf("  d=选择网卡  s=开始/停止抓包  f=显示过滤  c=清空\n");
    printf("  ↑↓=滚动  Tab=切换面板  q=退出\n");
}

int main(int argc, char *argv[])
{
    store_init();
    stream_init_all();
    capture_set_bpf("");

    /* 解析命令行参数 */
    if (argc >= 2) {
        if (strcmp(argv[1], "--list") == 0 || strcmp(argv[1], "-l") == 0) {
            return cmd_list_devs();
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[1], "--test") == 0 || strcmp(argv[1], "-t") == 0) {
            return cmd_test();
        }
        if (strcmp(argv[1], "--cli") == 0 || strcmp(argv[1], "-c") == 0) {
            if (argc < 3) {
                fprintf(stderr, "用法: %s --cli <dev> [count]\n", argv[0]);
                return 1;
            }
            const char *dev = argv[2];
            const char *bpf = NULL;
            int count = 20;
            /* 解析可选参数 */
            for (int i = 3; i < argc; i++) {
                if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
                    bpf = argv[i + 1];
                    i++;
                } else {
                    count = atoi(argv[i]);
                    if (count <= 0) count = 20;
                }
            }
            return cmd_cli_capture(dev, count, bpf);
        }
    }

    /* 默认 TUI 模式 */
    ui_init();
    ui_run();

    capture_stop();
    filter_free();
    stream_clear_all();
    ui_cleanup();

    return 0;
}
