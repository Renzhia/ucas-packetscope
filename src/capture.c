/*
 * capture.c - libpcap 抓包核心实现
 */
#include "capture.h"
#include "dissect/dissect.h"
#include <string.h>
#include <stdlib.h>
#include <signal.h>

capturer_t g_cap = {0};

/* 回调：每捕获一个包调用 */
static void capture_callback(unsigned char *user,
                             const struct pcap_pkthdr *hdr,
                             const unsigned char *bytes)
{
    (void)user;
    if (g_cap.state != CAP_RUNNING)
        return;

    /* 构造 packet_t */
    packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.ts     = hdr->ts;
    pkt.caplen = (int)hdr->caplen;
    pkt.origlen = (int)hdr->len;
    pkt.raw_len = (int)hdr->caplen;

    /* 拷贝原始字节 */
    pkt.raw = (uint8_t *)malloc(pkt.raw_len);
    if (!pkt.raw)
        return;
    memcpy(pkt.raw, bytes, pkt.raw_len);

    /* 解析协议栈 */
    dissect_packet(&pkt);

    /* 存入环形缓冲 */
    store_add(&pkt);

    /* 通知 UI 新包到达（通过全局计数，UI 定时刷新或 idle 回调读取） */
    /* g_new_count 由 UI 轮询 */
    extern volatile int g_new_packet_signal;
    g_new_packet_signal = 1;
}

/* 抓包线程入口 */
static void *capture_thread(void *arg)
{
    (void)arg;
    /* pcap_loop 阻塞直到 break_loop 或出错 */
    int ret = pcap_loop(g_cap.handle, -1, capture_callback, NULL);
    if (ret == -1) {
        /* 出错 */
    }
    g_cap.state = CAP_STOPPED;
    return NULL;
}

int capture_list_devs(pcap_if_t **devs, char *errbuf)
{
    if (pcap_findalldevs(devs, errbuf) == -1)
        return -1;
    return 0;
}

void capture_set_bpf(const char *filter)
{
    if (filter)
        strncpy(g_cap.bpf_filter, filter, sizeof(g_cap.bpf_filter) - 1);
    else
        g_cap.bpf_filter[0] = '\0';
}

int capture_start(const char *dev, char *errbuf)
{
    if (g_cap.state == CAP_RUNNING)
        return -1;

    strncpy(g_cap.dev, dev, sizeof(g_cap.dev) - 1);

    /* 打开网卡 */
    g_cap.handle = pcap_open_live(dev, SNAPLEN, 1, 1000, errbuf);
    if (!g_cap.handle) {
        return -1;
    }

    /* 设置 BPF 过滤 */
    if (g_cap.bpf_filter[0] != '\0') {
        struct bpf_program fp;
        if (pcap_compile(g_cap.handle, &fp, g_cap.bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            snprintf(errbuf + strlen(errbuf), PCAP_ERRBUF_SIZE,
                     "\nBPF 编译失败: %s", pcap_geterr(g_cap.handle));
            pcap_close(g_cap.handle);
            g_cap.handle = NULL;
            return -1;
        }
        if (pcap_setfilter(g_cap.handle, &fp) == -1) {
            snprintf(errbuf + strlen(errbuf), PCAP_ERRBUF_SIZE,
                     "\nBPF 设置失败: %s", pcap_geterr(g_cap.handle));
            pcap_freecode(&fp);
            pcap_close(g_cap.handle);
            g_cap.handle = NULL;
            return -1;
        }
        pcap_freecode(&fp);
    }

    g_cap.state = CAP_RUNNING;

    /* 启动抓包线程 */
    if (pthread_create(&g_cap.thread, NULL, capture_thread, NULL) != 0) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "无法创建抓包线程");
        pcap_close(g_cap.handle);
        g_cap.handle = NULL;
        g_cap.state = CAP_IDLE;
        return -1;
    }

    return 0;
}

void capture_stop(void)
{
    if (g_cap.state != CAP_RUNNING)
        return;

    g_cap.state = CAP_STOPPED;
    if (g_cap.handle) {
        pcap_breakloop(g_cap.handle);
    }
    if (g_cap.thread) {
        pthread_join(g_cap.thread, NULL);
        g_cap.thread = 0;
    }
    if (g_cap.handle) {
        pcap_close(g_cap.handle);
        g_cap.handle = NULL;
    }
}

int capture_is_running(void)
{
    return g_cap.state == CAP_RUNNING;
}

/* 获取默认网卡：通过路由表查找 default 路由的接口 */
const char *capture_default_dev(void)
{
    static char dev[64] = {0};

    /* 已缓存 */
    if (dev[0])
        return dev;

    /* macOS/Linux: 从路由表获取默认接口 */
    FILE *fp = popen("route -n get default 2>/dev/null | grep 'interface' | awk '{print $2}'", "r");
    if (fp) {
        if (fgets(dev, sizeof(dev), fp)) {
            /* 去掉末尾换行 */
            dev[strcspn(dev, "\r\n")] = '\0';
            if (dev[0])
                return dev;
        }
        pclose(fp);
    }

    /* 降级：pcap_lookupdev（已弃用但仍可用） */
    char errbuf[PCAP_ERRBUF_SIZE];
    char *lookup = pcap_lookupdev(errbuf);
    if (lookup) {
        strncpy(dev, lookup, sizeof(dev) - 1);
        return dev;
    }

    /* 最终降级：macOS 默认 en0 */
    strcpy(dev, "en0");
    return dev;
}
