/*
 * capture.h - libpcap 抓包核心接口
 */
#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>
#include <pthread.h>
#include "packet.h"

/* 抓包状态 */
typedef enum {
    CAP_IDLE,
    CAP_RUNNING,
    CAP_STOPPED,
} cap_state_t;

typedef struct {
    pcap_t        *handle;
    char           dev[256];        /* 当前网卡名 */
    char           bpf_filter[256]; /* BPF 捕获过滤表达式 */
    cap_state_t    state;
    pthread_t      thread;
    char           errbuf[PCAP_ERRBUF_SIZE];
} capturer_t;

extern capturer_t g_cap;

/* 获取网卡列表。返回数组，count 填数量。调用方负责 pcap_freealldevs */
int  capture_list_devs(pcap_if_t **devs, char *errbuf);

/* 设置 BPF 过滤（在打开前设置） */
void capture_set_bpf(const char *filter);

/* 启动抓包线程。dev=网卡名。成功返回0 */
int  capture_start(const char *dev, char *errbuf);

/* 停止抓包 */
void capture_stop(void);

/* 是否正在抓包 */
int  capture_is_running(void);

/* 获取默认网卡名（macOS: en0/Wi-Fi, Linux: 通过路由表）。返回静态缓冲区或 NULL */
const char *capture_default_dev(void);

#endif /* CAPTURE_H */
