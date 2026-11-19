/*
 * ui.c - ncurses TUI 主界面实现
 *
 * 布局：
 *   [状态栏]  网卡 | 状态 | 过滤 | 包数
 *   [包列表]  No. Time Src Dst Proto Len Info  (可滚动/选中)
 *   [详情树]  Ethernet > IPv4 > TCP > HTTP...  (可展开折叠)
 *   [Hex视图] 偏移 十六进制 ASCII
 *   [帮助栏]  快捷键提示
 *
 * 交互：
 *   ↑↓       包列表滚动
 *   Enter    选中包，更新详情和Hex
 *   ←→       切换三栏焦点
 *   Tab      切换面板
 *   f        输入显示过滤
 *   c        清空
 *   s        开始/停止抓包
 *   q        退出
 */
#include "ui.h"
#include "../packet.h"
#include "../capture.h"
#include "../filter.h"
#include "../stream.h"
#include <ncurses.h>
#include <locale.h>   /* setlocale - 中文显示必需 */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

/* 面板枚举 */
typedef enum { PANEL_LIST, PANEL_DETAIL, PANEL_HEX } panel_t;

/* 全局 UI 状态 */
static struct {
    WINDOW *win_status;   /* 状态栏 */
    WINDOW *win_list;     /* 包列表 */
    WINDOW *win_detail;   /* 详情树 */
    WINDOW *win_hex;      /* hex dump */
    WINDOW *win_help;     /* 帮助栏 */

    int      rows, cols;
    panel_t  focus;       /* 当前焦点面板 */

    int      list_sel;    /* 列表选中行（逻辑索引） */
    int      list_scroll; /* 列表滚动偏移 */
    int      detail_scroll;
    int      hex_scroll;

    char     dev[256];    /* 当前网卡 */
    char     display_filter[256]; /* 显示过滤 */
    int      filtering;   /* 是否启用显示过滤 */
} ui;

/* 信号：新包到达（capture.c 设置） */
volatile int g_new_packet_signal = 0;

/* ---- 窗口尺寸计算 ---- */
static int list_rows(void)    { return ui.rows - 2 - 10 - 8 - 2; } /* 减去状态栏2 + 详情10 + hex8 + 帮助2，至少8 */
static int detail_rows(void)  { return 10; }
static int hex_rows(void)     { return 8; }

/* ---- 创建窗口 ---- */
static void create_windows(void)
{
    getmaxyx(stdscr, ui.rows, ui.cols);

    int status_h = 2;
    int list_h   = list_rows();
    if (list_h < 4) list_h = 4;
    int detail_h = detail_rows();
    int hex_h    = hex_rows();
    int help_h   = 2;

    int y = 0;
    if (ui.win_status) delwin(ui.win_status);
    if (ui.win_list)   delwin(ui.win_list);
    if (ui.win_detail) delwin(ui.win_detail);
    if (ui.win_hex)    delwin(ui.win_hex);
    if (ui.win_help)   delwin(ui.win_help);

    ui.win_status = newwin(status_h, ui.cols, y, 0);             y += status_h;
    ui.win_list   = newwin(list_h,   ui.cols, y, 0);             y += list_h;
    ui.win_detail = newwin(detail_h, ui.cols, y, 0);             y += detail_h;
    ui.win_hex    = newwin(hex_h,    ui.cols, y, 0);             y += hex_h;
    ui.win_help   = newwin(help_h,   ui.cols, y, 0);
}

/* ---- 绘制状态栏 ---- */
static void draw_status(void)
{
    werase(ui.win_status);
    wattron(ui.win_status, A_REVERSE);
    mvwprintw(ui.win_status, 0, 0, " UCAS Sniffer ");
    wattroff(ui.win_status, A_REVERSE);

    int total = store_visible_count();
    mvwprintw(ui.win_status, 0, 16, "网卡: %s", ui.dev[0] ? ui.dev : "(未选择)");
    mvwprintw(ui.win_status, 0, 16 + 40, "状态: %s", capture_is_running() ? "抓包中" : "已停止");
    mvwprintw(ui.win_status, 0, 16 + 60, "包数: %d", total);

    if (ui.filtering && ui.display_filter[0])
        mvwprintw(ui.win_status, 1, 0, "显示过滤: %s", ui.display_filter);
    else
        mvwprintw(ui.win_status, 1, 0, "显示过滤: (无)");

    mvwprintw(ui.win_status, 1, ui.cols - 20, "焦点: %-8s",
              ui.focus == PANEL_LIST ? "列表" : ui.focus == PANEL_DETAIL ? "详情" : "Hex");

    wrefresh(ui.win_status);
}

/* ---- 绘制包列表 ---- */
static void draw_list(void)
{
    werase(ui.win_list);

    /* 标题行（col=1 避开 box 左边框） */
    wattron(ui.win_list, A_REVERSE);
    mvwprintw(ui.win_list, 0, 1, "%-6s %-10s %-18s %-18s %-6s %-5s %s",
              "No.", "Time", "Source", "Destination", "Proto", "Len", "Info");
    wattroff(ui.win_list, A_REVERSE);

    int avail = list_rows() - 1; /* 减标题行 */
    int total = store_visible_count();

    /* 计算可见包（应用显示过滤） */
    int shown = 0;
    int logical = 0;

    for (int i = 0; i < total && shown < avail; i++) {
        packet_t *pkt = store_get(i);
        if (!pkt) continue;

        /* 应用显示过滤 */
        if (ui.filtering && ui.display_filter[0]) {
            if (!filter_match(pkt))
                continue;
        }

        int row = shown + 1;

        /* 滚动：只显示 list_scroll 之后的 */
        if (shown < ui.list_scroll) {
            shown++;
            logical++;
            continue;
        }

        /* 时间格式化 */
        char tbuf[16];
        struct tm *tm = localtime(&pkt->ts.tv_sec);
        snprintf(tbuf, sizeof(tbuf), "%02d:%02d:%02d.%03d",
                 tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(pkt->ts.tv_usec / 1000));

        /* 高亮选中行 */
        if (logical == ui.list_sel && ui.focus == PANEL_LIST) {
            wattron(ui.win_list, A_REVERSE);
        }

        /* 截断 Info 到剩余宽度 */
        int info_w = ui.cols - 6 - 11 - 19 - 19 - 7 - 6 - 2; /* -2 for box borders */
        if (info_w < 4) info_w = 4;
        char info_trunc[256];
        int il = strlen(pkt->info);
        if (il > info_w) il = info_w;
        memcpy(info_trunc, pkt->info, il);
        info_trunc[il] = '\0';

        /* col=1 避开 box 左边框 */
        mvwprintw(ui.win_list, row, 1, "%-6d %-10s %-18s %-18s %-6s %-5d %s",
                  pkt->seq, tbuf,
                  pkt->src_addr[0] ? pkt->src_addr : "?",
                  pkt->dst_addr[0] ? pkt->dst_addr : "?",
                  pkt->protocol, pkt->origlen, info_trunc);

        if (logical == ui.list_sel && ui.focus == PANEL_LIST) {
            wattroff(ui.win_list, A_REVERSE);
        }

        shown++;
        logical++;
    }

    /* 边框 */
    box(ui.win_list, 0, 0);
    wrefresh(ui.win_list);
}

/* ---- 绘制详情树 ---- */
static void draw_detail(void)
{
    werase(ui.win_detail);
    box(ui.win_detail, 0, 0);

    mvwprintw(ui.win_detail, 0, 2, " 协议字段详情 ");

    /* 获取选中的包 */
    packet_t *pkt = store_get(ui.list_sel);
    if (!pkt) {
        mvwprintw(ui.win_detail, 1, 2, "(未选中数据包)");
        wrefresh(ui.win_detail);
        return;
    }

    /* 遍历节点树，深度优先输出 */
    int avail = detail_rows() - 2; /* 减去边框 */
    int shown = 0;

    /* 简单的深度优先遍历 */
    for (int i = 0; i < pkt->node_count && shown < avail + ui.detail_scroll; i++) {
        /* 判断是否是根节点（没有父节点被引用） */
        int is_root = 1;
        for (int j = 0; j < i; j++) {
            if (pkt->nodes[j].first_child == i) {
                is_root = 0;
                break;
            }
        }
        /* 检查是否是某节点的子节点 */
        if (!is_root) continue;

        /* 深度优先 */
        int stack[64], depths[64];
        int sp = 0;
        stack[0] = i;
        depths[0] = 0;
        sp = 1;

        while (sp > 0 && shown < avail + ui.detail_scroll) {
            int node = stack[sp - 1];
            int depth = depths[sp - 1];
            sp--;

            if (shown >= ui.detail_scroll) {
                int row = shown - ui.detail_scroll + 1;
                if (row >= 1 && row < avail + 1) {
                    /* 缩进 */
                    for (int d = 0; d < depth; d++)
                        mvwprintw(ui.win_detail, row, 2 + d * 2, "  ");
                    /* 节点名和值 */
                    if (pkt->nodes[node].value[0]) {
                        int maxw = ui.cols - 4 - depth * 2 - 2;
                        char val_trunc[NODE_VAL_LEN];
                        int vl = strlen(pkt->nodes[node].value);
                        if (vl > maxw) vl = maxw;
                        memcpy(val_trunc, pkt->nodes[node].value, vl);
                        val_trunc[vl] = '\0';
                        mvwprintw(ui.win_detail, row, 2 + depth * 2, "%s: %s",
                                  pkt->nodes[node].name, val_trunc);
                    } else {
                        wattron(ui.win_detail, A_BOLD);
                        mvwprintw(ui.win_detail, row, 2 + depth * 2, "%s", pkt->nodes[node].name);
                        wattroff(ui.win_detail, A_BOLD);
                    }
                }
            }
            shown++;

            /* 子节点逆序入栈（保证正序输出） */
            int child = pkt->nodes[node].first_child;
            /* 收集所有子节点 */
            int children[64];
            int cc = 0;
            while (child >= 0 && cc < 64) {
                children[cc++] = child;
                child = pkt->nodes[child].next_sibling;
            }
            for (int c = cc - 1; c >= 0; c--) {
                if (sp < 63) {
                    stack[sp] = children[c];
                    depths[sp] = depth + 1;
                    sp++;
                }
            }
        }
    }

    wrefresh(ui.win_detail);
}

/* ---- 绘制 Hex Dump ---- */
static void draw_hex(void)
{
    werase(ui.win_hex);
    box(ui.win_hex, 0, 0);
    mvwprintw(ui.win_hex, 0, 2, " Hex Dump ");

    packet_t *pkt = store_get(ui.list_sel);
    if (!pkt || !pkt->raw) {
        mvwprintw(ui.win_hex, 1, 2, "(无数据)");
        wrefresh(ui.win_hex);
        return;
    }

    int avail = hex_rows() - 2; /* 减边框 */
    int total_bytes = pkt->raw_len;
    int bytes_per_line = 16;
    int total_lines = (total_bytes + bytes_per_line - 1) / bytes_per_line;

    for (int line = ui.hex_scroll; line < total_lines && line < ui.hex_scroll + avail; line++) {
        int row = line - ui.hex_scroll + 1;
        int offset = line * bytes_per_line;

        /* 偏移 */
        wattron(ui.win_hex, A_DIM);
        mvwprintw(ui.win_hex, row, 1, "%04x  ", offset);
        wattroff(ui.win_hex, A_DIM);

        /* 十六进制字节 */
        int col = 8;
        for (int b = 0; b < bytes_per_line && offset + b < total_bytes; b++) {
            uint8_t byte = pkt->raw[offset + b];
            /* 高亮选中包中协议字段部分可以扩展 */
            mvwprintw(ui.win_hex, row, col, "%02x ", byte);
            col += 3;
        }

        /* ASCII */
        col = 8 + bytes_per_line * 3 + 2;
        for (int b = 0; b < bytes_per_line && offset + b < total_bytes; b++) {
            uint8_t byte = pkt->raw[offset + b];
            char c = (byte >= 0x20 && byte < 0x7f) ? (char)byte : '.';
            mvwprintw(ui.win_hex, row, col + b, "%c", c);
        }
    }

    wrefresh(ui.win_hex);
}

/* ---- 绘制帮助栏 ---- */
static void draw_help(void)
{
    werase(ui.win_help);
    wattron(ui.win_help, A_REVERSE);
    mvwprintw(ui.win_help, 0, 0, " [s]开始/停止  [↑↓]滚动  [Enter]选中  [f]显示过滤  [c]清空  [Tab]切换面板  [q]退出 ");
    wattroff(ui.win_help, A_REVERSE);
    wrefresh(ui.win_help);
}

/* ---- 刷新所有 ---- */
static void draw_all(void)
{
    draw_status();
    draw_list();
    draw_detail();
    draw_hex();
    draw_help();
}

/* ---- 输入对话框（简单行输入） ---- */
static int input_line(const char *prompt, char *buf, int bufsize)
{
    timeout(-1);  /* 切换到阻塞模式（主循环用的 timeout(100) 会让输入立刻超时） */
    echo();
    curs_set(1);
    int old_y, old_x;
    getyx(stdscr, old_y, old_x);

    /* 在底部状态栏区域输入 */
    mvprintw(ui.rows - 3, 0, "%s", prompt);
    clrtoeol();
    refresh();
    int ret = getnstr(buf, bufsize - 1);

    noecho();
    curs_set(0);
    move(old_y, old_x);
    return ret;
}

/* ---- 选择网卡 ---- */
static void select_device(void)
{
    pcap_if_t *devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (capture_list_devs(&devs, errbuf) != 0) {
        timeout(-1);
        mvprintw(ui.rows - 3, 0, "无法获取网卡列表: %s", errbuf);
        getch();
        return;
    }

    /* 列出网卡 */
    int y = ui.rows - 3;
    const char *def_dev = capture_default_dev();
    mvprintw(y, 0, "选择网卡 (输入序号, 直接回车=默认[%s]):", def_dev);
    clrtoeol();

    pcap_if_t *d = devs;
    int idx = 0;
    int def_idx = -1;  /* 默认网卡序号 */
    char dev_names[32][256];
    while (d && idx < 32) {
        int is_default = (strcmp(d->name, def_dev) == 0);
        if (is_default)
            def_idx = idx;
        mvprintw(y + idx + 1, 0, "  [%d] %-12s %s%s%s",
                 idx, d->name,
                 is_default ? "[默认] " : "",
                 d->description ? d->description : "",
                 is_default ? " <-- 推荐选择, 有正常网络流量" :
                 (strncmp(d->name, "utun", 4) == 0 || strncmp(d->name, "lo", 2) == 0)
                   ? " (虚拟/回环接口, 通常无流量)" : "");
        strncpy(dev_names[idx], d->name, sizeof(dev_names[idx]) - 1);
        dev_names[idx][sizeof(dev_names[idx]) - 1] = '\0';
        idx++;
        d = d->next;
    }

    char buf[8];
    timeout(-1);  /* 阻塞模式等待输入 */
    echo();
    curs_set(1);
    getnstr(buf, sizeof(buf) - 1);
    noecho();
    curs_set(0);

    int sel;
    if (buf[0] == '\0') {
        /* 直接回车 → 选默认网卡 */
        sel = def_idx;
    } else {
        sel = atoi(buf);
    }

    if (sel >= 0 && sel < idx) {
        strncpy(ui.dev, dev_names[sel], sizeof(ui.dev) - 1);
    }

    pcap_freealldevs(devs);
}

/* ---- 开始/停止抓包 ---- */
static void toggle_capture(void)
{
    if (capture_is_running()) {
        capture_stop();
        return;
    }

    if (!ui.dev[0]) {
        select_device();
        if (!ui.dev[0])
            return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if (capture_start(ui.dev, errbuf) != 0) {
        timeout(-1);
        mvprintw(ui.rows - 3, 0, "启动失败: %s", errbuf);
        mvprintw(ui.rows - 2, 0, "如提示权限不足, 请在终端执行: sudo chmod o+rw /dev/bpf*");
        mvprintw(ui.rows - 1, 0, "(按任意键继续)");
        getch();
    }
}

/* ---- 输入显示过滤 ---- */
static void input_display_filter(void)
{
    char buf[256];
    if (input_line("显示过滤 (如 tcp and tcp.port==80): ", buf, sizeof(buf)) == 0) {
        strncpy(ui.display_filter, buf, sizeof(ui.display_filter) - 1);
        if (buf[0]) {
            char errmsg[256];
            if (filter_compile(buf, errmsg, sizeof(errmsg)) != 0) {
                ui.display_filter[0] = '\0';
                timeout(-1);
                mvprintw(ui.rows - 3, 0, "过滤表达式错误: %s (按任意键)", errmsg);
                getch();
                ui.filtering = 0;
            } else {
                ui.filtering = 1;
            }
        } else {
            filter_free();
            ui.filtering = 0;
        }
        ui.list_sel = 0;
        ui.list_scroll = 0;
    }
}

/* ---- 主事件循环 ---- */
void ui_run(void)
{
    int ch;
    int last_count = 0;

    while (1) {
        /* 检查新包 */
        int cur_count = store_visible_count();
        if (cur_count != last_count) {
            last_count = cur_count;
            draw_all();
        }

        /* 处理 TCP 流重组 */
        if (cur_count > 0) {
            packet_t *latest = store_get(cur_count - 1);
            if (latest)
                stream_process_packet(latest);
        }

        /* 超时非阻塞读取 */
        timeout(100);
        ch = getch();

        if (ch == ERR)
            continue;

        switch (ch) {
        case 'q':
            return;
        case 's':
            toggle_capture();
            draw_all();
            break;
        case 'f':
            input_display_filter();
            draw_all();
            break;
        case 'c':
            store_clear();
            stream_clear_all();
            ui.list_sel = 0;
            ui.list_scroll = 0;
            draw_all();
            break;
        case 'd':
            select_device();
            draw_all();
            break;
        case '\t': /* Tab 切换面板 */
            ui.focus = (ui.focus + 1) % 3;
            draw_all();
            break;
        case KEY_UP:
            if (ui.focus == PANEL_LIST) {
                if (ui.list_sel > 0) ui.list_sel--;
                if (ui.list_sel < ui.list_scroll) ui.list_scroll = ui.list_sel;
            } else if (ui.focus == PANEL_DETAIL) {
                if (ui.detail_scroll > 0) ui.detail_scroll--;
            } else if (ui.focus == PANEL_HEX) {
                if (ui.hex_scroll > 0) ui.hex_scroll--;
            }
            draw_all();
            break;
        case KEY_DOWN:
            if (ui.focus == PANEL_LIST) {
                if (ui.list_sel < store_visible_count() - 1) ui.list_sel++;
                int avail = list_rows() - 1;
                if (ui.list_sel >= ui.list_scroll + avail)
                    ui.list_scroll = ui.list_sel - avail + 1;
            } else if (ui.focus == PANEL_DETAIL) {
                ui.detail_scroll++;
            } else if (ui.focus == PANEL_HEX) {
                ui.hex_scroll++;
            }
            draw_all();
            break;
        case KEY_LEFT:
            ui.focus = PANEL_LIST;
            draw_all();
            break;
        case KEY_RIGHT:
            ui.focus = (ui.focus + 1) % 3;
            draw_all();
            break;
        case '\n':
        case KEY_ENTER:
            draw_all();
            break;
        case KEY_PPAGE: /* PageUp */
            if (ui.focus == PANEL_LIST) {
                int avail = list_rows() - 1;
                ui.list_sel -= avail;
                if (ui.list_sel < 0) ui.list_sel = 0;
                ui.list_scroll = ui.list_sel;
            }
            draw_all();
            break;
        case KEY_NPAGE: /* PageDown */
            if (ui.focus == PANEL_LIST) {
                int avail = list_rows() - 1;
                ui.list_sel += avail;
                int max = store_visible_count() - 1;
                if (ui.list_sel > max) ui.list_sel = max;
                if (ui.list_sel >= ui.list_scroll + avail)
                    ui.list_scroll = ui.list_sel - avail + 1;
            }
            draw_all();
            break;
        case KEY_RESIZE:
            create_windows();
            draw_all();
            break;
        default:
            /* 更新显示（定期刷新） */
            draw_all();
            break;
        }
    }
}

void ui_init(void)
{
    /* 必须在 initscr() 之前设置 locale，否则中文（UTF-8 多字节字符）会乱码 */
    setlocale(LC_ALL, "");

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    halfdelay(1); /* 0.1秒超时 */

    start_color();
    use_default_colors();

    memset(&ui, 0, sizeof(ui));

    /* 自动选中默认网卡（en0/Wi-Fi 等），省去手动选择 */
    const char *def = capture_default_dev();
    if (def)
        strncpy(ui.dev, def, sizeof(ui.dev) - 1);

    create_windows();
    draw_all();
}

void ui_cleanup(void)
{
    endwin();
}
