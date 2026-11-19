/*
 * ui.h - TUI 界面接口 (ncurses)
 *
 * 三栏布局（仿 Wireshark）：
 *   ┌────────── 状态栏 ──────────┐
 *   ├── 包列表 (可滚动)          ├──
 *   ├── 协议字段树 (可展开折叠)  ├──
 *   ├── Hex Dump + ASCII         ├──
 *   └──────── 帮助栏 ────────────┘
 */
#ifndef UI_H
#define UI_H

/* 初始化 TUI */
void ui_init(void);

/* 主循环（阻塞直到用户退出） */
void ui_run(void);

/* 清理 */
void ui_cleanup(void);

#endif /* UI_H */
