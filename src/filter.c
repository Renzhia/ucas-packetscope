/*
 * filter.c - 显示过滤表达式引擎实现
 *
 * 递归下降解析器:
 *   expr  := term ( ('and' | 'or') term )*
 *   term  := 'not' term | '(' expr ')' | predicate
 *   predicate := protocol_name | field '==' value
 *
 * 字段支持:
 *   ip.addr, ip.src, ip.dst        — IPv4 地址
 *   tcp.port, tcp.srcport, tcp.dstport
 *   tcp.flags.syn, tcp.flags.ack, tcp.flags.fin, tcp.flags.rst
 *   udp.port
 */
#include "filter.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ---------- 词法 ---------- */
typedef enum {
    TOK_END,
    TOK_AND,
    TOK_OR,
    TOK_NOT,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_EQ,         /* == */
    TOK_STRING,     /* 标识符或值 */
    TOK_NUMBER,
} token_type_t;

typedef struct {
    token_type_t type;
    char         text[128];
} token_t;

typedef struct {
    const char *src;
    int         pos;
    token_t     cur;
    char        error[256];
    int         has_error;
} lexer_t;

static void lex_skip_ws(lexer_t *lx)
{
    while (lx->src[lx->pos] && isspace((unsigned char)lx->src[lx->pos]))
        lx->pos++;
}

static void lex_next(lexer_t *lx)
{
    lex_skip_ws(lx);
    char c = lx->src[lx->pos];
    if (c == '\0') {
        lx->cur.type = TOK_END;
        return;
    }
    if (c == '(') { lx->pos++; lx->cur.type = TOK_LPAREN; return; }
    if (c == ')') { lx->pos++; lx->cur.type = TOK_RPAREN; return; }
    if (c == '=' && lx->src[lx->pos + 1] == '=') {
        lx->pos += 2; lx->cur.type = TOK_EQ; return;
    }

    /* 标识符/数字/关键字 */
    int start = lx->pos;
    if (isdigit((unsigned char)c)) {
        while (lx->src[lx->pos] && (isdigit((unsigned char)lx->src[lx->pos]) ||
                                    lx->src[lx->pos] == '.')) {
            lx->pos++;
        }
        lx->cur.type = TOK_NUMBER;
    } else if (isalpha((unsigned char)c) || c == '_') {
        while (lx->src[lx->pos] && (isalnum((unsigned char)lx->src[lx->pos]) ||
                                    lx->src[lx->pos] == '_' || lx->src[lx->pos] == '.')) {
            lx->pos++;
        }
        lx->cur.type = TOK_STRING;
        /* 检查是否是关键字 */
        int len = lx->pos - start;
        if (len == 3 && strncasecmp(lx->src + start, "and", 3) == 0) {
            lx->cur.type = TOK_AND;
        } else if (len == 2 && strncasecmp(lx->src + start, "or", 2) == 0) {
            lx->cur.type = TOK_OR;
        } else if (len == 3 && strncasecmp(lx->src + start, "not", 3) == 0) {
            lx->cur.type = TOK_NOT;
        }
    }
    int len = lx->pos - start;
    if (len >= (int)sizeof(lx->cur.text))
        len = sizeof(lx->cur.text) - 1;
    memcpy(lx->cur.text, lx->src + start, len);
    lx->cur.text[len] = '\0';
}

static void lex_init(lexer_t *lx, const char *src)
{
    memset(lx, 0, sizeof(*lx));
    lx->src = src;
    lex_next(lx);
}

/* ---------- AST ---------- */
typedef enum {
    AST_AND,
    AST_OR,
    AST_NOT,
    AST_PROTO,       /* 协议名匹配 */
    AST_CMP,         /* 字段比较 */
} ast_type_t;

typedef struct ast_node {
    ast_type_t type;
    struct ast_node *left;
    struct ast_node *right;
    /* AST_PROTO: 协议名在 proto_name */
    char proto_name[32];
    /* AST_CMP: 字段名、值 */
    char field[64];
    char value[128];
    int  is_numeric;
    long numeric_val;
} ast_node_t;

static ast_node_t *new_node(ast_type_t type)
{
    ast_node_t *n = (ast_node_t *)calloc(1, sizeof(ast_node_t));
    n->type = type;
    return n;
}

/* 前向声明 */
static ast_node_t *parse_expr(lexer_t *lx);
static ast_node_t *parse_term(lexer_t *lx);

static ast_node_t *parse_primary(lexer_t *lx)
{
    if (lx->cur.type == TOK_LPAREN) {
        lex_next(lx);
        ast_node_t *e = parse_expr(lx);
        if (lx->cur.type != TOK_RPAREN) {
            lx->has_error = 1;
            snprintf(lx->error, sizeof(lx->error), "缺少右括号 ')'");
            return NULL;
        }
        lex_next(lx);
        return e;
    }
    if (lx->cur.type == TOK_NOT) {
        lex_next(lx);
        ast_node_t *n = new_node(AST_NOT);
        n->left = parse_term(lx);
        return n;
    }
    if (lx->cur.type == TOK_STRING) {
        /* 可能是协议名或字段比较 */
        char name[64];
        strncpy(name, lx->cur.text, sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
        lex_next(lx);

        if (lx->cur.type == TOK_EQ) {
            /* 字段比较 */
            lex_next(lx);
            ast_node_t *n = new_node(AST_CMP);
            strncpy(n->field, name, sizeof(n->field) - 1);
            if (lx->cur.type == TOK_STRING || lx->cur.type == TOK_NUMBER) {
                strncpy(n->value, lx->cur.text, sizeof(n->value) - 1);
                n->is_numeric = (lx->cur.type == TOK_NUMBER);
                if (n->is_numeric)
                    n->numeric_val = atol(lx->cur.text);
                lex_next(lx);
            } else {
                lx->has_error = 1;
                snprintf(lx->error, sizeof(lx->error), "比较运算符后缺少值");
                free(n);
                return NULL;
            }
            return n;
        } else {
            /* 协议名 */
            ast_node_t *n = new_node(AST_PROTO);
            strncpy(n->proto_name, name, sizeof(n->proto_name) - 1);
            return n;
        }
    }
    lx->has_error = 1;
    snprintf(lx->error, sizeof(lx->error), "意外的 token: %s", lx->cur.text);
    return NULL;
}

static ast_node_t *parse_term(lexer_t *lx)
{
    return parse_primary(lx);
}

static ast_node_t *parse_expr(lexer_t *lx)
{
    ast_node_t *left = parse_term(lx);
    while (!lx->has_error && (lx->cur.type == TOK_AND || lx->cur.type == TOK_OR)) {
        ast_type_t op = (lx->cur.type == TOK_AND) ? AST_AND : AST_OR;
        lex_next(lx);
        ast_node_t *right = parse_term(lx);
        ast_node_t *n = new_node(op);
        n->left = left;
        n->right = right;
        left = n;
    }
    return left;
}

/* ---------- 求值 ---------- */
static int match_ip(uint32_t pkt_ip, const char *value)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, value, &addr) != 1)
        return 0;
    return pkt_ip == addr.s_addr;
}

static int eval_node(const ast_node_t *n, const packet_t *pkt)
{
    if (!n)
        return 1;

    switch (n->type) {
    case AST_AND:
        return eval_node(n->left, pkt) && eval_node(n->right, pkt);
    case AST_OR:
        return eval_node(n->left, pkt) || eval_node(n->right, pkt);
    case AST_NOT:
        return !eval_node(n->left, pkt);
    case AST_PROTO: {
        const char *p = n->proto_name;
        if (strcasecmp(p, "tcp") == 0)   return pkt->is_tcp;
        if (strcasecmp(p, "udp") == 0)   return pkt->is_udp;
        if (strcasecmp(p, "icmp") == 0)  return pkt->is_icmp;
        if (strcasecmp(p, "arp") == 0)   return pkt->is_arp;
        if (strcasecmp(p, "http") == 0)  return (pkt->app_proto & APP_HTTP) != 0;
        if (strcasecmp(p, "dns") == 0)   return (pkt->app_proto & APP_DNS) != 0;
        if (strcasecmp(p, "ipv4") == 0 || strcasecmp(p, "ip") == 0) return pkt->is_ipv4;
        if (strcasecmp(p, "ipv6") == 0)  return pkt->is_ipv6;
        return 0;
    }
    case AST_CMP: {
        const char *f = n->field;
        const char *v = n->value;

        if (strcasecmp(f, "ip.addr") == 0 || strcasecmp(f, "ip.src") == 0) {
            if (pkt->is_ipv4)
                return match_ip(pkt->ipv4.src, v) ||
                       (strcasecmp(f, "ip.addr") == 0 && match_ip(pkt->ipv4.dst, v));
        }
        if (strcasecmp(f, "ip.addr") == 0 || strcasecmp(f, "ip.dst") == 0) {
            if (pkt->is_ipv4)
                return match_ip(pkt->ipv4.dst, v) ||
                       (strcasecmp(f, "ip.addr") == 0 && match_ip(pkt->ipv4.src, v));
        }
        if (strcasecmp(f, "tcp.port") == 0 || strcasecmp(f, "tcp.srcport") == 0) {
            if (pkt->is_tcp)
                return pkt->tcp.src_port == (uint16_t)n->numeric_val ||
                       (strcasecmp(f, "tcp.port") == 0 && pkt->tcp.dst_port == (uint16_t)n->numeric_val);
        }
        if (strcasecmp(f, "tcp.port") == 0 || strcasecmp(f, "tcp.dstport") == 0) {
            if (pkt->is_tcp)
                return pkt->tcp.dst_port == (uint16_t)n->numeric_val ||
                       (strcasecmp(f, "tcp.port") == 0 && pkt->tcp.src_port == (uint16_t)n->numeric_val);
        }
        if (strcasecmp(f, "udp.port") == 0 || strcasecmp(f, "udp.srcport") == 0) {
            if (pkt->is_udp)
                return pkt->udp.src_port == (uint16_t)n->numeric_val ||
                       (strcasecmp(f, "udp.port") == 0 && pkt->udp.dst_port == (uint16_t)n->numeric_val);
        }
        if (strcasecmp(f, "udp.port") == 0 || strcasecmp(f, "udp.dstport") == 0) {
            if (pkt->is_udp)
                return pkt->udp.dst_port == (uint16_t)n->numeric_val ||
                       (strcasecmp(f, "udp.port") == 0 && pkt->udp.src_port == (uint16_t)n->numeric_val);
        }
        if (strcasecmp(f, "tcp.flags.syn") == 0) return pkt->is_tcp && (pkt->tcp.flags & TCP_SYN);
        if (strcasecmp(f, "tcp.flags.ack") == 0) return pkt->is_tcp && (pkt->tcp.flags & TCP_ACK);
        if (strcasecmp(f, "tcp.flags.fin") == 0) return pkt->is_tcp && (pkt->tcp.flags & TCP_FIN);
        if (strcasecmp(f, "tcp.flags.rst") == 0) return pkt->is_tcp && (pkt->tcp.flags & TCP_RST);
        if (strcasecmp(f, "tcp.flags.psh") == 0) return pkt->is_tcp && (pkt->tcp.flags & TCP_PSH);
        return 0;
    }
    }
    return 1;
}

static void free_node(ast_node_t *n)
{
    if (!n) return;
    free_node(n->left);
    free_node(n->right);
    free(n);
}

/* ---------- 全局状态 ---------- */
static ast_node_t *g_filter_ast = NULL;

int filter_compile(const char *expr, char *errmsg, int errlen)
{
    filter_free();
    if (!expr || !*expr)
        return 0;

    lexer_t lx;
    lex_init(&lx, expr);
    g_filter_ast = parse_expr(&lx);

    if (lx.has_error || lx.cur.type != TOK_END) {
        if (errlen > 0) {
            if (lx.has_error)
                strncpy(errmsg, lx.error, errlen - 1);
            else
                snprintf(errmsg, errlen, "表达式末尾有未处理的 token");
            errmsg[errlen - 1] = '\0';
        }
        free_node(g_filter_ast);
        g_filter_ast = NULL;
        return -1;
    }
    return 0;
}

void filter_free(void)
{
    if (g_filter_ast) {
        free_node(g_filter_ast);
        g_filter_ast = NULL;
    }
}

int filter_match(const packet_t *pkt)
{
    if (!g_filter_ast)
        return 1;
    return eval_node(g_filter_ast, pkt);
}

int filter_active(void)
{
    return g_filter_ast != NULL;
}
