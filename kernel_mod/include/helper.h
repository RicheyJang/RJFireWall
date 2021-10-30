#ifndef _NETLINK_HELPER_H
#define _NETLINK_HELPER_H

#include "dependency.h"

// ---- APP 与 Kernel 通用协议 ------
#define MAXRuleNameLen 11

#define REQ_GETAllIPRules 1
#define REQ_ADDIPRule 2
#define REQ_DELIPRule 3
#define REQ_SETAction 4 
#define REQ_GETAllIPLogs 5
#define REQ_GETAllConns 6

#define RSP_Only_Head 10
#define RSP_MSG 11
#define RSP_IPRules 12
#define RSP_IPLogs 13

struct IPRule {
    char name[MAXRuleNameLen+1];
    unsigned int saddr;
    unsigned int smask;
    unsigned int daddr;
    unsigned int dmask;
    int sport;
    int dport;
    u_int8_t protocol;
    unsigned int action;
    unsigned int log;
    struct IPRule* nx;
};

struct IPLog {
    long tm;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    u_int8_t protocol;
    unsigned int len;
    unsigned int action;
    struct IPLog* nx;
};

struct APPRequest {
    unsigned int tp;
    char ruleName[MAXRuleNameLen+1];
    union {
        struct IPRule ipRule;
        unsigned int defaultAction;
        unsigned int num;
    } msg;
};

struct KernelResponseHeader {
    unsigned int bodyTp;
    unsigned int arrayLen;
};

// ----- netlink 相关 -----
#include <linux/netlink.h>

// netlink 协议号
#define NETLINK_MYFW 17

struct sock *netlink_init(void);
void netlink_release(void);
int nlSend(unsigned int pid, void *data, unsigned int len);

// ----- 应用交互相关 -------
int dealAppMessage(unsigned int pid, void *msg, unsigned int len);
void* formAllIPRules(unsigned int *len);
struct IPRule * addIPRuleToChain(char after[], struct IPRule rule);
int delIPRuleFromChain(char name[]);
void* formAllIPLogs(unsigned int num, unsigned int *len);
void* formAllConns(unsigned int *len);

// ----- netfilter相关 -----
// 最大缓存日志长度
#define MAX_LOG_LEN 1000

struct IPRule matchIPRules(struct sk_buff *skb, int *isMatch);
int addLog(struct IPLog log);
int addLogBySKB(unsigned int action, struct sk_buff *skb);

// ----- 连接池相关 --------
#include <linux/rbtree.h>

#define CONN_NEEDLOG 0x10
#define CONN_MAX_SYM_NUM 3
// 新建连接或已有连接刷新时的存活时长（秒）
#define CONN_EXPIRES 7
// 定期清理超时连接的时间间隔（秒）
#define CONN_ROLL_INTERVAL 5

typedef unsigned int conn_key_t[CONN_MAX_SYM_NUM]; // 连接标识符，用于标明一个连接，可比较

typedef struct connNode {
    struct rb_node node;
    conn_key_t key; // 连接标识符
    unsigned long expires; // 超时时间
    u_int8_t protocol; // 协议，仅用于向用户展示
    u_int8_t needLog; // 是否记录日志，仅用于hook
}connNode;

#define timeFromNow(plus) (jiffies + ((plus) * HZ))

void conn_init(void);
void conn_exit(void);
int hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);
int addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);
int eraseConnRelated(struct IPRule rule);

#endif