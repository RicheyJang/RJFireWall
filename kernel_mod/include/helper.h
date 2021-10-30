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

// ----- netfilter相关 -----
#define MAX_LOG_LEN 200

struct IPRule matchIPRules(struct sk_buff *skb, int *isMatch);
int addLog(struct IPLog log);
int addLogBySKB(unsigned int action, struct sk_buff *skb);

// ----- 连接池相关 --------
#define CONN_ROLL_INTERVAL 5

void conn_init(void);
void conn_exit(void);

#endif