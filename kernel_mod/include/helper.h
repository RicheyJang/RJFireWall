#ifndef _NETLINK_HELPER_H
#define _NETLINK_HELPER_H

#include "dependency.h"

#define MAXRuleNameLen 11

#define REQ_GETAllIPRules 1
#define REQ_ADDIPRule 2
#define REQ_DELIPRule 3

#define RSP_MSG 11
#define RSP_IPRules 12

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

struct APPRequest {
    unsigned int tp;
    union {
        struct IPRule ipRule;
        char ruleName[MAXRuleNameLen+1];
    } msg;
};

struct KernelResponseHeader {
    unsigned int bodyTp;
    unsigned int arrayLen;
};

// ----- netlink 相关 -----
#include <linux/netlink.h>
#define NETLINK_MYFW 17

struct sock *netlinkInit(void);
void netlinkRelease(void);
int nlSend(unsigned int pid, void *data, unsigned int len);

// ----- 应用交互相关 -------
int dealAppMessage(unsigned int pid, void *msg, unsigned int len);

#endif