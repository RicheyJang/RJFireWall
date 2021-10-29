#ifndef _HELPER_H
#define _HELPER_H

#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>

#define MAXRuleNameLen 11

#define REQ_GETAllIPRules 1
#define REQ_ADDIPRule 2
#define REQ_DELIPRule 3

#define RSP_Only_Head 10
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
    char ruleName[MAXRuleNameLen+1];
    union {
        struct IPRule ipRule;
    } msg;
};

struct KernelResponseHeader {
    unsigned int bodyTp;
    unsigned int arrayLen;
};

#endif