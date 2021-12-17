#ifndef _HELPER_H
#define _HELPER_H

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>

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
    unsigned int sport; // 源端口范围 高2字节为最小 低2字节为最大
    unsigned int dport; // 目的端口范围 同上
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

struct NATRecord { // NAT 记录or规则 （源端口转换）
    unsigned int saddr;
    unsigned int smask; // 仅当作为一条NAT规则时起作用
    unsigned int daddr;

    unsigned short sport; // 当作为一条NAT规则时，代表最小端口范围
    unsigned short dport; // 当作为一条NAT规则时，代表最大端口范围
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

// ----- 与内核交互函数 -----
int showRules(void);
int addRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,unsigned int proto,unsigned int log,unsigned int action);
int delRule(char *name);
int setDefaultAction(unsigned int action);
int showLogs(unsigned int num);
int showConns(void);

#endif