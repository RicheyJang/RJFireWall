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
#define REQ_ADDNATRule 7
#define REQ_DELNATRule 8
#define REQ_GETNATRules 9

#define RSP_Only_Head 10
#define RSP_MSG 11
#define RSP_IPRules 12
#define RSP_IPLogs 13
#define RSP_NATRules 14

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

struct NATRecord { // NAT 记录 or 规则(源IP端口转换)
    unsigned int saddr; // 记录：原始IP | 规则：原始源IP
    unsigned int smask; // 记录：无作用  | 规则：原始源IP掩码
    unsigned int daddr; // 记录：转换后的IP | 规则：NAT 源IP

    unsigned short sport; // 记录：原始端口 | 规则：最小端口范围
    unsigned short dport; // 记录：转换后的端口 | 规则：最大端口范围
    unsigned short nowPort; // 记录：当前使用端口 | 规则：无作用
    struct NATRecord* nx;
};

struct APPRequest {
    unsigned int tp;
    char ruleName[MAXRuleNameLen+1];
    union {
        struct IPRule ipRule;
        struct NATRecord natRule;
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
int addNATRule(char *sip,char *nat,unsigned short minport,unsigned short maxport);
int delNATRule(int num);
int showNATRules();
int delRule(char *name);
int setDefaultAction(unsigned int action);
int showLogs(unsigned int num);
int showConns(void);

#endif