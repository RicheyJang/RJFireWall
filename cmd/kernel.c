#include "exchange_msg.h"
#include "helper.h"
#include "tools.h"

int showKernelMsg(void *mem,unsigned int len) {
	struct KernelResponseHeader *head;
	char *msg;
	head = (struct KernelResponseHeader *)mem;
	if(head->bodyTp!=RSP_MSG || len<=sizeof(struct KernelResponseHeader)) 
		return -1;
	msg = (char *)(mem + sizeof(struct KernelResponseHeader));
	printf("From kernel: %s\n", msg);
	return 0;
}

int showOneRule(struct IPRule rule) {
	char saddr[25],daddr[25],sport[13],dport[13],proto[6],action[8],log[5];
	// ip
	IPint2IPstr(rule.saddr,rule.smask,saddr);
	IPint2IPstr(rule.daddr,rule.dmask,daddr);
	// port
	if(rule.sport == 0xFFFFu)
		strcpy(sport, "any");
	else
		sprintf(sport, "%u~%u", (rule.sport >> 16), (rule.sport & 0xFFFFu));
	if(rule.dport == 0xFFFFu)
		strcpy(dport, "any");
	else
		sprintf(dport, "%u~%u", (rule.dport >> 16), (rule.dport & 0xFFFFu));
	// action
	if(rule.action == NF_ACCEPT) {
		sprintf(action, "accept");
	} else if(rule.action == NF_DROP) {
		sprintf(action, "drop");
	} else {
		sprintf(action, "other");
	}
	// protocol
	if(rule.protocol == IPPROTO_TCP) {
		sprintf(proto, "TCP");
	} else if(rule.protocol == IPPROTO_UDP) {
		sprintf(proto, "UDP");
	} else if(rule.protocol == IPPROTO_ICMP) {
		sprintf(proto, "ICMP");
	} else if(rule.protocol == IPPROTO_IP) {
		sprintf(proto, "any");
	} else {
		sprintf(proto, "other");
	}
	// log
	if(rule.log) {
		sprintf(log, "yes");
	} else {
		sprintf(log, "no");
	}
	// print
	printf("%*s:\t%-18s\t%-18s\t%-11s\t%-11s\t%-8s\t%-6s\t%-3s\n", MAXRuleNameLen,
	rule.name, saddr, daddr, sport, dport, proto, action, log);
}

int showRules() {
	void *mem;
	unsigned int rspLen,i;
	struct IPRule *rules;
	struct APPRequest req;
	struct KernelResponseHeader *head;
	// exchange msg
	req.tp = REQ_GETAllIPRules;
	if(exchangeMsgK(&req,sizeof(req),&mem,&rspLen)<0) {
		printf("exchange with kernel failed.\n");
		return -2;
	}
	head = (struct KernelResponseHeader *)mem;
	if(head->bodyTp!=RSP_IPRules || rspLen<sizeof(struct KernelResponseHeader)) {
		printf("msg format error.\n");
		return -1;
	}
	rules = (struct IPRule *)(mem+sizeof(struct KernelResponseHeader));
	// show
	if(head->arrayLen==0) {
		printf("No rules now.\n");
		return 0;
	}
	printf("rule num: %u\n", head->arrayLen);
	printf("%*s:\t%-18s\t%-18s\t%-11s\t%-11s\t%-8s\t%-6s\t%-3s\n", MAXRuleNameLen,
	 "name", "source ip", "target ip", "source port", "target port", "protocol", "action", "log");
	for(i=0;i<head->arrayLen;i++) {
		showOneRule(rules[i]);
	}
	return 0;
}

int showOneLog(struct IPLog log, int showAll) {
	struct tm * timeinfo;
	char saddr[25],daddr[25],proto[6],action[8],tm[21];
	// ip
	IPint2IPstrNoMask(log.saddr,saddr);
	IPint2IPstrNoMask(log.daddr,daddr);
	// action
	if(log.action == NF_ACCEPT) {
		sprintf(action, "accept");
	} else if(log.action == NF_DROP) {
		sprintf(action, "drop");
	} else {
		sprintf(action, "other");
	}
	// protocol
	if(log.protocol == IPPROTO_TCP) {
		sprintf(proto, "TCP");
	} else if(log.protocol == IPPROTO_UDP) {
		sprintf(proto, "UDP");
	} else if(log.protocol == IPPROTO_ICMP) {
		sprintf(proto, "ICMP");
	} else if(log.protocol == IPPROTO_IP) {
		sprintf(proto, "any");
	} else {
		sprintf(proto, "other");
	}
	if(showAll) {
		// time
		timeinfo = localtime(&log.tm);
		sprintf(tm, "%4d-%02d-%02d %02d:%02d:%02d",
			1900 + timeinfo->tm_year, 1 + timeinfo->tm_mon, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
		// print
		printf("[%s] %-6s %-5s %15s:%-5u->%15s:%-5u len=%uB\n",
			tm, action, proto, saddr, log.sport, daddr, log.dport, log.len);
	} else { // show base
		printf("%-5s %15s:%-5u->%15s:%-5u Established\n",proto, saddr, log.sport, daddr, log.dport);
	}
}

int showLogs(unsigned int num) {
	void *mem;
	unsigned int rspLen,i;
	struct IPLog *logs;
	struct APPRequest req;
	struct KernelResponseHeader *head;
	// exchange msg
	req.msg.num = num;
	req.tp = REQ_GETAllIPLogs;
	if(exchangeMsgK(&req,sizeof(req),&mem,&rspLen)<0) {
		printf("exchange with kernel failed.\n");
		return -2;
	}
	head = (struct KernelResponseHeader *)mem;
	if(head->bodyTp!=RSP_IPLogs || rspLen<sizeof(struct KernelResponseHeader)) {
		printf("msg format error.\n");
		return -1;
	}
	logs = (struct IPLog *)(mem+sizeof(struct KernelResponseHeader));
	// show
	if(head->arrayLen == 0) {
		printf("No logs now.\n");
		return 0;
	}
	printf("log num: %u\n", head->arrayLen);
	for(i=0;i<head->arrayLen;i++) {
		showOneLog(logs[i], 1);
	}
	return 0;
}

int showConns(void) {
	void *mem;
	unsigned int rspLen,i;
	struct IPLog *logs;
	struct APPRequest req;
	struct KernelResponseHeader *head;
	// exchange msg
	req.tp = REQ_GETAllConns;
	if(exchangeMsgK(&req,sizeof(req),&mem,&rspLen)<0) {
		printf("exchange with kernel failed.\n");
		return -2;
	}
	head = (struct KernelResponseHeader *)mem;
	if(head->bodyTp!=RSP_IPLogs || rspLen<sizeof(struct KernelResponseHeader)) {
		printf("msg format error.\n");
		return -1;
	}
	logs = (struct IPLog *)(mem+sizeof(struct KernelResponseHeader));
	// show
	if(head->arrayLen == 0) {
		printf("No connections now.\n");
		return 0;
	}
	printf("connection num: %u\n", head->arrayLen);
	for(i=0;i<head->arrayLen;i++) {
		showOneLog(logs[i], 0);
	}
	return 0;
}

// 新增一条过滤规则，其中，sport/dport为端口范围：高2字节为最小 低2字节为最大
int addRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,unsigned int proto,unsigned int log,unsigned int action) {
	struct APPRequest req;
	void *mem;
	unsigned int rspLen;
	// form rule
	struct IPRule rule;
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		printf("wrong ip format: %s\n", sip);
		return -1;
	}
	if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		printf("wrong ip format: %s\n", dip);
		return -1;
	}
	rule.saddr = rule.saddr;
	rule.daddr = rule.daddr;
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAXRuleNameLen);
	// form req
	req.tp = REQ_ADDIPRule;
	req.ruleName[0]=0;
	strncpy(req.ruleName, after, MAXRuleNameLen);
	req.msg.ipRule = rule;
	// exchange
	if(exchangeMsgK(&req,sizeof(req),&mem,&rspLen)<0) {
		printf("exchange with kernel failed.\n");
		return -2;
	}
	showKernelMsg(mem,rspLen);
	return 0;
}

int delRule(char *name) {
	void *mem;
	unsigned int rspLen;
	struct APPRequest req;
	struct KernelResponseHeader *head;
	// form request
	req.tp = REQ_DELIPRule;
	strncpy(req.ruleName, name, MAXRuleNameLen);
	// exchange
	if(exchangeMsgK(&req,sizeof(req),&mem,&rspLen)<0) {
		printf("exchange with kernel failed.\n");
		return -1;
	}
	// print result
	head = (struct KernelResponseHeader *)mem;
	printf("del %d rules.\n", head->arrayLen);
    return head->arrayLen;
}

int setDefaultAction(unsigned int action) {
    void *mem;
	unsigned int rspLen;
	struct APPRequest req;
	// form request
	req.tp = REQ_SETAction;
	req.msg.defaultAction = action;
	// exchange
	if(exchangeMsgK(&req,sizeof(req),&mem,&rspLen)<0) {
		printf("exchange with kernel failed.\n");
		return -1;
	}
	// print result
	showKernelMsg(mem,rspLen);
    return 0;
}