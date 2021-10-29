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
	char saddr[25],daddr[25],proto[6],action[8],log[5];
	// ip
	IPint2IPstr(rule.saddr,rule.smask,saddr);
	IPint2IPstr(rule.daddr,rule.dmask,daddr);
	// action
	if(rule.action == NF_ACCEPT) {
		sprintf(action, "ACCEPT");
	} else if(rule.action == NF_DROP) {
		sprintf(action, "DROP");
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
	printf("%*s:\t%s\t%s\t%-11d\t%-11d\t%-8s\t%s\t%s\n", MAXRuleNameLen,
	rule.name, saddr, daddr, rule.sport, rule.dport, proto, action, log);
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
	}
	printf("rule num: %u\n", head->arrayLen);
	printf("%*s:\tsource ip\ttarget ip\tsource port\ttarget port\tprotocol\taction\tlog\n"
	, MAXRuleNameLen, "name");
	for(i=0;i<head->arrayLen;i++) {
		showOneRule(rules[i]);
	}
	return 0;
}

int addRule(char *after,char *name,char *sip,char *dip,int sport,int dport,unsigned int proto,unsigned int log,unsigned int action) {
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