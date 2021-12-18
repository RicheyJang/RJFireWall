#include "contact.h"

int showRules(struct IPRule *rules, int len);
int showNATRules(struct NATRecord *rules, int len);
int showLogs(struct IPLog *logs, int len);
int showConns(struct ConnLog *logs, int len);

void dealResponseAtCmd(struct KernelResponse rsp) {
	// 判断错误码
	switch (rsp.code) {
	case ERROR_CODE_EXIT:
		exit(0);
		break;
	case ERROR_CODE_NO_SUCH_RULE:
		printf("no such rule.\n");
		return;
	case ERROR_CODE_WRONG_IP:
		printf("Incorrect IP format.\n");
		return;
	}
	if(rsp.code < 0 || rsp.data == NULL || rsp.header == NULL || rsp.body == NULL) 
		return;
	// 处理数据
	switch (rsp.header->bodyTp) {
	case RSP_Only_Head:
		printf("succeed to delete %d rules.\n", rsp.header->arrayLen);
		break;
	case RSP_MSG:
		printf("From kernel: %s\n", (char*)rsp.body);
		break;
	case RSP_IPRules:
		showRules((struct IPRule*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_NATRules:
		showNATRules((struct NATRecord*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_IPLogs:
		showLogs((struct IPLog*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_ConnLogs:
		showConns((struct ConnLog*)rsp.body, rsp.header->arrayLen);
		break;
	}
	if(rsp.header->bodyTp != RSP_Only_Head && rsp.body != NULL) {
		free(rsp.data);
	}
}

int showOneRule(struct IPRule rule) {
	char saddr[25],daddr[25],sport[13],dport[13],proto[6],action[8],log[5];
	// ip
	IPint2IPstr(rule.saddr,rule.smask,saddr);
	IPint2IPstr(rule.daddr,rule.dmask,daddr);
	// port
	if(rule.sport == 0xFFFFu)
		strcpy(sport, "any");
	else if((rule.sport >> 16) == (rule.sport & 0xFFFFu))
		sprintf(sport, "only %u", (rule.sport >> 16));
	else
		sprintf(sport, "%u~%u", (rule.sport >> 16), (rule.sport & 0xFFFFu));
	if(rule.dport == 0xFFFFu)
		strcpy(dport, "any");
	else if((rule.dport >> 16) == (rule.dport & 0xFFFFu))
		sprintf(dport, "only %u", (rule.dport >> 16));
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

int showRules(struct IPRule *rules, int len) {
	int i;
	if(len == 0) {
		printf("No rules now.\n");
		return 0;
	}
	printf("rule num: %d\n", len);
	printf("%*s:\t%-18s\t%-18s\t%-11s\t%-11s\t%-8s\t%-6s\t%-3s\n", MAXRuleNameLen,
	 "name", "source ip", "target ip", "source port", "target port", "protocol", "action", "log");
	for(i = 0; i < len; i++) {
		showOneRule(rules[i]);
	}
	return 0;
}

int showNATRules(struct NATRecord *rules, int len) {
	int i;
	char saddr[25],daddr[25];
	if(len == 0) {
		printf("No NAT rules now.\n");
		return 0;
	}
	printf("NAT rule num: %d\n", len);
	printf("seq:\t%18s->%-18s:%-11s\n", "source ip", "NAT ip", "NAT port");
	for(i = 0; i < len; i++) {
		IPint2IPstr(rules[i].saddr,rules[i].smask,saddr);
		IPint2IPstrNoMask(rules[i].daddr,daddr);
		printf("%d:\t%18s->%-18s:%u-%u\n", i, saddr, daddr, rules[i].sport, rules[i].dport);
	}
	return 0;
}

int showOneLog(struct IPLog log) {
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
	// time
	timeinfo = localtime(&log.tm);
	sprintf(tm, "%4d-%02d-%02d %02d:%02d:%02d",
		1900 + timeinfo->tm_year, 1 + timeinfo->tm_mon, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
	// print
	printf("[%s] %-6s %-5s %15s:%-5u->%15s:%-5u len=%uB\n",
		tm, action, proto, saddr, log.sport, daddr, log.dport, log.len);
}

int showLogs(struct IPLog *logs, int len) {
	int i;
	if(len == 0) {
		printf("No logs now.\n");
		return 0;
	}
	printf("log num: %d\n", len);
	for(i = 0; i < len; i++) {
		showOneLog(logs[i]);
	}
	return 0;
}

int showOneConn(struct ConnLog log) {
	struct tm * timeinfo;
	char saddr[25],daddr[25],proto[6];
	// ip
	IPint2IPstrNoMask(log.saddr,saddr);
	IPint2IPstrNoMask(log.daddr,daddr);
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
	printf("%-5s %15s:%-5u->%15s:%-5u Established\n",proto, saddr, log.sport, daddr, log.dport);
}

int showConns(struct ConnLog *logs, int len) {
	int i;
	if(len == 0) {
		printf("No connections now.\n");
		return 0;
	}
	printf("connection num: %d\n", len);
	for(i = 0; i < len; i++) {
		showOneConn(logs[i]);
	}
	return 0;
}
