#include "exchange_msg.h"
#include "helper.h"

int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask){
	// init
    int p = -1, count = 0;
    unsigned int len = 0, tmp = 0, r_mask = 0, r_ip = 0,i;
	// 获取掩码
    for(i = 0; i < strlen(ipStr); i++){
        if(p != -1){
            len *= 10;
            len += ipStr[i] - '0';
        }
        else if(ipStr[i] == '/')
            p = i;
    }
	if(len > 32 || (p>=0 && p<7)) {
		return -1;
	}
    if(p != -1){
        if(len)
            r_mask = 0xFFFFFFFF << (32 - len);
    }
    else r_mask = 0xFFFFFFFF;
	// 获取IP
    for(i = 0; i < (p>=0 ? p : strlen(ipStr)); i++){
        if(ipStr[i] == '.'){
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += ipStr[i] - '0';
		if(tmp>256 || count>3)
			return -2;
    }
    r_ip = r_ip | tmp;
	*ip = r_ip;
	*mask = r_mask;
    return 0;
}

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
	for(i=0;i<head->arrayLen;i++) {
		printf("%s: %d %d %d\n", rules[i].name, rules[i].action, rules[i].log, rules[i].protocol);
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
}

int main(int argc, char *argv[]) {
	if(argc<3) {
		printf("wrong command.\n");
		return 0;
	}
	addRule("","1","127.0.0.1","127.0.0.1",-1,-1,IPPROTO_TCP,0,NF_ACCEPT);
	if(strcmp(argv[1], "rule")==0 || argv[1][0] == 'r') {
		if(strcmp(argv[2], "ls")==0) {
			showRules();
		}
		else if(strcmp(argv[2], "add")==0) {
			
		}
	}
}
