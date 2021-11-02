#include "helper.h"

// 新增过滤规则时的用户交互
void cmdAddRule() {
	char after[MAXRuleNameLen+1],name[MAXRuleNameLen+1],saddr[25],daddr[25],protoS[6];
	unsigned short sportMin,sportMax,dportMin,dportMax;
	unsigned int action = NF_DROP, log = 0, proto, i;
	printf("add rule after [enter for adding at head]: ");
	for(i=0;;i++) {
		if(i>MAXRuleNameLen) {
			printf("name too long.\n");
			return ;
		}
		after[i] = getchar();
		if(after[i] == '\n' || after[i] == '\r') {
			after[i] = '\0';
			break;
		}
	}
	printf("rule name [max len=%d]: ", MAXRuleNameLen);
	scanf("%s",name);
	if(strlen(name)==0 || strlen(name)>MAXRuleNameLen) {
		printf("name too long or too short.\n");
		return ;
	}
	printf("source ip and mask [like 127.0.0.1/16]: ");
	scanf("%s",saddr);
	printf("source port range [like 8080-8031]: ");
	scanf("%u-%u",&sportMin,&sportMax);
	if(sportMin > sportMax) {
		printf("the min port > max port.\n");
		return ;
	}
	printf("target ip and mask [like 127.0.0.1/16]: ");
	scanf("%s",daddr);
	printf("target port range [like 8080-8031]: ");
	scanf("%u-%u",&dportMin,&dportMax);
	if(dportMin > dportMax) {
		printf("the min port > max port.\n");
		return ;
	}
	printf("protocol [TCP/UDP/ICMP/any]: ");
	scanf("%s",protoS);
	if(strcmp(protoS,"TCP")==0)
		proto = IPPROTO_TCP;
	else if(strcmp(protoS,"UDP")==0)
		proto = IPPROTO_UDP;
	else if(strcmp(protoS,"ICMP")==0)
		proto = IPPROTO_ICMP;
	else if(strcmp(protoS,"any")==0)
		proto = IPPROTO_IP;
	else {
		printf("This protocol is not supported.\n");
		return ;
	}
	printf("action [1 for accept,0 for drop]: ");
	scanf("%d",&action);
	printf("is log [1 for yes,0 for no]: ");
	scanf("%u",&log);
	printf("result:\n");
	addRule(after,name,saddr,daddr,
		(((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
		(((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,log,action);
}

void wrongCommand() {
	printf("wrong command.\n");
	printf("uapp <command> <sub-command> [option]\n");
	printf("command: rule <add | del | ls | default>\n");
}

int main(int argc, char *argv[]) {
	if(argc<3) {
		//addRule("","rj","192.168.80.138","47.100.10.21",-1,-1,IPPROTO_ICMP,1,NF_DROP);
		wrongCommand();
		return 0;
	}
	// 过滤规则相关
	if(strcmp(argv[1], "rule")==0 || argv[1][0] == 'r') {
		if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
		// 列出所有过滤规则
			showRules();
		} else if(strcmp(argv[2], "del")==0) {
		// 删除过滤规则
			if(argc < 4)
				printf("Please point rule name in option.\n");
			else if(strlen(argv[3])>MAXRuleNameLen)
				printf("rule name too long!");
			else
				delRule(argv[3]);
		} else if(strcmp(argv[2], "add")==0) {
		// 添加过滤规则
			cmdAddRule();
		} else if(strcmp(argv[2], "default")==0) {
		// 设置默认规则
			if(argc < 4)
				printf("Please point default action in option.\n");
			else if(strcmp(argv[3], "accept")==0)
				setDefaultAction(NF_ACCEPT);
			else if(strcmp(argv[3], "drop")==0)
				setDefaultAction(NF_DROP);
			else
				printf("No such action. Only \"accept\" or \"drop\".\n");
		} else 
			wrongCommand();
	} else if(strcmp(argv[1], "nat")==0 || argv[1][0] == 'n') {

	} else if(strcmp(argv[1], "ls")==0 || argv[1][0] == 'l') {
	// 展示相关
		if(strcmp(argv[2],"log")==0) {
		// 过滤日志
			unsigned int num = 0;
			if(argc > 3)
				sscanf(argv[2], "%u", &num);
			showLogs(num);
		} else if(strcmp(argv[2],"con")==0 || argv[2][0] == 'c') {
		// 连接状态
			showConns();
		} else if(strcmp(argv[2],"rule")==0 || argv[2][0] == 'r') {
		// 已有过滤规则
			showRules();
		} else
			wrongCommand();
	} else 
		wrongCommand();
}
