#ifndef _TOOLS_H
#define _TOOLS_H

#include "dependency.h"

void getPort(struct sk_buff *skb, struct iphdr *hdr, unsigned short *src_port, unsigned short *dst_port){
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	switch(hdr->protocol){
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(tcpHeader->source);
			*dst_port = ntohs(tcpHeader->dest);
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(udpHeader->source);
			*dst_port = ntohs(udpHeader->dest);
			break;
		case IPPROTO_ICMP:
		default:
			//printk("other protocol\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}

//--------- 以下为临时工具函数 -----------------
void showIPk(const char *pre, unsigned long ip) {
    printk("%s %lu.%lu.%lu.%lu\n", pre, (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, (ip>>0)&0xff);
}

bool isIPPatch(unsigned ip, const char *ipStr){
    char tmp_ip[20];
    int p = -1, count = 0;
    unsigned len = 0, tmp = 0, mask = 0, r_ip = 0,i;
    strcpy(tmp_ip, ipStr);
    for(i = 0; i < strlen(tmp_ip); i++){
        if(p != -1){
            len *= 10;
            len += tmp_ip[i] - '0';
        }
        else if(tmp_ip[i] == '/')
            p = i;
    }
    if(p != -1){
        tmp_ip[p] = '\0';
        if(len)
            mask = 0xFFFFFFFF << (32 - len);
    }
    else mask = 0xFFFFFFFF;
    for(i = 0; i < strlen(tmp_ip); i++){
        if(tmp_ip[i] == '.'){
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += tmp_ip[i] - '0';
    }
    r_ip = r_ip | tmp;
    return (r_ip & mask) == (ip & mask);
}

#endif