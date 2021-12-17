#include "tools.h"
#include "helper.h"
#include "hook.h"

unsigned int hook_nat_in(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct connNode *conn;
    struct NATRecord record;
    unsigned short sport, dport;
    unsigned int sip, dip;
    u_int8_t proto;
    // 初始化
	struct iphdr *header = ip_hdr(skb);
	getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;
    // 查连接池 NAT_TYPE_DEST
    conn = hasConn(sip, dip, sport, dport);
    if(conn == NULL) { // 不应出现连接表中不存在的情况
        printk(KERN_WARNING "[fw nat] (in)get a connection that is not in the connection pool!\n");
        return NF_ACCEPT;
    }
    // 无记录->返回
    if(conn->natType != NAT_TYPE_DEST) {
        return NF_ACCEPT;
    }
    // TODO 转换目的地址+端口

    return NF_ACCEPT;
}

unsigned int hook_nat_out(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct connNode *conn;
    struct NATRecord record;
    int isMatch;
    u_int8_t proto;
    unsigned int sip, dip;
    unsigned short sport, dport, newPort = 0;
    // 初始化
	struct iphdr *header = ip_hdr(skb);
	getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;
    // 查连接池 NAT_TYPE_SRC
    conn = hasConn(sip, dip, sport, dport);
    if(conn == NULL) { // 不应出现连接表中不存在的情况
        printk(KERN_WARNING "[fw nat] (out)get a connection that is not in the connection pool!\n");
        return NF_ACCEPT;
    }
    // 确定NAT记录
    if(conn->natType == NAT_TYPE_SRC) { // 已有
        record = conn->nat;
    } else {
        struct connNode *reverseConn;
        struct NATRecord rule = matchNATRule(sip, dip, &isMatch);
        if(!isMatch) { // 不符合NAT规则，无需NAT
            return NF_ACCEPT;
        }
        // 新建NAT记录
        if(sport != 0) {
            newPort = getNewNATPort(rule);
            if(newPort == 0) { // 获取新端口失败，放弃NAT
                printk(KERN_WARNING "[fw nat] get new port failed!\n");
                return NF_ACCEPT;
            }
        }
        record = genNATRecord(sip, rule.daddr, sport, newPort);
        // 新建反向连接入连接池
        reverseConn = hasConn(dip, rule.daddr, dport, newPort);
        if(reverseConn == NULL) {
            reverseConn = addConn(dip, rule.daddr, dport, newPort, proto, 0);
        }
        if(reverseConn == NULL) { // 创建反向连接失败，放弃NAT
            printk(KERN_WARNING "[fw nat] add reverse connection failed!\n");
            return NF_ACCEPT;
        }
        setConnNAT(reverseConn, genNATRecord(rule.daddr, sip, newPort, sport), NAT_TYPE_DEST);
        // 记录在原连接中
        setConnNAT(conn, record, NAT_TYPE_SRC);
    }
    // TODO 转换源地址+端口

    return NF_ACCEPT;
}