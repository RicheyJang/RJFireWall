#include "tools.h"
#include "helper.h"
#include "hook.h"

unsigned int hook_nat_in(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    // 查连接池 NAT_TYPE_DEST

    // 无记录->返回

    // 转换目的地址+端口

    return NF_ACCEPT;
}

unsigned int hook_nat_out(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    // 查连接池 NAT_TYPE_SRC

    // 连接池中没有->查NAT规则表 -> 新建记录入连接池

    // 都没有->返回

    // 转换源地址+端口

    return NF_ACCEPT;
}