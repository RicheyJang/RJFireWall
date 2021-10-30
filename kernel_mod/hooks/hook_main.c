#include "helper.h"
#include "hook.h"

const unsigned int DEFAULT_ACTION = NF_ACCEPT;

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    unsigned int action = DEFAULT_ACTION;
    // 匹配规则
    int isMatch = 0;
    struct IPRule rule = matchIPRules(skb, &isMatch);
    if(isMatch) { // 匹配到了一条规则
        printk("[fw netfilter] patch rule %s.\n", rule.name);
        action = (rule.action==NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
        if(rule.log) { // 记录日志
            addLogBySKB(action, skb);
        }
    }
    return action;
}