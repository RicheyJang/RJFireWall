#include "helper.h"
#include "hook.h"

const unsigned int DEFAULT_ACTION = NF_ACCEPT;

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
    // match with rule chain
    int isMatch = 0;
    struct IPRule rule = matchIPRules(skb, &isMatch);
    if(isMatch) { // match a rule
        printk("[fw netfilter]patch rule %s.\n", rule.name);
        if(rule.action == NF_ACCEPT)
            return NF_ACCEPT;
        return NF_DROP;
    }
    // default
    return DEFAULT_ACTION;
}