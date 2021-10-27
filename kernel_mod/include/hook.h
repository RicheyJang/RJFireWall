#ifndef _HOOK_H
#define _HOOK_H

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state);

#endif