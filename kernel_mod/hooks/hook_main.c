#include "tools.h"
#include "hook.h"

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
    // initial data
	struct iphdr *header = ip_hdr(skb);
    unsigned short sPort, dPort;
    getPort(skb,header,&sPort,&dPort);

    // show
    showIPk("source IP:", ntohl(header->saddr));
    printk("source Port: %u\n", sPort);
    showIPk("target IP:", ntohl(header->daddr));
    printk("target Port: %u\n", dPort);
    printk("len: %u\n\n",ntohs(header->tot_len));

    // deal 220.181.38.251
    if(isIPPatch(ntohl(header->daddr), "220.181.38.148") || isIPPatch(ntohl(header->daddr), "220.181.38.251"))
    {
        return NF_DROP;
    }
    return NF_ACCEPT;
}