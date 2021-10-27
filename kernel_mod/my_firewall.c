#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jyq");

static struct nf_hook_ops nfho;

unsigned int telnet_filter(void *priv,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return NF_DROP;
}

static int myfw_init(void)
{
	printk("my firewall module loaded.\n");

	nfho.hook = telnet_filter;
	nfho.pf = PF_INET;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST; //new version, maybe changed to NF_INET_PRI_FIRST

	nf_register_net_hook(&init_net,&nfho);
	return 0;
}

static void myfw_exit(void)
{
	printk("my firewall module exit ...\n");
	nf_unregister_net_hook(&init_net,&nfho);
}

module_init(myfw_init);
module_exit(myfw_exit);
