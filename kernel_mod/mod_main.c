#include "dependency.h"
#include "hook.h"
#include "helper.h"

static struct nf_hook_ops nfop_in={
	.hook = hook_main,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfop_out={
	.hook = hook_main,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};

static int mod_init(void){
	printk("my firewall module loaded.\n");
	// nf_register_net_hook(&init_net,&nfop_in);
	// nf_register_net_hook(&init_net,&nfop_out);
	netlinkInit();
	return 0;
}

static void mod_exit(void){
	printk("my firewall module exit.\n");
	// nf_unregister_net_hook(&init_net,&nfop_in);
	// nf_unregister_net_hook(&init_net,&nfop_out);
	netlinkRelease();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("jyq");
module_init(mod_init);
module_exit(mod_exit);
