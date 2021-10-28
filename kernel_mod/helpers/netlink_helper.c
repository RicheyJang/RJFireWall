#include "helper.h"

static struct sock *nlsk = NULL;

int nlSend(unsigned int pid, uint8_t *info, unsigned int len)
{
	uint8_t reply[50];
	int rlen, retval;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	sprintf(reply, "NLTEST Reply for '%s'\0", info);
	rlen = strlen(reply) + 1;
	
	skb = nlmsg_new(rlen, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_WARNING "alloc reply nlmsg skb failed!\n");
		return -1;
	}
	
	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(rlen) - NLMSG_HDRLEN, 0);
	memcpy(NLMSG_DATA(nlh), reply, rlen);
    //NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);

	printk("[kernel space] nlmsglen = %d\n", nlh->nlmsg_len - NLMSG_SPACE(0));
	printk("[kernel space] skb->data send to user: '%s'\n", (uint8_t *) NLMSG_DATA(nlh));
	printk("[kernel space] netlink_unicast return: %d\n\n\n", retval);
	return retval;
}

void nlRecv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	uint8_t *data;
	unsigned int pid,len;
    // check skb
    nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk(KERN_WARNING "Illegal netlink packet!\n");
		return;
	}
    // deal data
	data = (uint8_t *) NLMSG_DATA(nlh);
    pid = nlh->nlmsg_pid;
    len = nlh->nlmsg_len - NLMSG_SPACE(0);
	printk("[kernel space] data receive from user: user_pid = %d, len=%d\n", nlh->nlmsg_pid, len);
	nlSend(pid, data, len);
}

struct netlink_kernel_cfg nltest_cfg = {
	.groups = 0,
	.flags = 0,
	.input = nlRecv,
	.cb_mutex = NULL,
	.bind = NULL,
	.unbind = NULL,
	.compare = NULL,
};

struct sock *netlinkInit() {
    nlsk = netlink_kernel_create(&init_net, NETLINK_MYFW, &nltest_cfg);
	if (!nlsk) {
		printk("can not create a netlink socket\n");
		return -1;
	}
	printk("netlink_kernel_create() success, nlsk = %p\n", nlsk);
    return nlsk;
}

void netlinkRelease() {
    netlink_kernel_release(nlsk);
}