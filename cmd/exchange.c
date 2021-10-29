#include "exchange_msg.h"

// 与内核交换数据，无需预先开好dmsg的空间，但要自行free
int exchangeMsgK(void *smsg, unsigned int slen, void **dmsg, unsigned int *dlen) {
	struct sockaddr_nl local;
	struct sockaddr_nl kpeer;
	int kpeerlen = sizeof(struct sockaddr_nl);
	// init socket
	int skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MYFW);
	if (skfd < 0) {
		//printf("[exchangeMsgK] can not create a netlink socket\n");
		return -1;
	}
	// bind
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	if (bind(skfd, (struct sockaddr *) &local, sizeof(local)) != 0) {
		//printf("[exchangeMsgK] bind() error\n");
		close(skfd);
		return -1;
	}
	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;
	// set send msg
	struct nlmsghdr *message=(struct nlmsghdr *)malloc(NLMSG_SPACE(slen)*sizeof(uint8_t));
	if(!message) {
		//printf("[exchangeMsgK] malloc fail");
		close(skfd);
		return -1;
	}
	memset(message, '\0', sizeof(struct nlmsghdr));
	message->nlmsg_len = NLMSG_SPACE(slen);
	message->nlmsg_flags = 0;
	message->nlmsg_type = 0;
	message->nlmsg_seq = 0;
	message->nlmsg_pid = local.nl_pid;
	memcpy(NLMSG_DATA(message), smsg, slen);
	// send msg
	if (!sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *) &kpeer, sizeof(kpeer))) {
		//printf("[exchangeMsgK] sendto fail");
		close(skfd);
		free(message);
		return -1;
	}
	// recv msg
	struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD)*sizeof(uint8_t));
	if (!nlh) {
		//printf("[exchangeMsgK] nlh malloc fail");
		close(skfd);
		free(message);
		return -1;
	}
	if (!recvfrom(skfd, nlh, NLMSG_SPACE(MAX_PAYLOAD), 0, (struct sockaddr *) &kpeer, (socklen_t *)&kpeerlen)) {
		//printf("[exchangeMsgK] recvfrom fail");
		close(skfd);
		free(message);
		free(nlh);
		return -1;
	}
	*dlen = nlh->nlmsg_len - NLMSG_SPACE(0);
	*dmsg = malloc(*dlen);
	if(!(*dmsg)) {
		//printf("[exchangeMsgK] dmsg malloc fail");
		close(skfd);
		free(message);
		free(nlh);
		return -1;
	}
	memset(*dmsg, 0, *dlen);
	memcpy(*dmsg, NLMSG_DATA(nlh), *dlen);
	// over
	close(skfd);
	free(message);
	free(nlh);
	return *dlen;
}