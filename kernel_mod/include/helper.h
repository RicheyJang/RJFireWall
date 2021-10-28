#ifndef _NETLINK_HELPER_H
#define _NETLINK_HELPER_H

#include "dependency.h"

// ----- netlink 相关 -----
#include <linux/netlink.h>
#define NETLINK_MYFW 17

struct sock *netlinkInit(void);
void netlinkRelease(void);
int nlSend(unsigned int pid, uint8_t *info, unsigned int len);

// ----- 应用交互相关 -------


#endif