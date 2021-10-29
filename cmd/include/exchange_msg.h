#ifndef _EXCHANGE_MSG_H
#define _EXCHANGE_MSG_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <unistd.h>

#define uint8_t unsigned char
#define NETLINK_MYFW 17
#define MAX_PAYLOAD 1024



int exchangeMsgK(void *smsg, unsigned int slen, void **dmsg, unsigned int *dlen);

#endif