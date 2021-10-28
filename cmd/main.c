#include "exchange_msg.h"

char *default_data = "user:a string";

int main(int argc, char *argv[])
{
	uint8_t *msg;
	int dlen;
	printf("send: \"%s\", len=%d\n", default_data, strlen(default_data));
	exchangeMsgK(default_data, strlen(default_data)+1, &msg, &dlen);

	int i;
	printf("main msg: addr=%p,content=", msg);
	for(i=0;i<dlen;i++) {
		printf("%02x'%c' ", msg[i], msg[i]);
	}
	printf("\nget: \"%s\", dlen=%d, strlen=%d\n", msg, dlen, strlen(msg));
	return 0;
}
