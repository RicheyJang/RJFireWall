#include "helper.h"

int dealAppMessage(unsigned int pid, void *msg, unsigned int len) {
    nlSend(pid, msg, len);
}