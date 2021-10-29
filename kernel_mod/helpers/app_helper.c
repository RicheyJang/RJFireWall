#include "helper.h"

extern unsigned int DEFAULT_ACTION;

int sendMsgToApp(unsigned int pid, const char *msg) {
    void* mem;
    unsigned int rspLen;
    struct KernelResponseHeader *rspH;
    rspLen = sizeof(struct KernelResponseHeader) + strlen(msg) + 1;
    mem = kzalloc(rspLen, GFP_ATOMIC);
    rspH = (struct KernelResponseHeader *)mem;
    rspH->bodyTp = RSP_MSG;
    rspH->arrayLen = strlen(msg);
    memcpy(mem+sizeof(struct KernelResponseHeader), msg, strlen(msg));
    nlSend(pid, mem, rspLen);
    kfree(mem);
    return rspLen;
}

int dealAppMessage(unsigned int pid, void *msg, unsigned int len) {
    struct APPRequest *req;
    struct KernelResponseHeader *rspH;
    void* mem;
    unsigned int rspLen;
    req = (struct APPRequest *) msg;
    switch (req->tp)
    {
    case REQ_GETAllIPRules:
        mem = formAllIPRules(&rspLen);
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDIPRule:
        if(addIPRuleToChain(req->ruleName, req->msg.ipRule)==NULL) {
            rspLen = sendMsgToApp(pid, "Fail: no such rule.");
            printk("[fw k2app] add rule fail\n");
        } else {
            rspLen = sendMsgToApp(pid, "Success.");
            printk("[fw k2app] add one rule success\n");
        }
        break;
    case REQ_DELIPRule:
        rspLen = sizeof(struct KernelResponseHeader);
        rspH = (struct KernelResponseHeader *)kzalloc(rspLen, GFP_KERNEL);
        rspH->bodyTp = RSP_Only_Head;
        rspH->arrayLen = delIPRuleFromChain(req->ruleName);
        printk("[fw k2app] success del %d rules.\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen);
        kfree(rspH);
        break;
    case REQ_SETAction:
        if(req->msg.defaultAction == NF_ACCEPT) {
            DEFAULT_ACTION = NF_ACCEPT;
            rspLen = sendMsgToApp(pid, "Set default action to ACCEPT.");
            printk("[fw k2app] Set default action to NF_ACCEPT.\n");
        } else {
            DEFAULT_ACTION = NF_DROP;
            rspLen = sendMsgToApp(pid, "Set default action to DROP.");
            printk("[fw k2app] Set default action to NF_DROP.\n");
        }
        break;
    default:
        rspLen = sendMsgToApp(pid, "No such req.");
        break;
    }
    return rspLen;
}