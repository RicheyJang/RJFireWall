#include "tools.h"
#include "helper.h"

static struct IPLog *logHead = NULL,*logTail = NULL;
static unsigned int logNum = 0;
static DEFINE_RWLOCK(logLock);

// 释放首部多余的日志节点 整理链表
int rollLog() {
    struct IPLog *tmp;
    unsigned int count = 0;
    write_lock(&logLock);
    while(logNum > MAX_LOG_LEN) {
        if(logHead == NULL) { // 链表头指针丢失
            logHead = logTail;
            logNum = logTail==NULL ? 0 : 1;
            write_unlock(&logLock);
            return count;
        }
        tmp = logHead;
        logHead = logHead->nx;
        logNum--;
        count++;
        if(logTail == tmp) { // 链表尾指针丢失
            logTail = logHead;
            logNum = logTail==NULL ? 0 : 1;
        }
        kfree(tmp);
    }
    write_unlock(&logLock);
    return count;
}

// 新增日志记录
int addLog(struct IPLog log) {
    struct IPLog *newLog,*now;
    newLog = (struct IPLog *) kzalloc(sizeof(struct IPLog), GFP_KERNEL);
    if(newLog == NULL) {
        printk(KERN_WARNING "[fw logs] kzalloc fail.\n");
        return 0;
    }
    newLog->nx = NULL;
    memcpy(newLog, &log, sizeof(struct IPLog));
    // 新增日志至日志链表
    write_lock(&logLock);
    if(logTail == NULL) { // 日志链表为空
        logTail = newLog;
        logHead = logTail;
        logNum = 1;
        write_unlock(&logLock);
        return 1;
    }
    logTail->nx = newLog;
    logTail = newLog;
    logNum++;
    write_unlock(&logLock);
    if(logNum > MAX_LOG_LEN) {
        rollLog();
    }
    return 1;
}

int addLogBySKB(unsigned int action, struct sk_buff *skb) {
    struct IPLog log;
    unsigned short sport,dport;
	struct iphdr *header;
    log.tm = time(NULL);
    header = ip_hdr(skb);
	getPort(skb,header,&sport,&dport);
    log.saddr = ntohl(header->saddr);
    log.daddr = ntohl(header->daddr);
    log.sport = sport;
    log.dport = dport;
    log.action = action;
    addLog(log);
}

// 将所有过滤日志形成Netlink回包
void* formAllIPLogs(unsigned int *len) {
    struct KernelResponseHeader *head;
    struct IPLog *now;
    void *mem,*p;
    unsigned int count;
    read_lock(&logLock);
    for(now=logHead,count=0;now!=NULL;now=now->nx,count++);
    *len = sizeof(struct KernelResponseHeader) + sizeof(struct IPLog) * count;
    mem = kzalloc(*len, GFP_ATOMIC);
    if(mem == NULL) {
        printk(KERN_WARNING "[fw logs] formAllIPLogs kzalloc fail.\n");
        read_unlock(&logLock);
        return NULL;
    }
    head = (struct KernelResponseHeader *)mem;
    head->bodyTp = RSP_IPLogs;
    head->arrayLen = count;
    for(now=logHead,p=(mem + sizeof(struct KernelResponseHeader));now!=NULL;now=now->nx,p=p+sizeof(struct IPLog))
        memcpy(p, now, sizeof(struct IPLog));
    read_unlock(&logLock);
    return mem;
}