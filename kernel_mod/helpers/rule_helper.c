#include "helper.h"

static struct IPRule *ipRuleHead = NULL;
static DEFINE_RWLOCK(ipRuleLock);

// 在名称为after的规则后新增一条规则，after为空时则在首部新增一条规则
struct IPRule * addIPRuleToChain(char after[], struct IPRule rule) {
    struct IPRule *newRule,*now;
    newRule = (struct IPRule *) kzalloc(sizeof(struct IPRule), GFP_ATOMIC);
    memcpy(newRule, &rule, sizeof(struct IPRule));

    write_lock(&ipRuleLock);
    if(ipRuleHead == NULL) {
        ipRuleHead = newRule;
        ipRuleHead->nx = NULL;
        write_unlock(&ipRuleLock);
        return newRule;
    }
    if(strlen(after)==0) {
        newRule->nx = ipRuleHead;
        ipRuleHead = newRule;
        write_unlock(&ipRuleLock);
        return newRule;
    }
    for(now=ipRuleHead;now!=NULL;now=now->nx) {
        if(strcmp(now->name, after)==0) {
            newRule->nx = now->nx;
            now->nx = newRule;
            write_unlock(&ipRuleLock);
            return newRule;
        }
    }
    // 添加失败
    write_unlock(&ipRuleLock);
    kfree(newRule);
    return NULL;
}

// 删除所有名称为name的规则
int delIPRuleFromChain(char name[]) {
    struct IPRule *now;
    int count = 0;
    write_lock(&ipRuleLock);
    while(ipRuleHead!=NULL && strcmp(ipRuleHead->name,name)==0) {
        now = ipRuleHead;
        ipRuleHead = ipRuleHead->nx;
        kfree(now);
    }
    for(now=ipRuleHead;now!=NULL && now->nx!=NULL;) {
        if(strcmp(now->nx->name,name)==0) { // 删除下条规则
            now->nx = now->nx->nx;
        } else {
            now = now->nx;
        }
    }
    write_unlock(&ipRuleLock);
}

unsigned int matchIPRules(struct sk_buff *skb) {
    
}