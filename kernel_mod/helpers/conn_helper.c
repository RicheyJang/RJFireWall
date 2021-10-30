#include "helper.h"

// --- 红黑树相关 ---

static struct rb_root connRoot = RB_ROOT;
static DEFINE_RWLOCK(connLock);

// 比较连接标识符
int connKeyCmp(conn_key_t l, conn_key_t r) {
	register int i;
	for(i=0;i<CONN_MAX_SYM_NUM;i++) {
		if(l[i] != r[i]) {
			return (l[i] < r[i]) ? -1 : 1;
		}
	}
	return 0;
}

// 按标识符查找节点，无该节点返回则NULL
struct connNode *searchNode(struct rb_root *root, conn_key_t key) {
	int result;
	struct rb_node *node;
	read_lock(&connLock);
	node = root->rb_node;
	while (node) {
		struct connNode *data = rb_entry(node, struct connNode, node);
		result = connKeyCmp(key, data->key);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else { // 找到节点
			read_unlock(&connLock);
			return data;
		}
	}
	read_unlock(&connLock);
	return NULL;
}

// 插入新节点，返回0标识节点已存在
int insertNode(struct rb_root *root, struct connNode *data) {
	struct rb_node **new, *parent;
	if(data == NULL) {
		return 0;
	}
	parent = NULL;
	read_lock(&connLock);
	new = &(root->rb_node);
	/* Figure out where to put new node */
	while (*new) {
		struct connNode *this = rb_entry(*new, struct connNode, node);
		int result = connKeyCmp(data->key, this->key);
		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else { // 已存在
			read_unlock(&connLock);
			return 0;
		}
	}
	/* Add new node and rebalance tree. */
	read_unlock(&connLock);
	write_lock(&connLock);
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
	write_unlock(&connLock);
	return 1; // 插入成功
}

// 删除节点
void eraseNode(struct rb_root *root, struct connNode *node) {
	if(node != NULL) {
		write_lock(&connLock);
		rb_erase(&(node->node), root);
		write_unlock(&connLock);
		kfree(node);
	}
}

// --- 业务相关 ---
// 是否超时
int isTimeout(unsigned long expires) {
	return (jiffies >= expires)? 1 : 0; // 当前时间 >= 超时时间 ?
}

// 检查是否存在指定连接
int hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport) {
	conn_key_t key;
	struct connNode *node = NULL;
	// 构建标识符
	key[0] = sip;
	key[1] = dip;
	key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
	// 查找节点
	node = searchNode(&connRoot, key);
	if(node != NULL) {
		node->expires = timeFromNow(CONN_EXPIRES); // 重新设置超时时间
		return 1;
	}
	return 0;
}

// 新建连接
int addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport) {
	// 初始化
	struct connNode *node = (struct connNode *)kzalloc(sizeof(connNode), GFP_KERNEL);
	if(node == NULL) {
		printk(KERN_WARNING "[fw conns] kzalloc fail.\n");
		return 0;
	}
	node->expires = timeFromNow(CONN_EXPIRES); // 设置超时时间
	// 构建标识符
	node->key[0] = sip;
	node->key[1] = dip;
	node->key[2] = ((((unsigned int)sport) << 16) | ((unsigned int)dport));
	// 插入节点
	return insertNode(&connRoot, node);
}

// 依据过滤规则，删除相关连接
int eraseConnRelated(struct IPRule rule) {
	struct rb_node *node;
	struct connNode *needDel = NULL;
	unsigned int pmask,port,count = 0;
	int hasChange = 1; // 连接池是否有更改（删除节点）
	// 初始化
	pmask = (rule.sport<0)? 0 : 0xFFFFu;
	pmask <<= 16;
	pmask |= (rule.dport<0)? 0 : 0xFFFFu;
	port = (rule.sport<0)? 0 : (unsigned int)rule.sport;
	port <<= 16;
	port |= (rule.dport<0)? 0 : (unsigned int)rule.dport;
	// 删除相关节点
	while(hasChange) { // 有更改时，持续遍历，防止漏下节点
		hasChange = 0;
		read_lock(&connLock);
		for (node = rb_first(&connRoot); node; node = rb_next(node)) {
			needDel = rb_entry(node, struct connNode, node);
			if(((rule.saddr & rule.smask) == (needDel->key[0] & rule.smask)) &&
			   ((rule.daddr & rule.dmask) == (needDel->key[1] & rule.dmask)) &&
			   ((      port &      pmask) == (needDel->key[2] &      pmask)) ) { // 相关规则
				hasChange = 1;
				break;
			}
		}
		read_unlock(&connLock);
		if(hasChange) { // 需要删除 开始删除节点
			eraseNode(&connRoot, needDel);
			count++;
		}
	}
	return count;
}

// 刷新连接池（定时器所用），删除超时连接
int rollConn(void) {
	struct rb_node *node;
	struct connNode *needDel = NULL;
	int hasChange = 1; // 连接池是否有更改（删除节点）
	printk("[fw conns] flush all conn start.\n");
	while(hasChange) { // 有更改时，持续遍历，防止漏下节点
		hasChange = 0;
		read_lock(&connLock);
		for (node = rb_first(&connRoot); node; node = rb_next(node)) {
			needDel = rb_entry(node, struct connNode, node);
			if(isTimeout(needDel->expires)) { // 超时 确认删除
				hasChange = 1;
				break;
			}
		}
		read_unlock(&connLock);
		if(hasChange) { // 需要删除 开始删除节点
			eraseNode(&connRoot, needDel);
		}
	}
	printk("[fw conns] flush all conn finish.\n");
	return 0;
}

// --- 定时器相关 ---
static struct timer_list conn_timer;//定义计时器

// 计时器回调函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void conn_timer_callback(unsigned long arg) {
#else
void conn_timer_callback(struct timer_list *t) {
#endif
    rollConn();
	mod_timer(&conn_timer, timeFromNow(CONN_ROLL_INTERVAL)); //重新激活定时器
}

// 初始化连接池相关内容（包括定时器）
void conn_init(void) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    init_timer(&conn_timer);
    conn_timer.function = &conn_timer_callback;//设置定时器回调方法
    conn_timer.data = ((unsigned long)0);
#else
    timer_setup(&conn_timer, conn_timer_callback, 0);
#endif
	conn_timer.expires = timeFromNow(CONN_ROLL_INTERVAL);//超时时间设置为CONN_ROLL_INTERVAL秒后
	add_timer(&conn_timer);//激活定时器
}

// 关闭连接池
void conn_exit(void) {
	del_timer(&conn_timer);
}