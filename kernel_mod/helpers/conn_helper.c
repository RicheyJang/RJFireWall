#include "helper.h"

static struct timer_list conn_timer;//定义计时器

int rollConn(void) {
	printk("[fw debug] call timer callback.\n");
	return 0;
}

// 计时器回调函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void conn_timer_callback(unsigned long arg) {
#else
void conn_timer_callback(struct timer_list *t) {
#endif
    rollConn();
	mod_timer(&conn_timer, jiffies + (CONN_ROLL_INTERVAL * HZ)); //重新激活定时器
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
	conn_timer.expires = jiffies + (CONN_ROLL_INTERVAL * HZ);//时间设置为CONN_ROLL_INTERVAL秒
	add_timer(&conn_timer);//激活定时器
}

// 关闭连接池
void conn_exit(void) {
	del_timer(&conn_timer);
}