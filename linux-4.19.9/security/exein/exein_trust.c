#include <linux/slab.h>
#include <linux/gfp.h>
#include "exein_types.h"
#include "exein_trust.h"
#include <linux/sched/signal.h>

void exein_mark_not_trusted(uint16_t tag, pid_t pid){
	int ret = kill_pid(find_vpid(pid), SIGKILL, 1);
	if (ret < 0) {
		printk(KERN_INFO "error kill pid\n");
		}
	printk(KERN_CRIT "EXEIN MARKED PROCESS AS NOT TRUSTED [tag:%d pid:%d]\n", tag, pid);
}
