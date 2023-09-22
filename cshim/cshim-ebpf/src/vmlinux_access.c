#include "vmlinux_access.h"

int task_struct_pid(struct task_struct *task)
{
	if (task == 0) {
		return -1;
	}
	return BPF_CORE_READ(task, pid);
}

int task_struct_tgid(struct task_struct *task)
{
	if (task == 0) {
		return -1;
	}
	return BPF_CORE_READ(task, tgid);
}
