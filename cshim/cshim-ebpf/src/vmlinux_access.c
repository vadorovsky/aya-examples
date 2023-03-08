#include "vmlinux_access.h"

pid_t task_struct_pid(struct task_struct *task)
{
	return __builtin_preserve_access_index(task->pid);
}

pid_t task_struct_tgid(struct task_struct *task)
{
	return __builtin_preserve_access_index(task->tgid);
}
