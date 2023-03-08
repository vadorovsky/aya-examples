#pragma once

#include "vmlinux.h"

pid_t task_struct_pid(struct task_struct *task);
pid_t task_struct_tgid(struct task_struct *task);
