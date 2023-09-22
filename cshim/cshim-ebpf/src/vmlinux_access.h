#pragma once

#include "types.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct task_struct {
  int pid;
  int tgid;
} __attribute__((preserve_access_index));

int task_struct_pid(struct task_struct *task);
int task_struct_tgid(struct task_struct *task);
