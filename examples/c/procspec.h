// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#ifndef __PROCSPEC_H
#define __PROCSPEC_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_EVENT_FDS 32

struct proc_spec_key {
	int pid_ns;
	char specs[MAX_FILENAME_LEN];
};

struct proc_spec_value {
	__u16 event_fds[MAX_EVENT_FDS];
};

#endif /* __PROCSPEC_H */
