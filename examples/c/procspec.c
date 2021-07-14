// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "procspec.h"
#include "procspec.skel.h"


static struct env {
	bool verbose;
	struct proc_spec_key ps_key;
	struct proc_spec_value ps_value;
} env;

const char *argp_program_version = "procspec 0.1";
const char *argp_program_bug_address = "<geyslan@gmail.com>";
const char argp_program_doc[] =
"BPF procspec application.\n"
"\n"
"It updates bpf process-spec map on policy/container changes.\n"
"\n"
"USAGE: ./procspec -n namespace-id -p process-spec -f event-filter-spec-fd1 ... [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "namespace-id", 'n', "NAMESPACE-ID", 0, "Namespace ID" },
	{ "process-spec", 'p', "PROCESS-SPEC", 0, "Process specification (wildcards)" },
	{ "event-filter-fds", 'f', "EVENT-FILTER-FDS", 0, "Event Filter Descriptors related to the process-spec" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'n':
		errno = 0;
		env.ps_key.pid_ns = (unsigned int) strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'p':
		strncpy(env.ps_key.specs, arg, sizeof(env.ps_key.specs)-1);
		env.ps_key.specs[MAX_FILENAME_LEN-1] = '\0';		
		break;
	case 'f':
		int index = 0;
		while (*arg && index < MAX_EVENT_FDS) {
			while (*arg && *arg == ' ')
				arg++;

			env.ps_value.event_fds[index] = (__u16) atoi(arg);
			index++;

			while (*arg && *arg != ' ')
				arg++;
		}
		break;
	//case ARGP_KEY_NO_ARGS:
		// fallthrough
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct procspec_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Load and verify BPF application */
	skel = procspec_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = procspec_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Get map fd by map name */
	int map_fd;
	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "proc_spec");
	if (map_fd == -EINVAL) {
		fprintf(stderr, "Failed to find map fd by name\n");
		goto cleanup;
	}

	/* Insert/Update map entry using map fd */
	err = bpf_map_update_elem(map_fd, &env.ps_key, &env.ps_value, BPF_ANY);
	if (err)
		fprintf(stderr, "Failed to insert/update proc_spec map entry\n");
	else
		printf("proc_spec map updated!\n");

cleanup:
	/* Clean up */
	procspec_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
