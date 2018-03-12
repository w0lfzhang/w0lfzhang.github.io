---
title: Linux Seccomp Learning
date: 2017-11-29 17:22:26
tags:
- seccomp
- syscall
categories:
- linux security
---

It's been a long time since I wrote my last blog. Lazy and busy! 

## What is seccomp
seccomp (short for secure computing mode) is a computer security facility in the Linux kernel which was merged into the Linux kernel mainline in kernel version 2.6.12. As we all know, plenty of system calls are exposed to the programs directly, but not all system calls are needed to the users, which will be dangerous if someone abuses the system calls. By using seccomp, we can limit the program to use the specific system calls, which can make the system more secure.
<!-- more -->

## How to use it
seccomp mode can be enabled via the prctl(2) system call using the PR_SET_SECCOMP argument, or (since Linux kernel 3.17[4]) via the seccomp(2) system call and the prerequisite is the kernel is configured with CONFIG_SECCOMP and CONFIG_SECCOMP_FILTER. seccomp mode used to be enabled by writing to a file, /proc/self/seccomp, but this method was removed in favor of prctl().
seccomp supports two modes: SECCOMP_MODE_STRICT and SECCOMP_MODE_FILTER. In SECCOMP_MODE_STRICT, it cannot use any system calls except exit(), sigreturn(), read() and write(). 
Have a look at the [kernel source code](http://elixir.free-electrons.com/linux/v3.13.1/source/kernel/seccomp.c#L377):
```c
int __secure_computing(int this_syscall)
{
	int mode = current->seccomp.mode;
	int exit_sig = 0;
	int *syscall;
	u32 ret;

	switch (mode) {
	case SECCOMP_MODE_STRICT:
		syscall = mode1_syscalls;
#ifdef CONFIG_COMPAT
		if (is_compat_task())
			syscall = mode1_syscalls_32;
#endif
		do {
			if (*syscall == this_syscall)
				return 0;
		} while (*++syscall);
		exit_sig = SIGKILL;
		ret = SECCOMP_RET_KILL;
		break;
#ifdef CONFIG_SECCOMP_FILTER
	case SECCOMP_MODE_FILTER: {
		......
}
```
model_syscalls is the array including the syscall numbers of exit(), sigreturn(), read() and write().
```c
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};
```
In SECCOMP_MODE_FILTER, since linux 3.5, it is possible to define advanced custom filters based on the BPF (Berkley Packet Filters) to limit what system calls and their arguments can be used by the process. In this mode, the caller must have the CAP_SYS_ADMIN ability or the thread must have been set [no_new_privs](https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt).
```c
case SECCOMP_MODE_FILTER: {
		int data;
		struct pt_regs *regs = task_pt_regs(current);
		ret = seccomp_run_filters(this_syscall);
		data = ret & SECCOMP_RET_DATA;
		ret &= SECCOMP_RET_ACTION;
		switch (ret) {
		case SECCOMP_RET_ERRNO:
			/* Set the low-order 16-bits as a errno. */
			syscall_set_return_value(current, regs,
						 -data, 0);
			goto skip;
		case SECCOMP_RET_TRAP:
			/* Show the handler the original registers. */
			syscall_rollback(current, regs);
			/* Let the filter pass back 16 bits of data. */
			seccomp_send_sigsys(this_syscall, data);
			goto skip;
		case SECCOMP_RET_TRACE:
			/* Skip these calls if there is no tracer. */
			if (!ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)) {
				syscall_set_return_value(current, regs,
							 -ENOSYS, 0);
				goto skip;
			}
			/* Allow the BPF to provide the event message */
			ptrace_event(PTRACE_EVENT_SECCOMP, data);
			/*
			 * The delivery of a fatal signal during event
			 * notification may silently skip tracer notification.
			 * Terminating the task now avoids executing a system
			 * call that may not be intended.
			 */
			if (fatal_signal_pending(current))
				break;
			if (syscall_get_nr(current, regs) < 0)
				goto skip;  /* Explicit request to skip. */

			return 0;
		case SECCOMP_RET_ALLOW:
			return 0;
		case SECCOMP_RET_KILL:
		default:
			break;
		}
		exit_sig = SIGSYS;
		break;
	}

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU
```
Each syscall is sent to the filter which tells what action to take:
1. SECCOMP_RET_KILL: Immediate kill with SIGSYS
2. SECCOMP_RET_TRAP: Send a catchable SIGSYS, giving a chance to emulate the syscall
3. SECCOMP_RET_ERRNO: Force errno value
4. SECCOMP_RET_TRACE: Yield decision to ptracer or set errno to -ENOSYS
5. SECCOMP_RET_ALLOW: Allow

In the code, seccomp_run_filters returns valid seccomp BPF response codes. And then choose what to do according to 'ret'. Of course we can control the 'response codes' in user space through seecomp or prctl syscall.

Last, we can see if seccomp is set via read the file /proc/<pid>/status:
0: closed.
1: in STRICT mode.
2: in FILTER mode.
```shell
w0lfzhang@w0lfzhang666:~/Desktop/linux-security$ cat /proc/1/status | grep Seccomp
Seccomp:	0
```

## Demos to show
### SECCOMP_MODE_STRICT
```c
#include <stdio.h>         /* printf */
#include <sys/prctl.h>     /* prctl */
#include <linux/seccomp.h> /* seccomp's constants */
#include <unistd.h>        /* dup2: just for test */

int main() {
  printf("step 1: unrestricted\n");

  // Enable filtering
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
  printf("step 2: only 'read', 'write', 'exit' and 'sigreturn' syscalls\n");
  
  // Redirect stderr to stdout
  dup2(1, 2);
  printf("step 3: !! YOU SHOULD NOT SEE ME !!\n");

  // Success (well, not so in this case...)
  return 0; 
}
```
When running the program:
```shell
w0lfzhang@w0lfzhang666:~/Desktop/linux-security$ ./seccomp1 
step 1: unrestricted
step 2: only 'read', 'write', '_exit' and 'sigreturn' syscalls
Killed
```
So it's apparent when a forbidden syscall is issued, the program is immediately killed.

### SECCOMP_MODE_FILTER
We can use libseccomp to simplify our work:
```shell
sudo apt-get install libseccomp-dev
```
```c
#include <stdio.h>   /* printf */
#include <unistd.h>  /* dup2: just for test */
#include <seccomp.h> /* libseccomp */

int main() {
  printf("step 1: unrestricted\n");

  // ensure none of our children will ever be granted more priv
  // (via setuid, capabilities, ...)
  prctl(PR_SET_NO_NEW_PRIVS, 1);
  // ensure no escape is possible via ptrace
  prctl(PR_SET_DUMPABLE, 0);
  
  // Init the filter
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

  // setup basic whitelist
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  
  // setup our rule
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2, 
                        SCMP_A0(SCMP_CMP_EQ, 1),
                        SCMP_A1(SCMP_CMP_EQ, 2));

  // build and load the filter
  seccomp_load(ctx);
  printf("step 2: only the whitelist and dup2(1, 2) syscalls\n");
 
  // Redirect stderr to stdout
  dup2(1, 2);
  printf("step 3: stderr redirected to stdout\n");

  // Duplicate stderr to arbitrary fd
  dup2(2, 42);
  printf("step 4: !! YOU SHOULD NOT SEE ME !!\n");

  // Success (well, not so in this case...)
  return 0; 
}
```
Run the program:
```shell
w0lfzhang@w0lfzhang666:~/Desktop/linux-security$ ./seccomp2
step 1: unrestricted
step 2: only the whitelist and dup2(1, 2) syscalls
step 3: stderr redirected to stdout
Bad system call
```

## Links
[Introduction to seccomp: BPF linux syscall filter](https://blog.yadutaf.fr/2014/05/29/introduction-to-seccomp-bpf-linux-syscall-filter/)
[seccomp 學習筆記](https://szlin.me/2017/08/23/kernel_seccomp/)
[SECCOMP(2) Linux Programmer's Manual SECCOMP(2)](http://man7.org/linux/man-pages/man2/seccomp.2.html)