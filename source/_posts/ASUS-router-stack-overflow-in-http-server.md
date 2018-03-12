---
title: ASUS router stack overflow in http server
date: 2018-01-17 11:14:49
tags:
- iot
- stack overflow
categories:
- iot
---

This is the detail about CVE-2018-5721.

## Detail
The vulnerability exists in router/httpd/web.c. When the authenticated users update some settings, it will call the function ej_update_variables.
While the length of variable action_script is not checked. The attackers can post any data to the server, which can make the server crashed or code execution.
<!-- more -->
```c
static int ej_update_variables(int eid, webs_t wp, int argc, char_t **argv) {
	...
	if (strlen(action_script) > 0) {
		char *p1, *p2;

		memset(notify_cmd, 0, sizeof(notify_cmd));
		if((p1 = strstr(action_script, "_wan_if")))
		{
			p1 += 7;
			strncpy(notify_cmd, action_script, p1 - action_script);
			p2 = notify_cmd + strlen(notify_cmd);
			sprintf(p2, " %s%s", wan_unit, p1);
		}
		...
	}
	...
}
```
## POC
A simple proving.
Fist of all, login into the web management(via any way if you could).
Then just update some setting.
Using burpsuite to change the value of action_script(make sure including "_wan_if"):
<img src="http://of38fq57s.bkt.clouddn.com/burp.PNG">
Then we can see the register of pc has been overwritten:
```
gdb-peda$ target remote 192.168.50.1:23333
Remote debugging using 192.168.50.1:23333
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
Warning: not running or target is remote
Save/restore a working gdb session to file as a script
Usage:
    session save [filename]
    session restore [filename]

0x405954cc in ?? ()
gdb-peda$ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
Warning: not running or target is remote
Save/restore a working gdb session to file as a script
Usage:
    session save [filename]
    session restore [filename]

0x64646464 in ?? ()
gdb-peda$ i r
r0             0x0	0x0
r1             0x1	0x1
r2             0x258	0x258
r3             0x0	0x0
r4             0x64646464	0x64646464
r5             0x64646464	0x64646464
r6             0x64646464	0x64646464
r7             0x64646464	0x64646464
r8             0x64646464	0x64646464
r9             0x64646464	0x64646464
r10            0x64646464	0x64646464
r11            0x405f04e8	0x405f04e8
r12            0x40576edc	0x40576edc
sp             0xbede3e80	0xbede3e80
lr             0x4056a764	0x4056a764
pc             0x64646464	0x64646464
cpsr           0x60000010	0x60000010
```




