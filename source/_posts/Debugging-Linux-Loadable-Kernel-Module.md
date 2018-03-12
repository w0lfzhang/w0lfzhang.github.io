---
title: Debugging Linux Loadable Kernel Module
date: 2017-08-09 00:41:28
tags:
- kernel debug
- LKM
categories:
- kernel_exploit
---

鉴于kernel rop实验没有成功，所以就把linux内核可加载模块的调试看了看，顺便记录一下下。

## Env
首先得重新编译内核，打开某些调试选项。因为我以前编译过了2.6.32的内核，所以就直接跳过这部分。
内核调试大部分情况下需要双机，我使用ubuntu14调试ubuntu10：
<!-- more -->
```shell
root@w0lfzhang666:/home/w0lfzhang/Desktop/kernel_debug/linux-2.6.32.21# uname -a
Linux w0lfzhang666 3.13.0-119-generic #166-Ubuntu SMP Wed May 3 12:18:55 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

w0lfzhang@w0lfzhang666:~$ uname -a
Linux w0lfzhang666 2.6.32.21 #1 SMP Fri May 19 13:40:41 CST 2017 i686 GNU/Linux
```
然后配置串口通信：
<img src="http://of38fq57s.bkt.clouddn.com/u10.PNG">
<img src="http://of38fq57s.bkt.clouddn.com/u14.PNG">

然后验证一下双机之间是否可正常通信：
```shell
ubuntu10
root@w0lfzhang666:/home/w0lfzhang# echo hello > /dev/ttyS1

ubuntu14
root@w0lfzhang666:/home/w0lfzhang/Desktop/kernel_debug/linux-2.6.32.21# cat /dev/ttyS1
hello
```
然后编辑ubuntu14的/etc/default/grub文件，在GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"这行添加'kgdboc=ttyS1,115200'，然后跟新grub：update-grub。
ubuntu10也差不多，只不过在那行增加'text kgdboc=ttyS1,115200'(增加text表示系统启动后是命令行界面而不是图形化)，然后更新grub。
更新后ubuntu10中没有像我参考的那篇博文一样有两个选项，我们可以自己修改一下/boot/grub/grub.cfg文件。
```shell
menuentry 'Ubuntu, with Linux 2.6.32.21' --class ubuntu --class gnu-linux --class gnu --class os {
	recordfail
	insmod ext2
	set root='(hd0,1)'
	search --no-floppy --fs-uuid --set 89a3d212-dc2a-4150-ada3-2dc7326cf585
	linux	/boot/vmlinuz-2.6.32.21 root=UUID=89a3d212-dc2a-4150-ada3-2dc7326cf585 ro   quiet splash text kgdboc=ttyS1,115200
	initrd	/boot/initrd.img-2.6.32.21
}
menuentry 'Ubuntu, with Linux 2.6.32.21---wait' --class ubuntu --class gnu-linux --class gnu --class os {
	recordfail
	insmod ext2
	set root='(hd0,1)'
	search --no-floppy --fs-uuid --set 89a3d212-dc2a-4150-ada3-2dc7326cf585
	echo	'Loading Linux 2.6.32.21 ...'
	linux	/boot/vmlinuz-2.6.32.21 root=UUID=89a3d212-dc2a-4150-ada3-2dc7326cf585 ro  quiet splash text kgdbwait kgdboc=ttyS1,115200
	echo	'Loading initial ramdisk ...'
	initrd	/boot/initrd.img-2.6.32.21
}
```
其中加了kgdbwait的表示系统刚启动就可以进入调试模式，没有的表示可在系统启动后调试内核。

## Debug
首先我们需要把我们ubuntu10内核源码编译的全部文件拷贝到ubuntu14中。启动ubuntu10，选择wait选项。然后在ubuntu14中执行下述命令：
```shell
root@w0lfzhang666:/home/w0lfzhang/Desktop/kernel_debug/linux-2.6.32.21# gdb vmlinux
......
......
Type "apropos word" to search for commands related to "word"...
Reading symbols from vmlinux...done.
gdb-peda$ set serial baud 115200
gdb-peda$ target remote /dev/ttyS1
Remote debugging using /dev/ttyS1
qTStatus: Target returns error code '22'.
Warning: not running or target is remote
kgdb_breakpoint () at kernel/kgdb.c:1721
1721		wmb(); /* Sync point after breakpoint */
qTStatus: Target returns error code '22'.
gdb-peda$ c
Continuing.
qTStatus: Target returns error code '22'.

```
此时ubuntu10处于运行状态，想让它断下来处于调试状态，可运行如下命令：
```
echo g > /proc/sysrq-trigger
```
此时ubuntu14可再次调试其内核：
```
gdb-peda$ c
Continuing.
qTStatus: Target returns error code '22'.
[New Thread 1774]

Program received signal SIGTRAP, Trace/breakpoint trap.
[Switching to Thread 1774]
Warning: not running or target is remote
kgdb_breakpoint () at kernel/kgdb.c:1721
1721		wmb(); /* Sync point after breakpoint */
gdb-peda$ 
```
接下来调试LKM，我把上次kernel rop的模块拿到ubuntu10编译一下，然后安装，用如下命令查看下加载基址；
```
cat /proc/modules | grep drv
drv 1688 0 - Live 0xf916f000
```
然后让ubuntu10处于调试模式，ubuntu14加载符号表并且下断点：
```
gdb-peda$ add-symbol-file /home/w0lfzhang/Desktop/kernel_rop/drv.ko 0xf916f000
add symbol table from file "/home/w0lfzhang/Desktop/kernel_rop/drv.ko" at
	.text_addr = 0xf916f000
Reading symbols from /home/w0lfzhang/Desktop/kernel_rop/drv.ko...done.
gdb-peda$ b device_ioctl 
Breakpoint 1 at 0xf916f0bc: file /home/w0lfzhang/Desktop/kernel_exp/kernel_rop/drv.c, line 55.
```
我们用kernel_rop中的trigger程序来调用内核模块的device_ioctl函数。
```c
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drv.h"

#define DEVICE_PATH "/dev/vulndrv"

int main(int argc, char **argv) {
	int fd;
	struct drv_req req;

	req.offset = atoll(argv[1]);

	//map = mmap((void *)..., ..., 3, 0x32, 0, 0);

	fd = open(DEVICE_PATH, O_RDONLY); 

	if (fd == -1) {
		perror("open");
	}

	ioctl(fd, 0, &req);

	return 0;
}
```
触发后我们可以在ubuntu14中看到已经断下：
```
gdb-peda$ c
Continuing.
qTStatus: Target returns error code '22'.
[New Thread 1808]
[Switching to Thread 1808]
Warning: not running or target is remote

Breakpoint 1, device_ioctl (file=0xc2791300, cmd=0x0, args=0xbff9089c)
    at /home/w0lfzhang/Desktop/kernel_exp/kernel_rop/drv.c:55
55	/home/w0lfzhang/Desktop/kernel_exp/kernel_rop/drv.c: No such file or directory.
gdb-peda$ p device_ioctl 
$1 = {long (struct file *, unsigned int, 
    unsigned long)} 0xf916f0a8 <device_ioctl>
gdb-peda$ ni
qTStatus: Target returns error code '22'.
Warning: not running or target is remote
0xf916f0bf	55	in /home/w0lfzhang/Desktop/kernel_exp/kernel_rop/drv.c
```
唯一的缺点是没有gdb调试用户态那样方便，无法直接显示汇编代码及寄存器的值。不过影响不是很大，可以看ida...

如果在ubuntu10启动时选择的是没有wait的选项，那么在调试需要注意的是当再ubuntu14中输入target remote /dev/ttyS1命令时，然后我们还需要在ubuntu10中输入echo g > /proc/sysrq-trigger命令。这时像前面那样调试即可。

本来想直接克隆ubuntu14来调一下那个kernel rop的实验，但是因为没重新编译内核，所以行不通~还是得编译一下64位的内核，下次反正得用的..

## Links
[利用GDB、KGDB调试应用程序及内核驱动模块](http://blog.nsfocus.net/gdb-kgdb-debug-application)
