---
title: 2017 RCTF Recho
date: 2017-05-28 10:44:03
tags:
- ROP
- stack overflow
- syscall
- libc-db
categories:
- ctf_practice
---

哎，正好星期三有考试，搞得我心不在焉，也没怎么认真做题。主要还是渣，渣，渣，重要的事要说三遍~！

## Challenge
第一题是个栈溢出，有两个问题需要解决：一是退出while循环，我那时不知道，现在知道了，可以用io.shutdown('send')，新姿势~~
<!-- more -->
```shell
shutdown(direction = "send")
Closes the tube for futher reading or writing depending on direction.

Parameters: direction (str) – Which direction to close; “in”, “read” or “recv” closes the tube in the ingoing direction, “out”, “write” or “send” closes it in the outgoing direction.
Returns:  None
```
第二个问题是libc没给。现在主要解决第二个问题。
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char nptr; // [sp+0h] [bp-40h]@2
  char buf[40]; // [sp+10h] [bp-30h]@4
  int v6; // [sp+38h] [bp-8h]@4
  int v7; // [sp+3Ch] [bp-4h]@2

  Init();
  write(1, "Welcome to Recho server!\n", 0x19uLL);
  while ( read(0, &nptr, 0x10uLL) > 0 )
  {
    v7 = atoi(&nptr);
    if ( v7 <= 15 )
      v7 = 16;
    v6 = read(0, buf, v7);
    buf[v6] = 0;
    printf("%s", buf);
  }
  return 0;
}
```
刚开始我是想用SROP来做，但因为这题用起来比较麻烦，所以我放弃了。后来问了我学长，按他的思路写一下。
MD，总忘记64位参数传递寄存器的顺序。
```
rdi, rsi, rdx, rcx, r8, r9
```
日狗了，栈上的数据TM总不对，有毒啊。。。我试了两台虚拟机都不行，我怀疑我的虚拟机出问题了。
```shell
gdb-peda$ x/32gx $rbp
0x7ffceda18870: 0x6010300000000000  0x4006fc0000000000
0x7ffceda18880: 0x0000180000000000  0x40070d0000000000
0x7ffceda18890: 0x00000a0000000000  0x0000000000400791
```
我肯定踩了狗屎了，这虚拟机肯定有毒。我放弃了，将思路记录下。

## Exploit
1. 首先执行一次脚本来leaking两个libc函数的地址从而得到libc.so。
2. 这时可以确定atoi和system的相对偏移，我们可以把atoi的got表项通过gadget add byte ptr [rdi], al;ret来改为system的地址。虽然偏移可能相差比较大，但是可以一字节一字节的修改。
3. 再次回到main函数中，发送/bin/sh;即可。

应该没啥问题吧...

后来看了下[官方wp](https://www.xctf.org.cn/information/e0d90ad9d0609320fd6743706135a80913d27b8d/)...其实很简单，程序中预留了flag字符串和用于syscall的gadget(syscall的地址很容易由read，write函数地址得出，加上相应偏移量即可)，所以只需要把read或其他函数的got表覆盖为syscall的地址，然后只需要一个改变rax的gadget(用于改变系统调用号)就能执行open->read->write系统调用链了。这种方法确实妙，出题人还是花了心思的。

这题还给了我一个提示，不要拿到题目就直接撸，可以先看一下字符窗口啥的，说不定有提示....很多题都直接提供get_flag函数的，ida有可能没显示这个函数，吃过好几次亏了~~





