---
title: XNUCA SSD QEMU ESCAPE
date: 2018-12-05 17:36:34
tags:
- vmescape
categories:
- vmescape
---


A few weeks ago, I remember I played xnuca ctf during my working time~ And I just saw the challenge ssd, because it was a qemu-escape and I found the bug at that time, but I didn't write the exploit script because I thought it's not so hard(I didn't know how many teams solved this challenge), after all, work is work~ The reason I write this write-up is to help those guys want to learn qemu-escape. I will give a detail talking about the exploit.
<!--more-->

## The Challenge
The first thing you need to do is figure out what the device does. If you are unfamiliar with how qemu emulates devices, you can see my previous post [here](https://www.w0lfzhang.com/2018/11/02/How-QEMU-Emulates-Devices/). I won't talk this much.

After analysis, I think it's a really simple device. And if you are a linux device driver programmer, nothing is difficult to understand. Let's see xnuca_mmio_read:
```c
__int64 __fastcall xnuca_mmio_read(__int64 a1, unsigned __int8 a2)
{
  _BYTE v3[12]; // [rsp+20h] [rbp-14h]

  *(_DWORD *)&v3[8] = 0;
  *(_QWORD *)v3 = a2;
  if ( a2 == 16 )
    return *(unsigned int *)(a1 + 0x9DC);
  if ( a2 == 32 )
    *(_QWORD *)&v3[4] = *(unsigned int *)(a1 + 0x9D0);
  return *(_QWORD *)&v3[4];
}
```
Easy and useless for your exploit. And turn to xnuca_mmio_write:
```c
__int64 __fastcall xnuca_mmio_write(__int64 XnucaState, int addr, unsigned int val, int size)
{
  __int64 result; // rax
  int _addr; // [rsp+10h] [rbp-30h]

  _addr = addr;
  result = XnucaState;
  if ( size == 4 || size == 8 )
  {
    result = (unsigned __int8)addr;
    if ( (unsigned __int8)addr == 32 )
    {
      result = xnuca_set_timer(XnucaState);
    }
    else if ( (_DWORD)result == 48 )
    {
      result = xnuca_send_request(
                 XnucaState,
                 (unsigned __int64)(addr & 0xF00) >> 8,
                 (unsigned __int64)((unsigned __int16)addr & 0xF000) >> 12,
                 (_addr & 0xFF0000u) >> 16,
                 (unsigned __int8)val);
    }
    else if ( (_DWORD)result == 16 )
    {
      result = xnuca_auth(XnucaState, val);
    }
  }
  return result;
}
```
It's obvious you should focus on this function. There are 3 types requests for the device:
```
1. auth
2. set_timer
3. send_request
```
Let's step into xnuca_auth:
```c
__int64 __fastcall xnuca_auth(__int64 XnucaState, char val)
{
  __int64 result; // rax

  if ( *(_DWORD *)(XnucaState + 0x9DC) <= 4u )
  {
    if ( *(_BYTE *)(XnucaState + *(unsigned int *)(XnucaState + 0x9DC) + 0x9D4) == val )
      ++*(_DWORD *)(XnucaState + 0x9DC);
    else
      *(_DWORD *)(XnucaState + 0x9DC) = 0;
  }
  result = *(unsigned int *)(XnucaState + 0x9DC);
  if ( (_DWORD)result == 5 )
  {
    *(_DWORD *)(XnucaState + 0x9D0) |= 1u;
    result = XnucaState;
    *(_DWORD *)(XnucaState + 0x9DC) = 0;
  }
  return result;
}
```
The function operates the field at offset 0x9DC and 0x9D0 of XnucaState structure. What we should remember is that it set the lowest bit of the 0x9D0-field when the 0x9DC-field equals 5. 
Then we see the xnuca_set_timer:
```c
__int64 __fastcall xnuca_set_timer(__int64 a1)
{
  __int64 result; // rax

  result = *(_DWORD *)(a1 + 0x9D0) & 1;
  if ( (_DWORD)result )
  {
    result = *(_DWORD *)(a1 + 0x9D0) & 2;
    if ( !(_DWORD)result )
    {
      timer_init_ns(a1 + 0xA00, 0, (__int64)xnuca_timer, a1);
      result = a1;
      *(_DWORD *)(a1 + 0x9D0) |= 2u;
    }
  }
  return result;
}
```
See? Only you set the 0x9D0-field's lowest bit, you can set the timer for the device. But it's just initializing the timer, if you want trigger the function xnuca_timer, you must invoke time_add or time_mod to add the timer into kernel. And let's have a look what the device will do when the time is expired. 
```c
__int64 __fastcall xnuca_timer(__int64 a1)
{
  __int64 result; // rax
  int v2; // eax
  void **v3; // rbx

  result = *(_DWORD *)(a1 + 0x9D0) & 4;
  if ( (_DWORD)result )
  {
    v2 = *(_DWORD *)(a1 + 0x9EC);
    switch ( v2 )
    {
      case 2:
        *(_DWORD *)(*(unsigned int *)(a1 + 0x9F0)
                  + *(_QWORD *)(*(_QWORD *)(a1 + 0x9E0) + 8LL * *(unsigned int *)(a1 + 0x9E8))) = *(_DWORD *)(a1 + 0x9F8);
        break;
      case 3:
        free(*(void **)(*(_QWORD *)(a1 + 0x9E0) + 8LL * *(unsigned int *)(a1 + 0x9E8)));
        break;
      case 1:
        v3 = (void **)(*(_QWORD *)(a1 + 0x9E0) + 8LL * *(unsigned int *)(a1 + 0x9E8));
        *v3 = malloc(*(unsigned int *)(a1 + 0x9F0));
        break;
    }
    result = a1;
    *(_DWORD *)(a1 + 0x9D0) &= 0xFFFFFFFB;
  }
  return result;
}
```
Malloc, edit, and free? That's right guess~ Obviously, the field at offset 0x9E0 is a ptr-array, field-0x9E8 is the index of array, field-0x9F0 is the size and field-0x9F8 is the content to write. Generally speaking, we can decide what to do and can pass the index and the size to it. So, can we? Let's see the last type request: xnuca_send_request.
```c
__int64 __fastcall xnuca_send_request(__int64 a1, int index, int what_to_do, int size, unsigned int val)
{
  __int64 v5; // rax

  *(_DWORD *)(a1 + 0x9E8) = index;
  *(_DWORD *)(a1 + 0x9EC) = what_to_do;
  *(_DWORD *)(a1 + 0x9F0) = size;
  *(_QWORD *)(a1 + 0x9F8) = val;
  *(_DWORD *)(a1 + 0x9D0) |= 4u;
  v5 = qemu_clock_get_ns(1u);
  return timer_mod(a1 + 2560, v5 + 10);
}
```
The function just initializes the fields we talked about and starts the timer.

Everything is clear? So you can find a UAF bug exists in xnuca_timer easily. Let's exploit it.

## Exploit
There is a challenge called EC3 in defcon quals, and in that case the device don't use the main_arena if you debug it and we can easily exploit that challenge because it saves the heap address(starting at 0x7f or 0x7e... whatever) in bss. But in this case, the device uses the main arena and the heap address is random totally. 

The easiest way to exploit a UAF bug is fastbin attack, and we just overwrite the fd-pointer and allocate mutil times to get the fake pointer. But the prerequisite is that you must find a place which saves the proper size field. You may want to overwrite malloc_hook or other hook functions, but you can not leaking libc's address.

So here comes the biggest challenge you will face: how to find a size field to satisfy the check of fastbin.

Some guys who doesn't see the source code of malloc don't know the secret~ The size you pass to malloc is size_t type, which is a 64-bit data type in 64-bit platform systems, but malloc just use the low 4 bytes for the size to allocate memory~ 
```c
/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```
So it's easy to find the size field for check. In the binary, the got saves many plt's address starting with 0x40, so you can make a fake chunk here. 
```
gef➤  x/6gx 0x11b92a2
0x11b92a2:  0xe6b600007fffe24d  0xae90000000000040
0x11b92b2:  0xe6d600007fffe213  0xe6e6000000000040
0x11b92c2:  0x14f0000000000040  0x934000007fffe219
```

Unlike EC3 challenge, in this time, we can control the order of malloc and we don't need to allocate multi chunks and write content to all the pointers.

All problems have solved, so here is the exploit steps:
1. allocate 1 chunk
2. free the above chunk
3. overwrite the freed chunk's fd pointer
4. allocate 2 chunks to get the fake pointer
5. overwrite free's got as system@plt
6. copy string 'cat ./flag;' to fake chunk
7. free the fake chunk to tigger system

You can see my exploit [here](https://github.com/w0lfzhang/vmescape/blob/master/xnuca/exp.c).