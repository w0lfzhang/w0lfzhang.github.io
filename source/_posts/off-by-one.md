---
title: off by one
date: 2016-10-21 13:39:06
tags:
- heap
- exploit
categories:
- heap_exploit
---

最近看了一篇讲off-by-one的文章，觉得那文章总结的还是不错的。所以就在那基础上再根据自己的以前的理解写几个例子来记录一下。

## 利用姿势

off-by-one利用方式有chunk overlapping和unlink两种。

### chunk overlapping

具体来讲，主要通过以下三种方式来overlapping chunks：
1. off-by-one overwrite allocated
2. off-by-one overwrite freed
3. off-by-one null byte
<!-- more -->
上面1跟2两种利用方式都差不多，都是通过extending chunks来达到overlapping chunks。具体就是通过一个溢出的字节来改写size字段。需要注意的是要改写size字段时要保证pre_inuse位为1，不然会触发unlink宏，而chunk A是正在被使用的，其fd，bk等字段会不满足条件从而程序crash。

方法1的具体操作如下：
<img src="http://of38fq57s.bkt.clouddn.com/off-by-one-allocate.PNG">

方法2的具体操作如下：
<img src="http://of38fq57s.bkt.clouddn.com/off-by-one-free.PNG">

方法3是这三种里面最难利用的，感觉也比较实用。这种方法是通过shrink chunks来达到目的的。其具体操作步骤如下：
<img src="http://of38fq57s.bkt.clouddn.com/off-by-one-null-Byte.PNG">
这种方法主要是free操作没有比较当前free的chunk's pre_size字段是否跟前一个chunk's size相等。


### unlink
unlink这种方法跟普通的smallbin's unlink差不多，所以就不做记录了。值得一提的是，以前没怎么注意largebin的unlink，不知道largebin的unlink是否已经修复仅仅是通过assert断言的漏洞。

## 利用举例
为了更好理解些，还是举个简单的例子来说明一下，只针对null-byte，因为其他两个很好理解。

```c
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>

int main(void)
{
    void *A, *B, *C;
    void *B1, *B2;

    A = malloc(0x100);
    B = malloc(0x208);
    C = malloc(0x100);
    printf("A:  %p  B:  %p  C:  %p\n", A, B, C);

    free(B);
    printf("\nfree B over!\n\n");
    ((char *)A)[0x104]='\x00';   //overwriting the last byte of size field to shrink chunk
    printf("overwrite chunk B's size\n");
    B1 = malloc(0x100);
    B2 = malloc(0x80);
    printf("\nB1: %p  B2: %p\n\n", B1, B2);

    free(B1);
    free(C);
    void *D = malloc(0x200);
    printf("D:  %p\n", D);
}
```
执行结果如下：
<img src="http://of38fq57s.bkt.clouddn.com/null-byte-result.PNG">

free(B)时B被加到unsorted bin中，随后连续两次分配从unsorted bin中切除相应大小的chunk。但是chunk C的size字段时始终没update的。所以最后我们可以看到D分配在了原来B的位置，这样我们控制了B2，就能对它进行任意写了。

off-by-one理解起来比较简单，但实际在ctf中利用起来还是很有技巧性的，还是得多做题啊，自己还没做多少这方面题啊，得加油啊。

## 参考链接

[Glibc Adventures: The Forgotten Chunks ](https://www.contextis.com/documents/120/Glibc_Adventures-The_Forgotten_Chunks.pdf)
