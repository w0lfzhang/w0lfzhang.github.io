---
title: 2016 ASIS CTF car-market
date: 2017-03-10 08:31:57
tags:
- off-by-one
- use-after-free
- ctf
categories:
- ctf_practice
---

## Challenge
好吧，程序是比较简单的，把程序分析完了，基本涉及两个数据结构：
```c
struct car
{
    char model[16];
    long price;
    struct customer* customer;
};
struct customer
{
    char first_name[32];
    char name[32];
    char* comment; // buffer size: 0x48
};
```
<!-- more -->
然后有一个car指针数组用来存储分配的car的堆块的地址。
分析完后就一脸蒙蔽了，不知道怎么做，无奈只好谷歌，找了一篇wp看了一下，利用思路有点难想到。不会没关系，做的题多了，自然就会了。顺便记录一下积累经验。

## Exploit
我就简单把利用过程记录下就行了，因为明天还得比赛，懒得写exp了，因为不出意外等下又得调好一小会。

这是一道关于off-by-one漏洞类型的题，利用思路就是围绕null byte来进行的。

### Way 1

好吧，首先得leak heap的地址，因为后面的利用会用到堆得地址。这部分很简单，先add customer，然后要add comment，然后又add customer，这样comment和customer堆块会先后被free，link到同一fastbin中。这样在customer的firstname字段会存有comment堆块的地址，然后只要输出firstname就可以得到堆得地址了。

然后就是利用null byte来做文章了，方法十分巧妙。(看了两篇wp，利用null byte各不相同，但还是有异曲同工之妙的)。我就随便挑了一种方法记录一下。
先让comment堆块跨越一个以0字节结尾的地址，然后在comment堆块里伪造一个size为0x30的chunk。触发customer的null byte off-by-one漏洞，使得comment指针的最后一个字节为\x00，让它指向在comment里伪造的chunk，然后释放comment堆块。
这样下一次在add car时，会分配这个伪造的chunk，事先在这个伪造的chunk里吧customer指针指向car指针数组。然后add customer，heap头部的car指针数组会被free掉一部分(0x50)成为新的customer堆块，这时候customer堆块里面存储的都是car指针。这时候set firstname就可以overwrite car指针了，这样把car指针改为某个函数的got地址，然后通过编辑修改got地址，最后就能hijack这个函数的流程了。

我觉得这种方法的伪造chunk部分很难搞，又要comment跨越一个以0字节结尾的地址，然后还得在其尾部构造指针，大小很难满足。


### Way 2

好吧，还看了一种也差不多的方法顺便也记一下。

leak heap的地址跟上面的一样。
然后就是leak libc的地址了。个人觉得这个方法比较好。
假设有个customer的comment指针的值为0x12345680，通过off-by-one漏洞触发后变成了0x12345600。当free这个堆块的时候不是释放真正的堆块。这时候如果有个car的memory layout如下：
```c
                      +------------------+
    car    0x123455F0 |               0x0| char model[16]
                      +------------------+
                      |              0x51|
                      +------------------+
    car+16 0x12345600 |              0x64| long price
                      +------------------+
    car+24 0x12345608 |        0x12348880| struct customer* customer
                      +------------------+
```
我们可以在model字段伪造一个fake chunk header，使它的size字段为0x50。这样当free comment(0x12345600)这个堆块时，就会把它link到大小为0x50的fastbin中。这样就造成了use-after-free了，0x12345600为dangling pointer。然后在增加comment的时候，程序会malloc返回0x12345600。此时comment将会和car重叠，这样我们编辑comment就在编辑car了。
我们可以将car的customer指针改为某个函数的got表的地址，然后就能leak libc的地址了。
然后再把这个car的customer指针改为ptr，当free这个customer时，会把ptr释放(0x50)。然后新增comment时，glibc会把这部分ptr数组的部分分配给用户。然后我们就能控制一部分car指针的。然后将car指针改为某个函数的got地址，最后overwrite这个got地址达到hijack程序的流程。

## Links
[ASIS CTF Finals 2016 car market 177](https://bamboofox.github.io/2016/09/14/ASIS-CTF-Finals-2016-car-market-177/)
[Asis CTF 2016 - Car Market Writeup](http://brieflyx.me/2016/ctf-writeups/asis-ctf-2016-carmarket/)
