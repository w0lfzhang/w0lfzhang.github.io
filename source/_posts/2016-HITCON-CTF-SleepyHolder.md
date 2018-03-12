---
title: 2016 HITCON CTF SleepyHolder
date: 2017-04-07 08:20:28
tags:
- malloc_consolidate
- unlink
categories:
- ctf_practice
---

这题是secert-holder的增强版：程序开头分配随机大小的堆块，然后是huge chunk分配后就锁定了，无法wipe和renew。所以难度增大了不少。

## Vulnerability
程序的漏洞还是wipe函数，指针没清零，很容易造成double free或use after free之类的漏洞。  
<!-- more -->
## Exploit
看了一下提醒：malloc consolidate。malloc的时候会有合并？查看malloc.c源代码中的\_int_malloc函数可以发现确实有合并。
```c
 /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
  */

  else {
    idx = largebin_index(nb);
    if (have_fastchunks(av))
      malloc_consolidate(av);
  }
```
```c
When there is a large request(largebin size is enough) of malloc, it will do consolidating
first in order to prevent fragmentation problem. Every fastbin is moved the unsortbin,
consolidates if possible, and finally goes to smallbin.
```
上面摘自https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder。
好吧，知道了这个秘密接下来就是exploit了。其实这个题真的挺难得，不稍微看一下wp真的做不出来。
下面是exploit steps：
1. keep small secret
2. keep big secret
3. wipe small secret
4. keep huge secret--now the fastbin chunk is in smallbin。
5. wipe small secret--it can bypass the double free checking becuase freeing fastbin chunk just checks the fasttop(the first chunk in fastbin) and  the fastbin is empty。After the operating, the chunk was linked into fastbin.
6. keep small secret--to make fake chunk to unlink。

如果没有step 5是不会成功的。因为此时那个small secret chunk在samllbin中，而直接分配smallbin中的chunk的话，相邻的chunk的inuse位会置1，这样后面的unlink会失败。而step 5是把这个chunk加入到了fastbin中，分配fastbin中的chunk不会改变inuse位。

unlink后就各自发挥了。可以把三个指针改为函数got表地址，后面标志位也相应置1。然后泄露libc的地址，可以把free_got改为printf_plt或put_plt。然后按照老套路把atoi_got改为system的地址。然后就没然后了。。。。

脚本可参考https://github.com/mehQQ/public_writeup/blob/master/hitcon2016/SleepyHolder/exp.py


