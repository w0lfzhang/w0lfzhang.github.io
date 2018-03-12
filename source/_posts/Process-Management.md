---
title: Process Management
date: 2017-03-06 00:17:26
tags:
- Linux Kernel
categories:
- kernel_development
---

感觉自己在linux内核方面的知识有所欠缺，所以打算把Linux Kernel Development这本书读一遍，顺便记录一下。
进程这块感觉还是挺重要的，毕竟是基础。以前略微读过windows内核，现在稍微还有点印象，所以读起来还是不难的。

## Process Descriptor and the Task Structure

内核把进程的列表放在叫做任务队列的双向循环链表中，其中的每一项是task_struct（定义在linux/sched.h中）的结构体，也被称作进程描述符，包含着一个进程的所有信息。
<!-- more -->
x86中，有个thread_info结构体存放着进程的task_struct指针，该结构体在内核栈的尾端分配。而thread_info可以通过current_thread_info宏得到，然后就可以得到task_struct指针了。其实就是current宏的实现。
```c
/*
 * how to get the current stack pointer in C
 */
register unsigned long current_stack_pointer asm ("sp");

/*
 * how to get the thread information struct from C
 */
static inline struct thread_info *current_thread_info(void)
{
    return (struct thread_info *)
                (current_stack_pointer & ~(THREAD_SIZE - 1));
}

static __always_inline struct task_struct *get_current(void)
{
    return current_thread_info()->task;
}

#define current get_current()
```
另外，我们可以通过如下方法得到current指针
```c
#define PAGE_SIZE 0x1000
#define PAGE_MASK4k (~(PAGE_SIZE -1))
#define PAGE_MASK8k (~(PAGE_SIZE*2 -1))

/*
* Returns 0 if the stack is invalid, 1 otherwise.
*/

int is_valid_stack(unsigned long test)
{
	if (test > 0xc0000000 && test < 0xff000000) 
	{
		long state = *((unsigned long *)test;

		if (state == 0) [5]
			return 1;

		else
			return 0;
	}

	return 0;
}

/*
* Computes the address of the task_struct from the
* address of the kernel stack. Returns NULL on failure.
*/

void *get_task_struct()
{
	unsigned long stack,ret,curr4k,curr8k;
	int dummy;
	stack = (unsigned long)&dummy; 
	stack4k = stack & PAGE_MASK4K; 
	stack8k = stack & PAGE_MASK8K; 

	#ifdef __x86_64__

		ret = *((unsigned long *)stack8k);

	#else // x86_32

		ret = *((unsigned long*)stack4k);
		if(!is_valid_stack(ret)) 
		{
			ret = *((unsigned long*)stack8k);
			if (!is_valid_stack(ret))
				return NULL;
		}

	#endif

	return (void*)ret;
}
```

## Process Creation

Linux采用fork()和exec()来创建进程。首先fork函数（通过clone系统调用实现）拷贝当前进程创建一个子进程，然后exec函数负责读取可执行文件并将其载入地址空间开始运行。至于fork函数的详细执行过程就没记录了。

## The Linux Implementation of Threads

刚开始看线程这部分有点搞不懂，但是想了一会儿，还是想清了。linux线程不像windows，内核把每个线程当做进程来实现，每个线程都有属于自己的task_struct。

线程和普通进程创建类似，通过clone()函数来创建，根据不同的参数标志来标志需要共享的资源。只不过父子进程要共享地址空间，文件系统资源，文件描述符等资源。需要注意的是fork()函数创建的进程有独立的地址空间，但是线程的创建通过CLONE_VM标志了和父进程共享地址空间，所以说这只能称之为线程，而不是进程。

## Process Termination

线程终结通过exit系统调用实现，该任务大部分主要靠[do_exit()](http://blog.csdn.net/gatieme/article/details/51638706)函数完成。在调用do_exit()后，尽管进程已经不能运行，但是系统还是保留了其进程描述符。前面do_exit()完成的是清理工作，还有task_struct结构需要释放。当父进程获得已终结子进程的信息后，后者通知内核它并不关注那些信息后，子进程的task_struct结构才被释放。

要注意的是如果父进程在子进程之前退出，必须要为子进程找一个新的父进程，否则这些进程会在退出时永远处于僵死状态，白白耗费内存。解决方法是给子进程在当前线程组内找一个线程作为父进程，如果不行，就让init进程作为他们的父进程。
