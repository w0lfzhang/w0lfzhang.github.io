---
title: Splice Syscall Analysis(1)
date: 2017-10-02 01:20:40
tags:
- splice
- socket & pipe
categories:
- kernel_development
---

最近接触splice系列的系统调用比较多，所以就干脆分析一下其内核源码。
首先看下splice干啥用的：
splice() moves data between two file descriptors without copying between kernel address space and user address space. It transfers up to len bytes of data from the file descriptor fd_in to the file descriptor fd_out, where one of the descriptors must refer to a pipe.
<!-- more -->
在两个文件间传输数据的话可以用splice系统调用：
```c
int pipefd[2];
pipe(pipefd);
fd1 = open(...);
fd2 = open(...);
splice(fd1, NULL, pipefd[1], NULL, 1024, SPLICE_F_MORE);
splice(pipefd[0], NULL, fd2, NULL, 1024, SPLICE_F_MORE);
```
官方说是啥高效的零拷贝，暂且不管这个，直接看源码吧。(all source code based on kernel 2.6.32.21)

## splice syscall
```c
SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	long error;
	struct file *in, *out;
	int fput_in, fput_out;

	if (unlikely(!len))
		return 0;

	error = -EBADF;
	in = fget_light(fd_in, &fput_in);
	if (in) {
		if (in->f_mode & FMODE_READ) {
			out = fget_light(fd_out, &fput_out);
			if (out) {
				if (out->f_mode & FMODE_WRITE)
					error = do_splice(in, off_in,
							  out, off_out,
							  len, flags);
				fput_light(out, fput_out);
			}
		}

		fput_light(in, fput_in);
	}

	return error;
}
```
splice的简要流程：
```c
splice
   |--->fget_light: get file pointer by fd
   |--->do_splice: main jobs
   |--->fput_light: do releasing jobs
```
splice的主要工作还是要由do_splice函数完成，接着跟进do_splice:
```c
/*
 * Determine where to splice to/from.
 */
static long do_splice(struct file *in, loff_t __user *off_in,
		      struct file *out, loff_t __user *off_out,
		      size_t len, unsigned int flags)
{
	struct pipe_inode_info *ipipe;
	struct pipe_inode_info *opipe;
	loff_t offset, *off;
	long ret;

	ipipe = pipe_info(in->f_path.dentry->d_inode);
	opipe = pipe_info(out->f_path.dentry->d_inode);

	if (ipipe && opipe) {
		if (off_in || off_out)
			return -ESPIPE;

		if (!(in->f_mode & FMODE_READ))
			return -EBADF;

		if (!(out->f_mode & FMODE_WRITE))
			return -EBADF;

		/* Splicing to self would be fun, but... */
		if (ipipe == opipe)
			return -EINVAL;

		return splice_pipe_to_pipe(ipipe, opipe, len, flags);
	}

	if (ipipe) {
		if (off_in)
			return -ESPIPE;
		if (off_out) {
			if (out->f_op->llseek == no_llseek)
				return -EINVAL;
			if (copy_from_user(&offset, off_out, sizeof(loff_t)))
				return -EFAULT;
			off = &offset;
		} else
			off = &out->f_pos;

		ret = do_splice_from(ipipe, out, off, len, flags);

		if (off_out && copy_to_user(off_out, off, sizeof(loff_t)))
			ret = -EFAULT;

		return ret;
	}

	if (opipe) {
		if (off_out)
			return -ESPIPE;
		if (off_in) {
			if (in->f_op->llseek == no_llseek)
				return -EINVAL;
			if (copy_from_user(&offset, off_in, sizeof(loff_t)))
				return -EFAULT;
			off = &offset;
		} else
			off = &in->f_pos;

		ret = do_splice_to(in, off, opipe, len, flags);

		if (off_in && copy_to_user(off_in, off, sizeof(loff_t)))
			ret = -EFAULT;

		return ret;
	}

	return -EINVAL;
}
```
根据源码总结下流程：
```c
                        do_splice
                            |
                            |
    -----------------------------------------------
    |                       |                     |  
    |two pipes              |in is pipe           |out is pipe
    |                       |                     |
splice_pipe_to_pipe    do_splice_from         do_splice_to
```

### splice_pipe_to_pipe
首先分析下两端都是管道的情况：
```c
static int splice_pipe_to_pipe(struct pipe_inode_info *ipipe,
			       struct pipe_inode_info *opipe,
			       size_t len, unsigned int flags)
{
	struct pipe_buffer *ibuf, *obuf;
	int ret = 0, nbuf;
	bool input_wakeup = false;


retry:
	ret = ipipe_prep(ipipe, flags);
	if (ret)
		return ret;

	ret = opipe_prep(opipe, flags);
	if (ret)
		return ret;

	/*
	 * Potential ABBA deadlock, work around it by ordering lock
	 * grabbing by pipe info address. Otherwise two different processes
	 * could deadlock (one doing tee from A -> B, the other from B -> A).
	 */
	pipe_double_lock(ipipe, opipe);

	do {
		if (!opipe->readers) {
			send_sig(SIGPIPE, current, 0);
			if (!ret)
				ret = -EPIPE;
			break;
		}

		if (!ipipe->nrbufs && !ipipe->writers)
			break;

		/*
		 * Cannot make any progress, because either the input
		 * pipe is empty or the output pipe is full.
		 */
		if (!ipipe->nrbufs || opipe->nrbufs >= PIPE_BUFFERS) {
			/* Already processed some buffers, break */
			if (ret)
				break;

			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			/*
			 * We raced with another reader/writer and haven't
			 * managed to process any buffers.  A zero return
			 * value means EOF, so retry instead.
			 */
			pipe_unlock(ipipe);
			pipe_unlock(opipe);
			goto retry;
		}

		ibuf = ipipe->bufs + ipipe->curbuf;
		nbuf = (opipe->curbuf + opipe->nrbufs) % PIPE_BUFFERS;
		obuf = opipe->bufs + nbuf;

		if (len >= ibuf->len) {
			/*
			 * Simply move the whole buffer from ipipe to opipe
			 */
			*obuf = *ibuf;
			ibuf->ops = NULL;
			opipe->nrbufs++;
			ipipe->curbuf = (ipipe->curbuf + 1) % PIPE_BUFFERS;
			ipipe->nrbufs--;
			input_wakeup = true;
		} else {
			/*
			 * Get a reference to this pipe buffer,
			 * so we can copy the contents over.
			 */
			ibuf->ops->get(ipipe, ibuf);
			*obuf = *ibuf;

			/*
			 * Don't inherit the gift flag, we need to
			 * prevent multiple steals of this page.
			 */
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;

			obuf->len = len;
			opipe->nrbufs++;
			ibuf->offset += obuf->len;
			ibuf->len -= obuf->len;
		}
		ret += obuf->len;
		len -= obuf->len;
	} while (len);

	pipe_unlock(ipipe);
	pipe_unlock(opipe);

	/*
	 * If we put data in the output pipe, wakeup any potential readers.
	 */
	if (ret > 0) {
		smp_mb();
		if (waitqueue_active(&opipe->wait))
			wake_up_interruptible(&opipe->wait);
		kill_fasync(&opipe->fasync_readers, SIGIO, POLL_IN);
	}
	if (input_wakeup)
		wakeup_pipe_writers(ipipe);

	return ret;
}
```
看懂这个函数需要了解一下内核管道的工作原理，具体可参考深入理解linux内核（第三版）的进程通信这章。
首先调用了ipipe_prep和opipe_prep，这两个函数的作用如下：
```
ipipe_prep:
/*
 * Make sure there's data to read. Wait for input if we can, otherwise
 * return an appropriate error.
 */
opipe_prep:
 /*
 * Make sure there's writeable room. Wait for room if we can, otherwise
 * return an appropriate error.
 */
```
pipe_double_lock函数用于避免多个进程对管道的同时访问造成的条件竞争。
while循环把ipipe管道的数据送到opipe管道：
1. 如果opipe没有读进程，发送SIGPIPE信号，退出循环。
2. 如果ipipe的读缓冲区数为0或者opipe的写缓冲区数已满，pipe_unlock ipipe和opipe，退出循环。
3. 从ipipe读取数据到opipe。
大致总结下函数流程：
```c
splice_pipe_to_pipe
        |--->ipipe_prep
        |--->opipe_prep
        |--->pipe_double_lock
        |--->while loop to move data from ipipe to opipe
        |--->pipe_unlock
        |--->wake up potential readers
```
一次写完有点冗长，所以就分两次写了。