---
title: Splice Syscall Analysis(2)
date: 2017-10-02 01:21:18
tags:
- splice
- socket & pipe
categories:
- kernel_development
---

接下来继续分析另外两种情况。
## do_splice_from
do_splice_from用于从in管道读取数据到out文件描述符对应的文件。
这个函数调用层次太深，不过分析倒是不难。接着看源码~
<!-- more -->
```c
/*
 * Attempt to initiate a splice from pipe to file.
 */
static long do_splice_from(struct pipe_inode_info *pipe, struct file *out,
			   loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *,
				loff_t *, size_t, unsigned int);
	int ret;

	if (unlikely(!(out->f_mode & FMODE_WRITE)))
		return -EBADF;

	if (unlikely(out->f_flags & O_APPEND))
		return -EINVAL;

	ret = rw_verify_area(WRITE, out, ppos, len);
	if (unlikely(ret < 0))
		return ret;

	splice_write = out->f_op->splice_write;
	if (!splice_write)
		splice_write = default_file_splice_write;

	return splice_write(pipe, out, ppos, len, flags);
}
```
函数前面都是相关检查，主要实现在splice_write中。而splice_write直接赋值为out->f_op->splice_write，如果相应的file_operations没有实现splice_write函数，则赋值为default_file_splice_write。
接下来看一种常见的情况：out是相应的socket file。因为其他情况都比较简单。
```c
/*
 *	Socket files have a set of 'special' operations as well as the generic file ones. These don't appear
 *	in the operation structures but are done directly via the socketcall() multiplexor.
 */

static const struct file_operations socket_file_ops = {
	.owner =	THIS_MODULE,
	.llseek =	no_llseek,
	.aio_read =	sock_aio_read,
	.aio_write =	sock_aio_write,
	.poll =		sock_poll,
	.unlocked_ioctl = sock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_sock_ioctl,
#endif
	.mmap =		sock_mmap,
	.open =		sock_no_open,	/* special open code to disallow open via /proc */
	.release =	sock_close,
	.fasync =	sock_fasync,
	.sendpage =	sock_sendpage,
	.splice_write = generic_splice_sendpage,
	.splice_read =	sock_splice_read,
};
```
splice_write由generic_splice_sendpage实现：
```c
/**
 * generic_splice_sendpage - splice data from a pipe to a socket
 * @pipe:	pipe to splice from
 * @out:	socket to write to
 * @ppos:	position in @out
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will send @len bytes from the pipe to a network socket. No data copying
 *    is involved.
 *
 */
ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe, struct file *out,
				loff_t *ppos, size_t len, unsigned int flags)
{
	return splice_from_pipe(pipe, out, ppos, len, flags, pipe_to_sendpage);
}
```
这个函数是个wrapper，接着看splice_from_pipe：
```c
ssize_t splice_from_pipe(struct pipe_inode_info *pipe, struct file *out,
			 loff_t *ppos, size_t len, unsigned int flags,
			 splice_actor *actor)
{
	ssize_t ret;
	struct splice_desc sd = {
		.total_len = len,
		.flags = flags,
		.pos = *ppos,
		.u.file = out,
	};

	pipe_lock(pipe);
	ret = __splice_from_pipe(pipe, &sd, actor);
	pipe_unlock(pipe);

	return ret;
}
```
这么多wrapper.....
```c
/**
 * __splice_from_pipe - splice data from a pipe to given actor
 * @pipe:	pipe to splice from
 * @sd:		information to @actor
 * @actor:	handler that splices the data
 *
 * Description:
 *    This function does little more than loop over the pipe and call
 *    @actor to do the actual moving of a single struct pipe_buffer to
 *    the desired destination. See pipe_to_file, pipe_to_sendpage, or
 *    pipe_to_user.
 *
 */
ssize_t __splice_from_pipe(struct pipe_inode_info *pipe, struct splice_desc *sd,
			   splice_actor *actor)
{
	int ret;

	splice_from_pipe_begin(sd);
	do {
		ret = splice_from_pipe_next(pipe, sd);
		if (ret > 0)
			ret = splice_from_pipe_feed(pipe, sd, actor);
	} while (ret > 0);
	splice_from_pipe_end(pipe, sd);

	return sd->num_spliced ? sd->num_spliced : ret;
}
```
我能怎么办？继续呗...
```c
int splice_from_pipe_feed(struct pipe_inode_info *pipe, struct splice_desc *sd,
			  splice_actor *actor)
{
	......
	ret = actor(pipe, buf, sd);
	.....
}
```
直接看重点算了，由generic_splice_sendpage函数可知actor为pipe_to_sendpage：
```c
/*
 * Send 'sd->len' bytes to socket from 'sd->file' at position 'sd->pos'
 * using sendpage(). Return the number of bytes sent.
 */
static int pipe_to_sendpage(struct pipe_inode_info *pipe,
			    struct pipe_buffer *buf, struct splice_desc *sd)
{
	struct file *file = sd->u.file;
	loff_t pos = sd->pos;
	int ret, more;

	ret = buf->ops->confirm(pipe, buf);
	if (!ret) {
		more = (sd->flags & SPLICE_F_MORE) || sd->len < sd->total_len;

		ret = file->f_op->sendpage(file, buf->page, buf->offset,
					   sd->len, &pos, more);
	}

	return ret;
}
```
由splice_from_pipe函数可知sd->u.file为socket file。接下来又是一波wrapper，我就只分析到socket的sendpage了，往下还有wrapper，但是分析到socket那层就够了。
socket的sendpage由sock_sendpage实现：
```c
static ssize_t sock_sendpage(struct file *file, struct page *page,
			     int offset, size_t size, loff_t *ppos, int more)
{
	struct socket *sock;
	int flags;

	sock = file->private_data;

	flags = !(file->f_flags & O_NONBLOCK) ? 0 : MSG_DONTWAIT;
	if (more)
		flags |= MSG_MORE;

	return kernel_sendpage(sock, page, offset, size, flags);
}
```
进入kernel_sendpage：
```c
int kernel_sendpage(struct socket *sock, struct page *page, int offset,
		    size_t size, int flags)
{
	if (sock->ops->sendpage)
		return sock->ops->sendpage(sock, page, offset, size, flags);

	return sock_no_sendpage(sock, page, offset, size, flags);
}
```
socket的proto_ops一般没实现sendpage函数，那就直接分析sock_no_sendpage：
```c
ssize_t sock_no_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags)
{
	ssize_t res;
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov;
	char *kaddr = kmap(page);
	iov.iov_base = kaddr + offset;
	iov.iov_len = size;
	res = kernel_sendmsg(sock, &msg, &iov, 1, size);
	kunmap(page);
	return res;
}
```
知道sock_no_sendpage会调用kernel_sendmsg就够了，然后kernel_sendmsg无外乎是调用sock_sendmsg，然后sock_sendmsg是调用sock->ops->sendmsg。OK，time to stop！再继续下去就是到struct sock的proto里面去了，最后就到tcp_recvmsg，udp_recvmsg里去了，罢了罢了，分析不下去了！

最后总结下do_splice_from(针对socket情况)：
```c
do_splice_from
    |
    |-->fp->f_op->splice_write
      		||(equal)
      	generic_splice_sendpage
      	    |
      	    |-->splice_from_pipe
      	           |
      	           |-->__splice_from_pipe
      	                   |
      	                   |-->splice_from_pipe_feed
      	                          |
      	                          |-->pipe_to_sendpage
      	                                |
      	                                |-->fp->f_op->sendpage
      	                                      ||
      	                                    sock_sendpage
      	                                      |
      	                                      |-->kernel_sendpage
      	                                            |
      	                                            |-->sock_no_sendpage
      	                                                  |
      	                                                  |-->kernel_sendmsg
```

## do_splice_to
do_splice_to用于从in文件描述符对应的文件读取数据到out管道。
```c
*
 * Attempt to initiate a splice from a file to a pipe.
 */
static long do_splice_to(struct file *in, loff_t *ppos,
			 struct pipe_inode_info *pipe, size_t len,
			 unsigned int flags)
{
	ssize_t (*splice_read)(struct file *, loff_t *,
			       struct pipe_inode_info *, size_t, unsigned int);
	int ret;

	if (unlikely(!(in->f_mode & FMODE_READ)))
		return -EBADF;

	ret = rw_verify_area(READ, in, ppos, len);
	if (unlikely(ret < 0))
		return ret;

	splice_read = in->f_op->splice_read;
	if (!splice_read)
		splice_read = default_file_splice_read;

	return splice_read(in, ppos, pipe, len, flags);
}
```
分析过程同do_splice_from，不再赘述了，心累。

## Links
[Linux Sockets and the Virtual Filesystem](http://isomerica.net/~dpn/socket_vfs.pdf)