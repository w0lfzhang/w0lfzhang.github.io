---
title: Linux TTY Driver
date: 2017-08-31 01:53:26
tags:
- tty driver
categories:
- kernel_development
---

tty驱动这个东西我理解起来有点困难。但是最近做的kernel exploitation都涉及tty这个东西，所以很有必要把它搞懂。断断续续看了2天，差不多搞懂了~
<!-- more -->
## WTF is tty?
tty(teletype)是各种类型的终端的一种简称，如串行端口终端(/dev/ttySn)，伪终端(dev/pty/)，控制终端(/dev/tty)，控制台终端(/dev/ttyn, /dev/console)等。终端也是一种字符设备，终端模型从上到下可划分为三层：
1. 顶层tty core驱动层提供字符设备接口；
2. 最底层是tty driver层用来和硬件进行通讯，实现tty_operations供tty core和LDISC层调用；
3. 中间层line discipline实现终端输入输出数据处理的策略。
<img src="http://of38fq57s.bkt.clouddn.com/tty_driver_arch.gif">

## Some Structures
有几个结构体在整个框架中都比较重要，还是需要熟悉一下。
任何驱动程序的主要数据结构是[tty_driver](http://elixir.free-electrons.com/linux/latest/source/include/linux/tty_driver.h#L296)，它被用来向tty core注册和注销驱动程序。
```c
/* the source code is based on linux kernel 3.19 */

struct tty_driver {
	int	magic;		/* magic number for this structure */
	struct kref kref;	/* Reference management */
	struct cdev *cdevs;
	struct module	*owner;
	const char	*driver_name;
	const char	*name;
	int	name_base;	/* offset of printed name */
	int	major;		/* major device number */
	int	minor_start;	/* start of minor device number */
	unsigned int	num;	/* number of devices allocated */
	short	type;		/* type of tty driver */
	short	subtype;	/* subtype of tty driver */
	struct ktermios init_termios; /* Initial termios */
	unsigned long	flags;		/* tty driver flags */
	struct proc_dir_entry *proc_entry; /* /proc fs entry */
	struct tty_driver *other; /* only used for the PTY driver */

	/*
	 * Pointer to the tty data structures
	 */
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;

	/*
	 * Driver methods
	 */

	const struct tty_operations *ops;
	struct list_head tty_drivers;
};
```
其实实现驱动程序大部分情况下是填写相应的结构体，最主要的还是相关的函数指针，而在tty driver中我们需要重点关注的是[tty_operations](http://elixir.free-electrons.com/linux/v3.19/source/include/linux/tty_driver.h#L251)这个结构体，其中包含了tty driver的所有的回调函数，由tty driver设置，并被tty core调用。
```c
struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *driver,
			struct inode *inode, int idx);
	int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
	void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
	int  (*open)(struct tty_struct * tty, struct file * filp);
	void (*close)(struct tty_struct * tty, struct file * filp);
	void (*shutdown)(struct tty_struct *tty);
	void (*cleanup)(struct tty_struct *tty);
	int  (*write)(struct tty_struct * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(struct tty_struct *tty, unsigned char ch);
	void (*flush_chars)(struct tty_struct *tty);
	int  (*write_room)(struct tty_struct *tty);
	int  (*chars_in_buffer)(struct tty_struct *tty);
	int  (*ioctl)(struct tty_struct *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(struct tty_struct *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
	void (*throttle)(struct tty_struct * tty);
	void (*unthrottle)(struct tty_struct * tty);
	void (*stop)(struct tty_struct *tty);
	void (*start)(struct tty_struct *tty);
	void (*hangup)(struct tty_struct *tty);
	int (*break_ctl)(struct tty_struct *tty, int state);
	void (*flush_buffer)(struct tty_struct *tty);
	void (*set_ldisc)(struct tty_struct *tty);
	void (*wait_until_sent)(struct tty_struct *tty, int timeout);
	void (*send_xchar)(struct tty_struct *tty, char ch);
	int (*tiocmget)(struct tty_struct *tty);
	int (*tiocmset)(struct tty_struct *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(struct tty_struct *tty, struct winsize *ws);
	int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
	int (*get_icount)(struct tty_struct *tty,
				struct serial_icounter_struct *icount);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
	const struct file_operations *proc_fops;
};
```
还有个结构体我们需要了解以下，[tty-struct](http://elixir.free-electrons.com/linux/v3.19/source/include/linux/tty.h#L237):
```c
struct tty_struct {
	int	magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;

	/* Protects ldisc changes: Lock tty not pty */
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;

	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	spinlock_t ctrl_lock;
	spinlock_t flow_lock;
	/* Termios values are protected by the termios rwsem */
	struct ktermios termios, termios_locked;
	struct termiox *termiox;	/* May be NULL for unsupported */
	char name[64];
	struct pid *pgrp;		/* Protected by ctrl lock */
	struct pid *session;
	unsigned long flags;
	int count;
	struct winsize winsize;		/* winsize_mutex */
	unsigned long stopped:1,	/* flow_lock */
		      flow_stopped:1,
		      unused:BITS_PER_LONG - 2;
	int hw_stopped;
	unsigned long ctrl_status:8,	/* ctrl_lock */
		      packet:1,
		      unused_ctrl:BITS_PER_LONG - 9;
	unsigned int receive_room;	/* Bytes free for queue */
	int flow_change;

	struct tty_struct *link;
	struct fasync_struct *fasync;
	int alt_speed;		/* For magic substitution of 38400 bps */
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	struct list_head tty_files;

#define N_TTY_BUF_SIZE 4096

	int closing;
	unsigned char *write_buf;
	int write_cnt;
	/* If the tty has a pending do_SAK, queue it here - akpm */
	struct work_struct SAK_work;
	struct tty_port *port;
};
```
tty core使用tty_struct保存当前特定的tty端口的状态，除了少数例外，该结构的几乎所有的成员只能被tty core使用。

在介绍如何工作之前，首先把line discipline简单的熟悉一下，虽然这个东西是真的复杂，但是只需了解一下大概原理就行了。
tty core从用户那得到将发往tty设备的数据，然后把数据发送给tty线路规程驱动程序，该驱动程序负责把数据传递给tty driver。从tty硬件那接受的数据将回溯到tty驱动程序，然后流入tty线路规程驱动程序，接着是tty core，最后用户从tty core那里得到数据。tty驱动程序是不能直接与tty discipline通信的，甚至不知道它的存在，tty discipline的作用是使用特殊的方法，把从用户或者硬件那里接受的数据格式化。
再来看一个结构体[tty_ldisc](http://elixir.free-electrons.com/linux/v3.19/source/include/linux/tty_ldisc.h#L221):
```c
struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};

struct tty_ldisc_ops {
	int	magic;
	char	*name;
	int	num;
	int	flags;

	/*
	 * The following routines are called from above.  <== for tty core
	 */
	int	(*open)(struct tty_struct *);
	void	(*close)(struct tty_struct *);
	void	(*flush_buffer)(struct tty_struct *tty);
	ssize_t	(*chars_in_buffer)(struct tty_struct *tty);
	ssize_t	(*read)(struct tty_struct *tty, struct file *file,
			unsigned char __user *buf, size_t nr);
	ssize_t	(*write)(struct tty_struct *tty, struct file *file,
			 const unsigned char *buf, size_t nr);
	int	(*ioctl)(struct tty_struct *tty, struct file *file,
			 unsigned int cmd, unsigned long arg);
	long	(*compat_ioctl)(struct tty_struct *tty, struct file *file,
				unsigned int cmd, unsigned long arg);
	void	(*set_termios)(struct tty_struct *tty, struct ktermios *old);
	unsigned int (*poll)(struct tty_struct *, struct file *,
			     struct poll_table_struct *);
	int	(*hangup)(struct tty_struct *tty);

	/*
	 * The following routines are called from below.  <== for tty driver
	 */
	void	(*receive_buf)(struct tty_struct *, const unsigned char *cp,
			       char *fp, int count);
	void	(*write_wakeup)(struct tty_struct *);
	void	(*dcd_change)(struct tty_struct *, unsigned int);
	void	(*fasync)(struct tty_struct *tty, int on);
	int	(*receive_buf2)(struct tty_struct *, const unsigned char *cp,
				char *fp, int count);

	struct  module *owner;

	int refcount;
};
```
这个结构体主要是line discipline层用的，因为其工作在tty core与tty driver之间，所以它需要为二者提供相应的接口函数。正如结构体中注释描述的那样，可以看到哪些函数提供给哪一层作为接口使用。

## How to work
之前我困惑的原因是搞不懂那几个operations结构体的函数之间的调用关系，例如基本每个结构体都会有open，write等函数指针，实在搞得我有点懵。最后历经千辛万苦，终于看懂了。(能看懂内核源码是一件很幸福的事)
感谢[tty初探—uart驱动框架分析](http://blog.csdn.net/lizuobin2/article/details/51773305)这篇博文的作者！！

首先因为终端是一种字符设备，那我们先从file_operations(内核已经实现大部分该结构体的大部分函数)开始研究。拿[tty_fops](http://elixir.free-electrons.com/linux/v3.19/source/drivers/tty/tty_io.c#L456)做例子说一下，其初始化如下：
```c
static const struct file_operations tty_fops = {
	.llseek		= no_llseek,
	.read		= tty_read,
	.write		= tty_write,
	.poll		= tty_poll,
	.unlocked_ioctl	= tty_ioctl,
	.compat_ioctl	= tty_compat_ioctl,
	.open		= tty_open,
	.release	= tty_release,
	.fasync		= tty_fasync,
};
```
假设我们再用户空间调用了open打开了一个设备节点文件，我们来看下内核函数的调用顺序。
如上，第一应该是调用tty_fops中的tty_open函数，因为打开的是字符设备。tty_open函数会在tty_driver的全局链表中找到相应的tty_driver，然后根据tty_driver分配并初始化一个tty_struct结构体。因为tty core用的是tty_struct结构体，当其要调用tty driver层的相关函数时必须要要从某个地方找到tty_operations，所以tty_struct中有个tty_operations结构体来保存tty_driver实现的回调函数。所以tty_open在初始化tty_struct时会设置tty_struct->ops = tty_driver->ops。有个细节注意一下(when reading source code)，在linux内核源码中tty核心层的实现是tty_io.c，tty discipline一般由n_tty(N_TTY).c实现。
tty_open会调用tty_init_dev函数：
```c
struct tty_struct *tty_init_dev(struct tty_driver *driver, int idx)
{
	......
	/*
	 * Structures all installed ... call the ldisc open routines.
	 * If we fail here just call release_tty to clean up.  No need
	 * to decrement the use counts, as release_tty doesn't care.
	 */
	retval = tty_ldisc_setup(tty, tty->link);
	if (retval)
		goto err_release_tty;
	/* Return the tty locked so that it cannot vanish under the caller */
	return tty;
	......
}
```
然后调用tty_ldisc_setup函数：
```c
int tty_ldisc_setup(struct tty_struct *tty, struct tty_struct *o_tty)
{
	struct tty_ldisc *ld = tty->ldisc;
	int retval;

	retval = tty_ldisc_open(tty, ld);
	if (retval)
		return retval;

	if (o_tty) {
		retval = tty_ldisc_open(o_tty, o_tty->ldisc);
		if (retval) {
			tty_ldisc_close(tty, ld);
			return retval;
		}
	}
	return 0;
}
```
我们再来看tty_ldisc_open函数：
```c
static int tty_ldisc_open(struct tty_struct *tty, struct tty_ldisc *ld)
{
	WARN_ON(test_and_set_bit(TTY_LDISC_OPEN, &tty->flags));
	if (ld->ops->open) {
		int ret;
                /* BTM here locks versus a hangup event */
		ret = ld->ops->open(tty);
		if (ret)
			clear_bit(TTY_LDISC_OPEN, &tty->flags);
		return ret;
	}
	return 0;
}
```
在这个函数里会调用tty discipline的open函数。但是这个函数不会调用tty driver的open函数，看下面代码：
```c
static int tty_open(struct inode *inode, struct file *filp)
{
	tty = tty_init_dev(driver, index);
	......
	if (tty->ops->open)
		retval = tty->ops->open(tty, filp);
	else
		retval = -ENODEV;
	......
```
所以如果tty_operations定义了open函数就会调用，一般是必须要实现open函数。

对于write和read，调用层次更加清晰，如下图：
<img src="http://of38fq57s.bkt.clouddn.com/tty.png">
分析貌似太复杂，懒得分析了，不过最后大概原理算是搞懂了~

还有个重要的点是tty driver的ioctl：
```c
long tty_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tty_struct *tty = file_tty(file);
	struct tty_struct *real_tty;
	void __user *p = (void __user *)arg;
	int retval;
	struct tty_ldisc *ld;

	/* the ioctls kernel implements */
	......
	case TIOCSSERIAL:
		tty_warn_deprecated_flags(p);
		break;
	}
	if (tty->ops->ioctl) {
		retval = tty->ops->ioctl(tty, cmd, arg);
		if (retval != -ENOIOCTLCMD)
			return retval;
	}
	ld = tty_ldisc_ref_wait(tty);
	retval = -EINVAL;
	if (ld->ops->ioctl) {   <=== here
		retval = ld->ops->ioctl(tty, file, cmd, arg);
		if (retval == -ENOIOCTLCMD)
			retval = -ENOTTY;
	}
	tty_ldisc_deref(ld);
	return retval;
}
```
当ioctl在用户态被调用时(对应设备节点是相应tty终端)，tty core将根据cmd命令或者调用内核内置的ioctl，或者调用tty driver的ioctl。

其实理清tty core，tty driver，tty disciline之间的调用关系就差不多基本搞清了tty的原理。总的来说，tty core处理数据时会调用tty driver设置的相应的tty_operations里面的函数，中间数据可能要经过tty discipline被格式化。其实就是系统给封装了一下，tty_driver不要去实现file_operations结构体的函数成员，而是去实现tty_operations的函数成员，用户通过跟tty core直接交互，而tty core可以直接跟tty driver交互，用户间接地通过tty core跟tty driver交互。

## References
Linux设备驱动开发详解：基于最新的Linux 4.0内核——13.3.65：终端设备驱动
[tty初探—uart驱动框架分析](http://blog.csdn.net/lizuobin2/article/details/51773305)
[linux 终端设备 - 线路规程](http://blog.csdn.net/kickxxx/article/details/8512309)
[Linux TTY Driver](https://yannik520.github.io/tty/tty_driver.html#sec-3)


