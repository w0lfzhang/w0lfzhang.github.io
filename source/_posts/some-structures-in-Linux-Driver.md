---
title: some structures in Linux Driver
date: 2017-07-17 18:31:57
tags:
- inode
- file_operations
categories:
- kernel_development
---

## file_operations
这个结构体包含了驱动程序的各种操作。这个结构中包含了一组函数指针，这些指针必须指向驱动程序中实现的各种特定操作的函数，对于不支持的操作，该字段可设置为NULL。如果设置为NULL，内核的具体处理行为是各不相同的。该结构的具体定义在linux/fs.h，定义如下：
<!-- more -->
```c
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*aio_read) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
	ssize_t (*aio_write) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
	int (*iterate) (struct file *, struct dir_context *);
	unsigned int (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*aio_fsync) (struct kiocb *, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	int (*show_fdinfo)(struct seq_file *m, struct file *f);
};
```
owner字段是指向拥有该模块的指针。内核使用这个字段以避免在模块的操作正在被使用时卸载该模块，几乎在所有情况下，该字段被初始化为THIS_MODULE。其他字段都是驱动程序实现的各种操作。一般常用的方法有read，write，ioctl，open，release方法等。关于open和release方法的描述：
open()：
这是对设备文件执行的第一个操作。该方法用于应用程序使用文件前打开文件，提供给驱动程序以初始化的能力，为以后的操作准备。主要的操作有：(1)增加驱动程序使用计数器，以避免不正确的卸载驱动程序；(2)在第一次使用驱动程序支持的设备时对设备进行初始化；(3)如有必要则更新f_op指针；(4)分配并填写置于filp->private_data里的数据结构。
release()：
该方法用于不再使用文件时的释放内存、关闭设备等。主要的操作有：(1)减少驱动程序使用计数器；(2)在驱动程序支持的设备使用完毕时对设备进行关闭操作；(3)释放由open()分配的、保存在file->private_data里的所有内容。
open和release的描述摘自此[blog](http://blog.csdn.net/LDan508/article/details/50547713?locationNum=2&fps=1)。

## file
刚开始看的时候以为跟用户空间的FILE有啥关系，实际上是没有任何联系的。file结构代表一个被打开的文件(系统中的每个打开的文件在内核空间都有一个对应的file结构)。它由内核在open时创建，并传递给在该文件上进行操作的所有函数，直到最后的close函数。
```c
struct file {
	/*
	 * fu_list becomes invalid after file_free is called and queued via
	 * fu_rcuhead for RCU freeing
	 */
	union {
		struct list_head	fu_list;
		struct llist_node	fu_llist;
		struct rcu_head 	fu_rcuhead;
	} f_u;
	struct path		f_path;
#define f_dentry	f_path.dentry
	struct inode		*f_inode;	/* cached value */
	const struct file_operations	*f_op;

	/*
	 * Protects f_ep_links, f_flags, f_pos vs i_size in lseek SEEK_CUR.
	 * Must not be taken from IRQ context.
	 */
	spinlock_t		f_lock;
#ifdef CONFIG_SMP
	int			f_sb_list_cpu;
#endif
	atomic_long_t		f_count;
	unsigned int 		f_flags;
	fmode_t			f_mode;
	loff_t			f_pos;
	struct fown_struct	f_owner;
	const struct cred	*f_cred;
	struct file_ra_state	f_ra;

	u64			f_version;
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
	/* needed for tty driver, and maybe others */
	void			*private_data;

#ifdef CONFIG_EPOLL
	/* Used by fs/eventpoll.c to link all the hooks to this file */
	struct list_head	f_ep_links;
	struct list_head	f_tfile_llink;
#endif /* #ifdef CONFIG_EPOLL */
	struct address_space	*f_mapping;
#ifdef CONFIG_DEBUG_WRITECOUNT
	unsigned long f_mnt_write_state;
#endif
};
```
关于一些字段的说明，可以参考这篇[blog](http://blog.sina.com.cn/s/blog_7943319e01018m3w.html)。

## inode
内核使用inode在内部表示文件。对单个文件，可能会有许多个file结构，但是他们都指向单个inode结构。
```c
/*
 * Keep mostly read-only and often accessed (especially for
 * the RCU path lookup and 'stat' data) fields at the beginning
 * of the 'struct inode'
 */
struct inode {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;

#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif

	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;

#ifdef CONFIG_SECURITY
	void			*i_security;
#endif

	/* Stat data, not accessed from path walking */
	unsigned long		i_ino;
	/*
	 * Filesystems may only read i_nlink directly.  They shall use the
	 * following functions for modification:
	 *
	 *    (set|clear|inc|drop)_nlink
	 *    inode_(inc|dec)_link_count
	 */
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t			i_rdev;
	loff_t			i_size;
	struct timespec		i_atime;
	struct timespec		i_mtime;
	struct timespec		i_ctime;
	spinlock_t		i_lock;	/* i_blocks, i_bytes, maybe i_size */
	unsigned short          i_bytes;
	unsigned int		i_blkbits;
	blkcnt_t		i_blocks;

#ifdef __NEED_I_SIZE_ORDERED
	seqcount_t		i_size_seqcount;
#endif

	/* Misc */
	unsigned long		i_state;
	struct mutex		i_mutex;

	unsigned long		dirtied_when;	/* jiffies of first dirtying */

	struct hlist_node	i_hash;
	struct list_head	i_wb_list;	/* backing dev IO list */
	struct list_head	i_lru;		/* inode LRU list */
	struct list_head	i_sb_list;
	union {
		struct hlist_head	i_dentry;
		struct rcu_head		i_rcu;
	};
	u64			i_version;
	atomic_t		i_count;
	atomic_t		i_dio_count;
	atomic_t		i_writecount;
	const struct file_operations	*i_fop;	/* former ->i_op->default_file_ops */
	struct file_lock	*i_flock;
	struct address_space	i_data;
#ifdef CONFIG_QUOTA
	struct dquot		*i_dquot[MAXQUOTAS];
#endif
	struct list_head	i_devices;
	union {
		struct pipe_inode_info	*i_pipe;
		struct block_device	*i_bdev;
		struct cdev		*i_cdev;
	};

	__u32			i_generation;

#ifdef CONFIG_FSNOTIFY
	__u32			i_fsnotify_mask; /* all events this inode cares about */
	struct hlist_head	i_fsnotify_marks;
#endif

#ifdef CONFIG_IMA
	atomic_t		i_readcount; /* struct files open RO */
#endif
	void			*i_private; /* fs or device private pointer */
};
```
inode结构中包含了大量的有关文件的信息。但是只有少许字段对编写驱动程序有用。
dev_t i_dev;
表示设备文件的结点，这个域实际上包含了设备编号。
struct cdev *i_cdev;
struct cdev是字符设备的内核的内部结构。当inode指向一个字符设备文件时，此字段为一个指向struct cdev结构的指针。

最后找了张图来总结一下三个结构体之间的联系：
<img src="http://of38fq57s.bkt.clouddn.com/file-inode-fops.png">
关于那个chrdevs可参考[这里](http://blog.csdn.net/zqixiao_09/article/details/50850004)。
这篇[博客](http://blog.csdn.net/zqixiao_09/article/details/50839042)把设备相关的基础知识总结的很好，其实linux驱动程序的知识大部分还是来源于linux设备分驱动程序那本书，只是博主将其总结的很好，值得看一下。
