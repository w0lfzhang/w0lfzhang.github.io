---
title: ioctl in Linux Driver
date: 2017-07-16 21:32:14
tags:
- Linux_Driver
- ioctl
categories:
- kernel_development
---

## Introducing ioctl 
在linux设备驱动中，出了读取和写入设备外，大部分驱动程序还需要另外一种能力，即通过设备驱动程序执行各种类型的硬件控制，比如，用户空间经常会请求设备锁门，弹出介质，报告错误信息，改变波特率等等。这些操作通常通过ioctl方法支持。该方法实现了同名的系统调用。
<!-- more -->
在用户空间，ioctl系统调用原型如下：
```c
int ioctl(int fd, unsigned long cmd, ...)
```
原型中的点并不是数目不定的一串参数，而是一个可选参数。
驱动程序的ioctl方法原型和用户空间的版本存在一些不同：
```c
int (*ioctl)(struct inode *inode, struct file filp,
			 unsigned int cmd, unsigned long arg);
```
从网上找了张图说明应用层和内核之间的ioctl的联系：
<img src="http://of38fq57s.bkt.clouddn.com/ioctl.png">

## How to work
每个设备都有它自己的ioctl的命令码，命令码必须和设备一一对应才能正常且正确的工作。在linux是这么定义命令码(cmd)的：
```
-------------------------------------
| type | number | direction | size  |
-------------------------------------
| 8bit | 8bit   | 2bit      | 14bit |
-------------------------------------
```
type: 幻数。选择一个号码(read Documentation/ioctl/ioctl-nubmer.txt first)，用来区分不同的设备，并在整个驱动程序中使用这个号码。这个字段占8bit(_IOC_TYPEBITS)。
number：序数。也是8bit宽(_IOC_NRBITS)，用来给自己的命令编号。
direction：数据传输方向。占2bit(_IOC_DIRBITS)。如果涉及到传参，该字段可定义数据的传输方向。
```
_IOC_NONE: 值为0，无数据传输。
_IOC_READ: 值为1，从设备驱动读取数据。
_IOC_WRITE: 值为2，往设备驱动写入数据。
_IOC_READ | _IOC_WRITE: 值为3，双向数据传输。
```
size: 数据大小，字段宽度跟体系结构有关。可通过_IOC_SIZEBITS宏查看具体数值。

接下来就是怎么构造命令码了。
_IO(type,nr): 没有参数的命令
_IOR(type,nr,size): 该命令是从驱动读取数据
_IOW(type,nr,size): 该命令是从驱动写入数据
_IOWR(type,nr,size): 双向数据传输
size参数只需要填上参数的类型即可，如int，上面的命令会自动检测类型并赋值为sizeof(int)。
```
#define _IOC(dir,type,nr,size) \
	(((dir)  << _IOC_DIRSHIFT) | \
	 ((type) << _IOC_TYPESHIFT) | \
	 ((nr)   << _IOC_NRSHIFT) | \
	 ((size) << _IOC_SIZESHIFT))

/* used to create numbers */
#define _IO(type,nr)		_IOC(_IOC_NONE,(type),(nr),0)
#define _IOR(type,nr,size)	_IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
```
还有拆分cmd的相关宏操作，如下：
```
/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)		(((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)		(((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)		(((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)		(((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)
```

然后还有个预定义命令，预定义命令是由内核来识别并且实现相应的操作。当这些命令用于我们的设备时，他们会在我们自己的文件操作被调用之前被解码，换句话说，一旦你使用了这些命令，你的驱动程序不会受到这些请求，因为内核已经把它处理掉了。
预定义命令分为三组：
1. 可用于任何文件的命令
2. 只用于普通文件的命令
3. 特定文件系统类型的命令

一些对任何文件都是预定义的命令如下：
FIOCLEX：file ioctl close on exec，对文件设置专用的标志，当调用进程执行一个新程序时，文件描述符将被关闭。
FIONCLEX：file ioctl not close on exec，清除由FIOCLEX设置的标志。
FIOQSIZE：获得一个文件或目录的大小，当用于设备文件时，返回一个ENOTTY错误。

最后是参数的传递。一般有两种方式：整数和指针。注意下指针传递需要验证指针的合法性，否则会导致内核崩溃等问题。驱动程序应该对每一个用到的用户空间的地址做适当的检查，如果是非法地址则应该返回一个错误。相关函数有access_ok, put_user, get_user等。
```c
int access_ok(int type, const void *addr, unsigened long size)
```
该函数用于检测用户空间地址的安全性。
type: 用于指定数据传输的方向，VERIFY_READ表示要读取应用层数据，VERIFY_WRITE表示要往应用层写如数据。如果既读取又写入，那就使用VERIFY_WRITE。
addr: 用户空间的地址
size: 数据的大小
返回值: 成功返回1，失败返回0。


