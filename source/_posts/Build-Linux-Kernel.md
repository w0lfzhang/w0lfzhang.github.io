---
title: Build Linux Kernel
date: 2017-05-12 02:36:59
tags:
- kernel build
categories:
- kernel_exploit
---

为了测验内核stack overflow，决定自己编译内核替换已有的内核。
搞了一天，终于成功编译新内核并安装成功了，美滋滋....还是把过程和遇到的坑记录一下。

## Prepare Kernel Source
```shell
w0lfzhang@w0lfzhang666:~/Desktop$ apt-cache search linux-source
linux-source - Linux kernel source with Ubuntu patches
linux-source-2.6.32 - Linux kernel source for version 2.6.32 with Ubuntu patches

w0lfzhang@w0lfzhang666:~/Desktop$ sudo apt-get install linux-source-2.6.32
or
w0lfzhang@w0lfzhang666:~$ wget https://www.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.21.tar.xz
```
<!-- more -->
## Build Kernel
过程还是不难的，只是时间比较久而已...
1. make mrproper
2. make clean //其实这两个steps不要也没关系
3. make oldconfig。当然也可以make menuconfig，不过在可能需要安装某些包(apt-get install libncurses5-dev)。然后把里面的CONFIG_CC_STACKPROTECTOR=y给注释掉。
4. make bzImage
5. make modules
6. make modules_install
7. make install
8. update-initramfs -k 2.6.32.21 -c。主要针对没有生成initrd.img。需要注意的是在内核较低的版本用以下命令可能会在重新启动出现以下问题。所以还是用这个命令吧。
```shell
//using this causing problem
mkinitramfs -o /boot/initrd.img-linux-3.2.12

//problem
error: You need to load the kernel first
```

接下来就是编辑grub配置文件了。不同版本名字可能不同吧，不过都位于/boot/grub/目录下。我们需要做的是找到以下字段：
```shell
### BEGIN /etc/grub.d/10_linux ###
......
### END /etc/grub.d/10_linux ###
```
把里面的内容复制粘贴到这个字段的前面。以下是我更改后的grub.cfg。
```shell
### BEGIN /etc/grub.d/10_linux ###
menuentry 'Ubuntu, with Linux 2.6.32.21' --class ubuntu --class gnu-linux --class gnu --class os {
	recordfail
	insmod ext2
	set root='(hd0,1)'
	search --no-floppy --fs-uuid --set 89a3d212-dc2a-4150-ada3-2dc7326cf585
	linux	/boot/vmlinuz-2.6.32.21 root=UUID=89a3d212-dc2a-4150-ada3-2dc7326cf585 ro   quiet splash
	initrd	/boot/initrd.img-2.6.32.21
}
menuentry 'Ubuntu, with Linux 2.6.32.21 (recovery mode)' --class ubuntu --class gnu-linux --class gnu --class os {
	recordfail
	insmod ext2
	set root='(hd0,1)'
	search --no-floppy --fs-uuid --set 89a3d212-dc2a-4150-ada3-2dc7326cf585
	echo	'Loading Linux 2.6.32.21 ...'
	linux	/boot/vmlinuz-2.6.32.21 root=UUID=89a3d212-dc2a-4150-ada3-2dc7326cf585 ro single 
	echo	'Loading initial ramdisk ...'
	initrd	/boot/initrd.img-2.6.32.21
}
menuentry 'Ubuntu, with Linux 2.6.32-21-generic' --class ubuntu --class gnu-linux --class gnu --class os {
	recordfail
	insmod ext2
	set root='(hd0,1)'
	search --no-floppy --fs-uuid --set 89a3d212-dc2a-4150-ada3-2dc7326cf585
	linux	/boot/vmlinuz-2.6.32-21-generic root=UUID=89a3d212-dc2a-4150-ada3-2dc7326cf585 ro   quiet splash
	initrd	/boot/initrd.img-2.6.32-21-generic
}
menuentry 'Ubuntu, with Linux 2.6.32-21-generic (recovery mode)' --class ubuntu --class gnu-linux --class gnu --class os {
	recordfail
	insmod ext2
	set root='(hd0,1)'
	search --no-floppy --fs-uuid --set 89a3d212-dc2a-4150-ada3-2dc7326cf585
	echo	'Loading Linux 2.6.32-21-generic ...'
	linux	/boot/vmlinuz-2.6.32-21-generic root=UUID=89a3d212-dc2a-4150-ada3-2dc7326cf585 ro single 
	echo	'Loading initial ramdisk ...'
	initrd	/boot/initrd.img-2.6.32-21-generic
}
### END /etc/grub.d/10_linux ###
```
我们只需要把复制粘贴的linux和initrd后面的改为我们自己编译的内核路径。那啥把2.6.32-21-generic都改为2.6.32.21也没关系。也可以执行update-grub2命令, 不需要手动复制粘贴. 最后再把里面的timeout改为10。
```
if keystatus --shift; then
  set timeout=-1
else
  set timeout=10

in ubuntu16
GRUB_DEFAULT=0
#GRUB_HIDDEN_TIMEOUT=0
GRUB_HIDDEN_TIMEOUT_QUIET=true
GRUB_TIMEOUT=10
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
```

重启时遇到下面这个问题，不知道是什么原因。
```
The disk drive for / is not ready yet or not present
Continue to wait; or Press S to skip or M for manual recovery
```
不过我最后重新编译内核然后就可以了...神奇....

最后重启，美滋滋。
```shell
w0lfzhang@w0lfzhang666:~$ uname -a
Linux w0lfzhang666 2.6.32.21 #1 SMP Fri May 12 12:46:13 CST 2017 i686 GNU/Linux
```

## Reference
[Linux 内核编译（三天吐血经历！)](http://blog.csdn.net/qq_34247099/article/details/50949720)
