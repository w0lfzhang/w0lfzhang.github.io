---
title: Starting fuzz with AFL
date: 2017-11-30 17:54:15
tags:
- fuzzing
- AFL
categories:
- fuzzing
---

It's really hard to pwn the switches...So I decide to pick some time to learn fuzzing. 
The first problem is to choose a fuzzing tool. And I think AFL(American fuzzy lop) is a good tool to start fuzzing. The second problem is to choose a target to fuzz. That's easy, there are many programs to choose. And I choose [the GNU project](http://ftp.gnu.org/)'s binutils according to the blog I read. Then start my fist fuzzing.
<!-- more -->
## Install AFL
```
wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -xzvf afl-latest.tgz
cd afl-2.52b/
make
sudo make install
```
Also, we can use afl-clang-fast, which can make it fast to fuzz. 
```shell
cd afl-2.51b/llvm_mode/
sudo apt-get install llvm-dev llvm
make
cd ..
make
sudo make install
```

## Fuzzing with AFL
First download the binutils source code of the GNU project.
```
wget http://ftp.gnu.org/gnu/binutils/binutils-2.25.tar.gz
```
Unzip it and compile it.
```shell
cd ~/binutils-2.25
CC=afl-gcc ./configure (or CC=afl-clang-fast ./configure)
make
```
Once finished, execute the command:
```
# echo core > /proc/sys/kernel/core_pattern
```
Next is to create the input and output directories:
```
cd ~/binutils-2.25
mkdir afl_in afl_out
cp /bin/ps afl_in/
```
And last is to start fuzzing:
```
cd ~/binutils-2.25
afl-fuzz -i afl_in -o afl_out ./binutils/readelf -a @@
```
Fuzzing ran about 1 hour and didn't get any crash!
<img src="http://of38fq57s.bkt.clouddn.com/afl-fuzz-readelf.PNG">

## Links
[Fuzzing With AFL-Fuzz, a Practical Example ( AFL vs Binutils )](https://www.evilsocket.net/2015/04/30/fuzzing-with-afl-fuzz-a-practical-example-afl-vs-binutils/)

