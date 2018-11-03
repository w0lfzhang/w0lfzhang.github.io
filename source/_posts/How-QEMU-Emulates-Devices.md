---
title: How QEMU Emulates Devices
date: 2018-11-02 17:43:09
tags:
- qemu
- emulate device
categories:
- vmescape
---

It's been a long time since last blog. And recently, I've been focusing on VM escaping. I read lots of papers, brefings and also some writeups. VM escaping is kind of comprehensive challenge, you must be familiar with kernel, equipped with ctf skills and other stuff. I gonna write some simple articles about vm-escape of qemu. After seeing some papers, I found device emulation is the biggest source of vulns. So here today, we talk about how qemu emulates devices, which is really important for the next exploiting.
<!--more-->

## How qemu works
First let us figure out how qemu works. We know qemu is a machine emulator and virtualizer which is meant to run programs for another Linux/BSD target and operating systems for any machine. 
When you emulate your operating system, a qemu process is running. It's clear every qemu process represents a guest. 

```
				Qemu Running Guests
		-----------------------------------
		| ---------  ---------  --------- |       		  
		| |qemu   |  |qemu   |  |qemu   | |	  
		| |guest1 |  |guest2 |  |guest3 | |
		| ---------  ---------  --------- |
		| ------------------------------- |   
		| |    Linux Host Kernel        | |
		| |                             | |
		| ------------------------------- |
		-----------------------------------
```

And then you have to know is qemu's memory layout. The physical memory allocated for the guest is actually a mmapp'ed private region in the virtual address space of QEMU. 

```
                        Guest' processes
                     +--------------------+
Virtual addr space   |                    |
                     +--------------------+
                     |                    |
                     \__   Page Table     \__
                        \                    \
                         |                    |  Guest kernel
                    +----+--------------------+----------------+
Guest's phy. memory |    |                    |                |
                    +----+--------------------+----------------+
                    |                                          |
                    \__                                        \__
                       \                                          \
                        |             QEMU process                 |
                   +----+------------------------------------------+
Virtual addr space |    |                                          |
                   +----+------------------------------------------+
                   |                                               |
                    \__                Page Table                   \__
                       \                                               \
                        |                                               |
                   +----+-----------------------------------------------++
Physical memory    |    |                                               ||
                   +----+-----------------------------------------------++
```

When you exploit a vm-escape vulnerability, you deal with the memory any time and any where. So it's a big part for you to make it. And below is the qemu process's memory maps, we allocated 2G RAM for the guest.
<img src="/images/qemumaps.PNG">

More details you can read the source code of qemu or you can find some introductions about qemu. And next we'll talk about the topic: device emulation.

## Device Emulation
Before we talk about this, there are some points you must be clear, MMIO(Memory-Maped IO) and MPIO(Port-maped IO), bus system and more about kernel. I suggest you read the chapter 6 of the book *Professional Linux Kernel Architecture*. It's better if you are a linux kernel hacker. You should know that PCI bus is the most popular bus in any kind of architecture, and we just consider PCI bus. And the source code below is all from qemu-2.12.1.

<img src="/images/pcibus.png" width="600" height="300">

So everything is done, let's go.

QEMU uses QOM(QEMU Object Module) to to implement almost all the devices emulation. It is involved with a few structures: TypeImpl(qom/object.c), ObjectClass, Object and TypeInfo(include/qom/object.h). The first thing we gonna do is to figure out the relationship among them.
It's kind of like OOP. If you program with c plus plus or other OOP languages, it will be easy to understand. 

TypeInfo describes information about the type including what it inherits from, the instance and class size, and constructor/destructor hooks. We can simply think it includes everything about a type.
```c
struct TypeInfo
{
    const char *name;
    const char *parent;

    size_t instance_size;
    void (*instance_init)(Object *obj);
    void (*instance_post_init)(Object *obj);
    void (*instance_finalize)(Object *obj);

    bool abstract;
    size_t class_size;

    void (*class_init)(ObjectClass *klass, void *data);
    void (*class_base_init)(ObjectClass *klass, void *data);
    void (*class_finalize)(ObjectClass *klass, void *data);
    void *class_data;

    InterfaceInfo *interfaces;
};
```
We use type_register_static(TypeInfo) to register a type. It will allocate and initialize a struct TypeImpl instance with data from the struct TypeInfo. The fields of them is almost the same. And finally, the instance of TypeInfo will be added into the hash table. After all the type_register_static() functions for the QEMU machine's buses, devices, etc have all been executed, qemu will initializes all the ObjectClasses in type_initialize().
```c
static const TypeInfo pci_testdev_info = {
        .name          = TYPE_PCI_TEST_DEV,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(PCITestDevState),
        .class_init    = pci_testdev_class_init,
};

TypeImpl *type_register_static(const TypeInfo *info)
{
    return type_register(info);
}

TypeImpl *type_register(const TypeInfo *info)
{
    assert(info->parent);
    return type_register_internal(info);
}

static TypeImpl *type_register_internal(const TypeInfo *info)
{
    TypeImpl *ti;
    ti = type_new(info);

    type_table_add(ti);
    return ti;
}
```
Every type has an ObjectClass associated with it. ObjectClass derivatives are instantiated dynamically but there is only ever one instance for any given type. It holds a table of function pointers for the virtual methods implemented by this type. 
```c
struct ObjectClass
{
    /*< private >*/
    Type type;  
    GSList *interfaces;

    const char *object_cast_cache[OBJECT_CLASS_CAST_CACHE];
    const char *class_cast_cache[OBJECT_CLASS_CAST_CACHE];

    ObjectUnparent *unparent;

    GHashTable *properties;
};
```
We can define our own classes. Consider the following structures:
```c
/* include/qom/object.h */
typedef struct TypeImpl *Type;
typedef struct ObjectClass ObjectClass;
struct ObjectClass
{
        /*< private >*/
        Type type;       /* points to the current Type's instance */
        ...

/* include/hw/qdev-core.h */
typedef struct DeviceClass {
        /*< private >*/
        ObjectClass parent_class;
        /*< public >*/
        ...

/* include/hw/pci/pci.h */
typedef struct PCIDeviceClass {
        DeviceClass parent_class;
        ...
```
Since the C standard guarantees that the first field of a struct is always at byte 0, this arrangement makes it possible to directly cast a SubClass pointer to a pointer of type  BaseClass. And when initializing a class, its parent classes are initialized first. After the parent class object has initialized, it will be copied into the current class object and any additional storage in the class object is zero filled. The class automatically inherits any virtual function pointers that the parent class has already initialized. Once all of the parent classes have been initialized, TypeInfo::class_init(invoked in type_initialize()) is called to let the class being instantiated provide default initialize for its virtual functions. It's no doubt it's completely like c++.  
```c
static void pci_testdev_class_init(ObjectClass *klass, void *data)
{
        DeviceClass *dc = DEVICE_CLASS(klass);
        PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

        k->init = pci_testdev_init;
        k->exit = pci_testdev_uninit;
        ...
        dc->desc = "PCI Test Device";
        ...
}
```
Now let's see the Object:
```c
struct Object
{
    /*< private >*/
    ObjectClass *class;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};
```
As we can see, the first member of this object is a pointer to a ObjectClass. Why? This allows identification of the real type of the object at run time. And what is Object structure used to do? Type is just a type, not a device! From the TypeInfo structure, two functioni pointers are attracting our attention: instance_init and class_init. class_init is responsible for initializing the Type's ObjectClass instance. instance_init function is mainly to initialize object's own members. So what's the difference between them? The Object's constructor and destructor(in TypeInfo, like ObjectClass) functions only get called if the corresponding PCI device's -device option was specified on the QEMU command line. In other words, you must emulate a device, otherwise qemu just allocates an Object instance, but you can't get it and initialize it.
From the PCI bus picture, we see the relationship among the devices just like the *Tree*, so ike ObjectClass, we can use OOP to make it efficient to program. 
```c
/* include/qom/object.h */
typedef struct Object Object;
struct Object
{
        /*< private >*/
        ObjectClass *class; /* points to the Type's ObjectClass instance */
        ...

/* include/qemu/typedefs.h */
typedef struct DeviceState DeviceState;
typedef struct PCIDevice PCIDevice;

/* include/hw/qdev-core.h */
struct DeviceState {
        /*< private >*/
        Object parent_obj;
        /*< public >*/
        ...

/* include/hw/pci/pci.h */
struct PCIDevice {
        DeviceState qdev;
    	...

struct YourDeviceState{
		PCIDevice pdev;
		...
```
QOM will use instace_size as the size to allocate a Device Object, and then it invokes the instance_init to retrieve the allocated Object instance by the macro OBJECT_CHECK() and initialize it. 
```c
static int pci_testdev_init(PCIDevice *pci_dev)
{
        PCITestDevState *d = PCI_TEST_DEV(pci_dev);
        ...
```

Then the last thing to be done is set up PCI regions. It includes configuration space and the I/O ports and device memory. Just like the physical machine, the kernel accesses the I/O ports or deivce memory via BARs(Base Adress Register). 
<img src="/images/qemudevice.PNG" width="600" height="300"> 

QEMU uses MemoryRegion structure to handle the memory. The structure is kind of complicated... Just see include/exec/memory.h. It contains a MemoryRegionOps which is required for MMIO and PMIO.
It's involved in two functions, first invoking memory_region_init_io() and then calling pci_register_bar(). It's not difficult to use the api functions. The only thing we have to clear is that the I/O and memory regions are carried out either via static declaration of variables or dynamic allocation.
```c
/*static declaration*/
typedef struct IVShmemState {
        /*< private >*/
        PCIDevice parent_obj;
        /*< public >*/
        ...
        uint32_t intrmask;
        uint32_t intrstatus;
        uint32_t doorbell;
        [...]
        }

/*dynamic allocation*/
typedef struct PCITestDevState {
        /*< private >*/
        PCIDevice parent_obj;
        /*< public >*/
        ...
        IOTest *tests;
        ...
} PCITestDevState;

static int pci_testdev_init(PCIDevice *pci_dev)
{
        PCITestDevState *d = PCI_TEST_DEV(pci_dev);
        ...
        d->tests = g_malloc0(IOTEST_MAX * sizeof *d->tests)
```
So first use memory_region_init_io() to initialize the MemoryRegion structure, and finally invoke pci_register_bar() to register BAR information with QEMU.

So far, we've talked about how qemu emulated a device. And [here](https://github.com/rcvalle/blizzardctf2017) is an good example to learn it or you can just read the source code.

## See Your Devices
We can use the command *lspci* to see the details about our devices. 
Fist use *lspci* to see all the pci devices.
```shell
root@ubuntu:/home/ubuntu# lspci
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
```
Then if you want to see more detail about some one device:
```shell
root@ubuntu:/home/ubuntu# lspci -s 00:03.0 -k -vv
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
	Subsystem: Red Hat, Inc Device 1100
	Physical Slot: 3
	Control: I/O+ Mem+ BusMaster- SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx-
	Status: Cap- 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Region 0: Memory at febf1000 (32-bit, non-prefetchable) [size=256]
	Region 1: I/O ports at c050 [size=8]
```
We can see that BAR0 is 32-bit and non-prefetchable. BAR1 corresponds to PMIO Region 0xc050-oxc058.
Last if you want to access the device memory or ports in userland(root), just access the resource files.
```shell
root@ubuntu:/home/ubuntu# ls -la /sys/devices/pci0000\:00/0000\:00\:03.0/
......
-r--r--r--  1 root root 4096 Nov  2 09:18 resource
-rw-------  1 root root  256 Nov  2 09:22 resource0
-rw-------  1 root root    8 Nov  2 09:22 resource1
......
```
The file resource saves the info about resource0 and resource1.
```shell
root@ubuntu:/home/ubuntu# cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
0x00000000febf1000 0x00000000febf10ff 0x0000000000040200
0x000000000000c050 0x000000000000c057 0x0000000000040101
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
......
```
The line indicates start-address, end-address and flags.
Resource0 and resource1 represent the device memory and port I/O. We can use dd command to access I/O and write a simple c program to access device memory, like [pcimem](https://github.com/billfarrow/pcimem).


Talked too much, time to end.

## References
[QEMU Internals: Big picture overview](http://blog.vmsplice.net/2011/03/qemu-internals-big-picture-overview.html)
[VM escape - QEMU Case Study](http://www.phrack.org/papers/vm-escape-qemu-case-study.html)
[Essential QEMU PCI API](http://web.archive.org/web/20151116022950/http://nairobi-embedded.org/001_qemu_pci_device_essentials.html)
[Writing a PCI Device Driver](http://web.archive.org/web/20151115031755/http://nairobi-embedded.org:80/linux_pci_device_driver.html)
[include/qom/object.h](#)
[QEMU Attack Surface and Security Internals](#)
[QEMU中的对象模型——QOM](https://blog.csdn.net/u011364612/article/details/53485856)
