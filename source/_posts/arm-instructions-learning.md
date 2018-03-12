---
title: arm instructions learning
date: 2016-11-02 11:48:54
tags:
- arm
- assemble
categories:
- arm
---

Recnetly, I want to learn the pwn of arm, so I find some docs to read.

## Register
below are the points about the register:
1. 37 registers, but most using 16 registers each time(not including status register)
2. R0-7 for everything
3. R8-12 are general registers and when changing to FIQ model, use their shadow register
4. R13 for stack pointer, but it's optional
5. R14 for keeping the return address specially
6. R15 for PC pointer
<!-- more -->
OK, here is the picture:
<img src="http://of38fq57s.bkt.clouddn.com/ArmRegister.PNG">

## Instruction
basic format instruction(assemble syntax):
```
<opcode> {condition(4 bits)} {S} <Rd>, <Rn> {, operand2}
```
inside <> is necessary, inside {} is optional.

1. Data access
including storing and loading instruction, (note: word --> 4 bytes) egg:
```
ldr R0,[R1]   R0<--[R1]
str R0,[R1]   R0-->[R1]
```
2. Data processing
```
mov R0,R1  R0<--R1
```
3. Branch instruction:
```
B target --> jump to target
BL target --> the next instruction's address is saved to R14
BX Rm  --> jump to R, and changing model according to the least bit
```
4. Coprocessor instruction
5. Misc instruction
```
mrs R1,CPSR   R1<--CPSR
```
6. Fake instruction

## Stack Operation
1. grows down and grows up in memory
2. The value of the stack pointer can either:
• Point to the last occupied address (Full stack)
– and so needs pre-decrementing (ie before the push)
• Point to the next occupied address (Empty stack)
– and so needs post-decrementing (ie after the push)
3. The stack type to be used is given by the postfix to the instruction:
• STMFD / LDMFD : Full Descending stack
• STMFA / LDMFA : Full Ascending stack
• STMED / LDMED : Empty Descending stack
• STMEA / LDMEA : Empty Ascending stack
Note: ARM Compiler will always use a Full descending stack

## Addressing modes
1. Immediate
```
add R0,R0,#1
```
2. Register direct
```
add R0,R1,R2
```
3. Register indirect
```
ldr R1,[R2]
```
4. Base address with index
```
ldr R0,[R1,#4]   R0<--[R1+4]
ldr R0,[R1],#4   R0<--[R1], R1<--R1+4
```
5. Register with shifting
```
mov R0,R2,LSL #3  R0<--R2 LSL 3
```
6. Multiple registers
```
ldmia R0,{R1,R2,R3,R4}   R1<--[R0] R2<--[R0+4] R3<--[R0+8] R4<--[R0+12]
```

## Procedure
1. Argument: when less than 4 args, using R0-R3, when over 4, the rest using stack
2. Using BL to call the procedure
3. Saving R14 and when call ending, moving r14 to R15
4. Using R0 to save the return value

## APCS
OK, about APCS, I just find a blog page and pdf to read, hers is the link:
[APCS](http://infocenter.arm.com/help/topic/com.arm.doc.ihi0042f/IHI0042F_aapcs.pdf)
[bolg](http://blog.csdn.net/skyflying2012/article/details/37510171)


