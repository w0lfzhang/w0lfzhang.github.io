---
title: Cryptography Basis
date: 2017-08-11 23:18:40
tags:
- crypto
- RSA
- AES
categories:
- crypto
---

上个暑假在xman学了点密码学的东西，到现在忘得差不多了...平时没怎么用到，但是觉得密码学这一块还是挺重要的，所以还是认真搞一下。
古典密码学就不说了，主要还是现代密码学。现代密码学按加密原理主要分为对称加密体制和非对称加密体制。
<!-- more -->
## 对称加密
加密/解密密钥相同或者很容易从其中一个推出另一个.
代表算法：DES、AES、RC4、A5. 
一般来说加密类型有分组加密和序列加密。
分组密码：又称块密码， 将明文消息的二进制序列划分成固定大小的块， 每块分别在密钥控制下变换成等长的二进制密文序列。
序列密码：又称流密码，将明文消息的二进制序列逐位加密，产生密文。
<img src="http://of38fq57s.bkt.clouddn.com/crypto.PNG">

分组加密可以配合多种工作模式。主要可概括为如下：
1. 前一个分组的加密结果会影响到下一个分组的加密结果：
如：CBC模式，CFB模式，OFB模式
<img src="http://of38fq57s.bkt.clouddn.com/cbcas.PNG">
2. 前一个分组的加密结果和下一个分组独立：
如：CTR模式，ECB模式
<img src="http://of38fq57s.bkt.clouddn.com/ecbas.PNG">

### AES
AES算法明文分组长度固定为128比特，加密数据块分组长度也为128比特，密钥的长度可以为128、192、256bit。AES。根据使用的密码长度，AES最常见的有3种方案，用以适应不同的场景要求，分别是AES-128、AES-192和AES-256。
AES的大体加密和解密过程如下：
<img src="http://of38fq57s.bkt.clouddn.com/aes-detail.PNG">
加密和解密算法的输入是一个128bit的分组，这个分组被描述为4\*4的方阵，这个方阵会在各个阶段被修改。密钥也被描述为4\*4的矩阵。
AES算法输入的密钥需要被拓展为一个int型的数组w[n]，n由密钥长度决定。在每轮加密中有四个不同的字(128bit)作为该轮的轮密钥。
<img src="http://of38fq57s.bkt.clouddn.com/aes-args.PNG">

由上面的加密流程图可知，AES的加密主要分为四个不同的阶段，包括一个置换和三个代替：
#### 字节代替——SubBytes
该操作是一个简单的查表操作。AES定义了一个S盒(固定值的16*16矩阵)。方阵中的值按如下方式映射为一个新的字节：把该字节的高4位作为行值，低4位作为列值，以行列值为索引从S盒中取出相应的元素作为输出。
<img src="http://of38fq57s.bkt.clouddn.com/aes-subbytes.PNG">
#### 行位移——ShiftRows
矩阵的第一个行保持不变，第二行循环左移一个字节，第三行循环左移两个字节，第四行循环左移三个字节。
<img src="http://of38fq57s.bkt.clouddn.com/aes-shiftrows.PNG">
#### 列混淆——MixColumns
每列中的每个字节被映射为一个新的值，该值由该列中的4个字节通过函数变换得到，变换如下：
<img src="http://of38fq57s.bkt.clouddn.com/aes-mixcolunms.PNG">
#### 轮密钥加——AddRoundKey
这个过程比较简单，直接用矩阵与轮密钥XOR即可。
<img src="http://of38fq57s.bkt.clouddn.com/aes-addroundkey.PNG">

AES的加密过程大体如上，在网上找了份C语言的[源码](https://github.com/dhuertas/AES/blob/master/aes.c)，可以参考一下。
AES是分组加密，也就是说它是对固定大小的分组数据进行处理。不过，大多数要加密的的数据都不是16字节长。为了解决这个问题，所以一般在加密时需要选择合适的模式。所以就有啥AES-ECB，AES-CBC模式等。平时加密解密啥的可以借助openssl，这个开源软件功能还是很强大的。


## 非对称加密
非对称密码其加密和解密使用不同的密钥：一个是公钥，另一个是私钥。非对称密码也称作公钥密码，加密密钥与解密密钥没有直接关系。
一个例子如下：
<img src="http://of38fq57s.bkt.clouddn.com/rsa-exp.PNG">
代表算法：RSA、ElGamal公钥密码体制、椭圆曲线公钥密码体制.

### RSA
算法过程如下：
<img src="http://of38fq57s.bkt.clouddn.com/rsa.PNG">
注：上面的私钥为(d,n)。
≡在数论里是同余的意思。例如：4≡1(mod 3)，即：4和1除以3的余数是相同的。

## Reference
密码编码学与网络安全[William Stallings]

