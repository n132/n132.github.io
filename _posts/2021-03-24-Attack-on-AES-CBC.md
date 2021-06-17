---
title: Attack_on_AES_CBC
date: 2021-03-24 12:04:28
tags:
---

介绍AES-CBC模式下一些攻击方法，使用场景
<!--more-->

# Prelogue

介绍AES-CBC模式下一些攻击方法，使用场景

# What's AES and CBC?

AES 是一种分组密码, 将明文分为等长的块进行加密。CBC 是其中的一种分组模式他的加密/解密流程如下图所示。

![CBC_ENC]("/images/CBC_ENC.png")

![CBC_DEC]("/images/CBC_DEC.png")

其中包含的几个参数分别是：

```
明文 Plaintext
密文 Ciphertext
初始向量 IV
密钥 Key
分组长度 block_size
中间值 Mid_Value = Plaintext ^ IV
```

# IV Deducing on CBC

在面对一个解密服务的时候，我们可以通过构造密文来推算出IV。

试想有这样一个解密服务，接收密文解密后给出明文。

从解密流程图可以看到每一个块分为2步：Block Cipher DEC 和 XOR。

如果我们向服务器发送长度为两个block_siz的密文 C|C,  假设服务器返回了明文 P1 | P2. 

我们将通过以下计算得到 `IV=P1 ^ P2 ^ C`

```
因为：
P1 = dec(C)^ IV
P2 = dec(C)^ C
所以：
P1 ^ P2 = IV ^ C
IV = P1 ^ P2 ^ C
```

# Bit Flipping on CBC

比特翻转攻击，是通过修改密文中的一部分来更改解密后的明文值。

试想有这样一个场景：服务器接收一串密文解密后判断其中的变量admin的值。

```python
from Crypto.Cipher import AES m="hahahahahahahaha=1;admin=0;uid=1" key="1234567890abcdef" iv="fedcba0987654321"
cipher = AES.new(key, AES.MODE_CBC, iv)
c=cipher.encrypt(m)
print c.encode("hex")
#49a98685a527bdfa4077c400963a4e3c 9effb4148566f10bce9e07ccbb731896
```

将上面的数据代入加密流程我们可以发现

![Bit_Flip]("/images/Bit_Flip.png")

所以我们要想admin=1那么要让第一个块的0x77变成`0x76=0x77^0x31^0x30` ，只要做如下修改：

```python
49a98685a527bdfa4077c400963a4e3c9effb4148566f10bce9e07ccbb731896
->
49a98685a527bdfa4076c400963a4e3c9effb4148566f10bce9e07ccbb731896
```

虽然一个块被破坏了但是我们确实修改了重要参数，这在一些web应用中非常管用。

# Padding Oracle Attack on CBC

这个漏洞很有趣，并没有通过算法本身来攻击而是攻击了Padding模式。

当加密时采用了PKCS5的充填模式时，长度不足一个块的数据会被补成一个块且补充的内容为缺少的长度。这里我给出个充填的例子。

```python
def pad(msg):
    byte = 16 - len(msg) % 16
    return msg + chr(byte) * byte

def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]
```

攻击过程分两种情况讨论：

## 服务器会检查Padding

这种情况下服务器会确认解出来的密文最后的内容是否符合Padding模式，如果不符合会让客户端得知（例如直接中断回话）

```
plaintext[-1] <0x10 and plaintext[-1] ≥ 0
for x in range(0x10-ord(plaintext[-1])): plaintext[x] == plaintext[-1]
```

这种情况下可以通过服务器的反应（是否中断）来还原明文，具体步骤如下。

```
已知：单个block的密文C1，与其IV
设C1经过Block Cipher DEC之后为M1，则 M1[-1]^IV[-1]要等于0x1 时服务器才不会中断
遍历0-255这样就可以爆破出当上传的最后一字节的值为Vx没有收到中断，此时Vx^M1[-1]==0x1
由此可知M1[-1] == 0x1 ^Vx
所以Plaintext[-1]==M1[-1]^IV[-1]==0x1 ^ Vx ^ IV[-1]
如上步骤设置 Vy^M1[-2] == 0x2 and Vx'^M1[-1]==0x2 依次推算出所有明文
```

## 服务器不检查Padding

虽然服务器不检查padding但是因为unpad返回的是msg[:-ord(msg[-1])]而最后一个字节可以通过我们的IV来控制

```
def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]
```

这样我们可以通过控制最后一字节来控制服务器端解密后明文的长度：如果设置最后一个字节为0xf那么明文只会有一个长度，而此时我们可以通过爆破这个字节来确定明文，然后控制最后一个字节为0xe，依次爆破出每个字节。

# Related Challenges?

[https://cryptopals.com/sets/2](https://cryptopals.com/sets/2)

[2017 HITCON Secret Server](https://ctftime.org/task/4849)