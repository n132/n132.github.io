---
title: Cryptoals_S1
date: 2021-03-26 17:03:55
tags:
layout: default
---
Challenges in Cryptopals Set1
<!--more-->
# Prologue

Cryptopals : [https://cryptopals.com/](https://cryptopals.com/)

This set is marked as a "qualifying" and "relatively easy" set. Let's have a try.

# Convert hex to base64

## challenge

The string:

```
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
```

Should produce:

```
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

## solution

```python
import base64
raw='49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
res='SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
print(base64.b64encode(raw.decode("hex"))==res)
```

# Fixed XOR

## challenge

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

```
1c0111001f010100061a024b53535009181c
```

... after hex decoding, and when XOR'd against:

```
686974207468652062756c6c277320657965
```

... should produce:

```
746865206b696420646f6e277420706c6179
```

## solution

```python
raw=  '1c0111001f010100061a024b53535009181c'
x =   '686974207468652062756c6c277320657965'
res = '746865206b696420646f6e277420706c6179'
x   = int("0x"+x,16)
raw = int("0x"+raw,16)
result = raw ^ x
print(hex(result)=="0x"+res+"L")
```

# Single-byte XOR cipher

## challenge

The hex encoded string:

```
1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
```

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

## solution

```python

raw = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
raw = raw.decode("hex")
t="abcdefghijklmnopqrstuvwxyz"
t+=t.upper()
for i in t:
    flag=''
    for _ in raw:
        flag+= chr(ord(_)^ord(i))
    print(flag)
```

# Detect single-character XOR

## challenge

One of the 60-character strings in [this file](https://cryptopals.com/static/challenge-data/4.txt) has been encrypted by single-character XOR.

Find it.

## Solution

```python
data='''
0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032
...
32042f46431d2c44607934ed180c1028136a5f2b26092e3b2c4e2930585a
'''
data=data.strip().split("\n")
for _ in data:
    _ = _.decode("hex")
    for i in range(0,127):
        flag=''
        for j in _:
            cur = chr(ord(j)^i)
            if ord(cur) > 127:   
                flag=''
                break
            else:
                flag+=cur
        if(flag!=''):
            print(flag)
# Now that the party is jumping
```

# Implement repeating-key XOR

## challenge

Here is the opening stanza of an important work of the English language:

```
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
```

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

```
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

## solution

```python
plaintext='''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''
key="ICE"
res=''
aim='0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
for x in range(len(plaintext)):
    res+="%02x"%(ord(plaintext[x])^ord(key[x%len(key)]))
print(res==aim)
```

# **Break repeating-key XOR**

## Challenge

[There's a file here.](https://cryptopals.com/static/challenge-data/6.txt) It's been base64'd after being encrypted with repeating-key XOR.

## Solution

Use Hamming Distance to get the possible key-length.

### Why Hamming Distance doesn't change after XOR

```python
IF:
	Hamming_Distance(A,B)== X 
Then, We can get:
	Bin(ord(A)^ord(B))[2:].count("1") == X
Then:
	Hamming_Distance(A^C,B^C)
=	Bin(ord(A)^ord(B)^ord(C)^ord(C))[2:].count("1")
= Bin(ord(A)^ord(B))[2:].count("1")
= X

```

Get the plaintext by using the solution in single-character XOR.

```python
a='this is a test'
b='wokka wokka!!!'
from pwn import *
import base64
def str_2_bin(a):
    res=''
    for x in a:
        #print(x)
        res+=bin((x))[2:].rjust(8,'0')
    return res
def hamming_dis(a,b):
    bin_a= str_2_bin(a)
    bin_b= str_2_bin(b)
    if(len(bin_a)!=len(bin_b)):
        exit()
    l= len(bin_a)
    res=0
    for x in range(l):
        res+=ord(bin_a[x])^ord(bin_b[x])
    return res
def get_raw():
    f=open("./6.txt")
    data=f.read()
    f.close()
    return data
def cal(str_arry,block_size):
    str_arry=str_arry[:len(str_arry)-(len(str_arry)%block_size)]
    res=0
    t=len(str_arry)//block_size-1
    #print(t)
    if t <= 5:
        return False
    for x in range(5):
        res+=hamming_dis(str_arry[block_size*x:block_size*(x+1)],str_arry[block_size*(x+1):block_size*(x+2)])
    return res/5/block_size
def get_idx(data,idx,m):
    res=""
    for x in range(len(data)):
        if(x%m==idx):
            res+=chr(data[x])
    return res
def do_cal(raw):
    for x in range(2,40):
        print(cal(raw,x),x)
def dec(idx_data):
    groups=[]
    for _ in idx_data:
        res=-1
        max_pos=-1
        for kn in range(256):
            l=len(_)
            pos=0
            for y in _:
                if(chr(ord(y)^kn) in table):
                        pos+=1
            pos=pos/l
            if(pos > max_pos):
                max_pos=pos
                res=kn
        tmp=''
        if(max_pos>0.90):
            for y in _:
                tmp+=chr(ord(y)^res)
            groups.append(tmp)
    if(groups==[]):
        return None
    return groups
if __name__ == '__main__':
    raw= base64.b64decode(get_raw())
    do_cal(raw)
    res=[x for x in range(2,41)]
    table='abcdefghijklmnopqrstuvwxyz'
    table+=table.upper()
    table+="0123456789 '.,"
    for x in res:
        flag=''
        idx_data=[]
        for y in range(x):
            idx_data.append(get_idx(raw,y,x))
        plaintext=dec(idx_data)
        if plaintext == None:
            continue
        for x in range(1,len(plaintext)):
            if(len(plaintext[x])<len(plaintext[0])):
                plaintext[x]=plaintext[x]+'\0'
        for idx in range(len(plaintext[0])):
            for c in plaintext:
                flag+=c[idx]
        print(flag)
```

# AES in ECB mode

## Challenge

The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key:"YELLOW SUBMARINE"

## Solution

```python
from Crypto.Cipher import AES
import base64
def get_data():
    f=open("./7.txt")
    data=f.read()
    data=base64.b64decode(data)
    f.close()
    return data
key=b"YELLOW SUBMARINE"
aes= AES.new(key,AES.MODE_ECB)
data=get_data()
print(aes.decrypt(data))
```

# Detect AES in ECB mode

In my view, this challenge doesn't give the info that there are some same blocks in plaintext

## Challenge

[In this file](https://cryptopals.com/static/challenge-data/8.txt) are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.


## Solution

```python
with open("./8.txt") as fp:
    data=[l.replace("\n",'') for l in fp.readlines()]
import re
for x in data:
    b=re.findall(".{32}",x)
    if(len(b)!=len(set(b))):
        print(x)
```