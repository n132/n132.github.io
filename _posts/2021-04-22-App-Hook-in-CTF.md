---
title: App_Hook_in_CTF
date: 2021-04-22 23:27:21
tags:
---
通过一个简单的实例来熟悉使用Frida/objection做hook。
<!--more-->
# Prologue

最近在学习Frida，然后其中的一个demo是一个TCTF的题目，我开始用了逆向的方式一点点弄出来然后抱着学习Frida的目的hook了一遍做出来。以下是两个方法的过程，可以作为熟悉hook的练习材料。

# Challenge

题目的附件可以在Xctf-攻防世界-练习-Mobile-app3处下载，我在[此处][1]做了备份提供下载。下载之后得到了一个以 `.ab` 为后缀的文件，file以下可以得知是一个`Android Backup`文件，谷歌以下发现可以用这个[工具][2]提取，提取之后得到两个数据库文件一个apk文件，接下来就可以开始逆向了。

# Solution

直接逆向，一共只有4个类：a,b,AnotherActivity,MainActivity。

先看MainActivity，其中a连接了一个数据库，其中的click将输入的账号密码存入数据库。

a方法中的`getWritableDatabase`的参数就是数据库的密码。

```python
String a2 = aVar.a(contentValues.getAsString("name"), contentValues.getAsString("password"));
aVar.a(a2 + aVar.b(a2, contentValues.getAsString("password"))).substring(0, 7)
```

所以我们要做的是弄清楚这个密码然后看看数据库内容。

aVar 是一个a的实例，先看看a类的两个方法`a.a`&`a.b`，还是比较短/简单的，其中还涉及到了类b。

先看类b，可以看出两个方法分别返回参数的md5和sha-1。

```python
public class b {
    public static final String a(String str) {
        char[] cArr = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            byte[] bytes = str.getBytes();
            MessageDigest instance = MessageDigest.getInstance("MD5");
            instance.update(bytes);
            byte[] digest = instance.digest();
            int length = digest.length;
            char[] cArr2 = new char[(length * 2)];
            int i = 0;
            for (byte b : digest) {
                int i2 = i + 1;
                cArr2[i] = cArr[(b >>> 4) & 15];
                i = i2 + 1;
                cArr2[i2] = cArr[b & 15];
            }
            return new String(cArr2);
        } catch (Exception e) {
            return null;
        }
    }

    public static final String b(String str) {
        char[] cArr = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        try {
            byte[] bytes = str.getBytes();
            MessageDigest instance = MessageDigest.getInstance("SHA-1");
            instance.update(bytes);
            byte[] digest = instance.digest();
            int length = digest.length;
            char[] cArr2 = new char[(length * 2)];
            int i = 0;
            for (byte b : digest) {
                int i2 = i + 1;
                cArr2[i] = cArr[(b >>> 4) & 15];
                i = i2 + 1;
                cArr2[i2] = cArr[b & 15];
            }
            return new String(cArr2);
        } catch (Exception e) {
            return null;
        }
    }
}
```

然后在看类a的方法

```python
a.a(S1,S2):
	return S1[:4]+S2[:4]
a.a(S1):
	return b.b(S1+"yaphetshan")#SHA-1(S1+"yaphetshan")
a.b(S1):
	return b.a(S1)#MD5(S1)
```

所以我们可以一步步得到数据库密码

先算a2

```python
String a2 = aVar.a(contentValues.getAsString("name"), contentValues.getAsString("password"));
-> Stranger[:4]+123456[:4]
->"Stra1234"
```

再算密码

```python
aVar.a(a2 + aVar.b(a2, contentValues.getAsString("password"))).substring(0, 7)
->aVar.a(a2 + aVar.b(a2, "123456")).substring(0, 7)
->aVar.a("Stra1234" + MD5("Stra1234")).substring(0, 7)
->SHA-1("Stra1234" + MD5("Stra1234")+"yaphetshan")[:7]
->SHA-1("Stra1234"+"44e2e4457d4e252ca5b9fe9d20b3fea5"+"yaphetshan")[:7]
->"ae56f99638285eb0743d8bf76d2b0c80e5cbb096"[:7]
->"ae56f99"
```

然后就可以得到一串看似base编码过的数据解码得到`Tctf{H3ll0_Do_Y0u_Lov3_Tenc3nt!}`

# Another Solution

既然我们知道`getWritableDatabase`的参数就是密码我们可以直接hook这个函数，打印参数就行。

用的是Frida，右键找方法的declaration，发现是类`net.sqlcipher.database.SQLiteOpenHelper`下的.

打开objection`objection -d -g com.example.yaphetshan.tencentwelcome explore`搜一下有没有`getWritableDatabase`这个方法

```python
...mple.yaphetshan.tencentwelcome on (samsung: 7.1.2) [usb] # android hooking list class_methods net.sqlcipher.database.SQLiteOpenH
elper
public abstract void net.sqlcipher.database.SQLiteOpenHelper.onCreate(net.sqlcipher.database.SQLiteDatabase)
public abstract void net.sqlcipher.database.SQLiteOpenHelper.onUpgrade(net.sqlcipher.database.SQLiteDatabase,int,int)
public synchronized net.sqlcipher.database.SQLiteDatabase net.sqlcipher.database.SQLiteOpenHelper.getReadableDatabase(char[])
public synchronized net.sqlcipher.database.SQLiteDatabase net.sqlcipher.database.SQLiteOpenHelper.getReadableDatabase(java.lang.String)
public synchronized net.sqlcipher.database.SQLiteDatabase net.sqlcipher.database.SQLiteOpenHelper.getWritableDatabase(char[])
public synchronized net.sqlcipher.database.SQLiteDatabase net.sqlcipher.database.SQLiteOpenHelper.getWritableDatabase(java.lang.String)
public synchronized void net.sqlcipher.database.SQLiteOpenHelper.close()
public void net.sqlcipher.database.SQLiteOpenHelper.onOpen(net.sqlcipher.database.SQLiteDatabase)

Found 8 method(s)
```

用hooking watch给hook上

```python
android hooking watch class_method net.sqlcipher.database.SQLiteOpenHelper.getWritableDatabase --dump-args
```

之后重进程序就可以得到数据库密码`ae56f99`

```python
(agent) [242721] Arguments net.sqlcipher.database.SQLiteOpenHelper.getWritableDatabase(ae56f99)
- [incoming message] ------------------
{
  "payload": "\u001b[90m[242721] \u001b[39mCalled \u001b[32mnet.sqlcipher.database.SQLiteOpenHelper\u001b[39m.\u001b[92mgetWritableDatabase\u001b[39m(\u001b[31m[C\u001b[39m)",
  "type": "send"
}
```

在`eternalsakura13`的博客上发现了一个trick不用重进程序：

通过`android heap search instances com.example.yaphetshan.tencentwelcome.MainActivity`得到内存中实例

```python
Hashcode  Class                                               toString()
----------  --------------------------------------------------  ----------------------------------------------------------
 234706883  com.example.yaphetshan.tencentwelcome.MainActivity  com.example.yaphetshan.tencentwelcome.MainActivity@dfd57c3
```

然后`android heap execute 234706883 a`调用a方法，a方法就会调用`getWritableDatabase`从而触发hook。

# Epilogue

通过一个实例练习了Frida/objection的使用，思路清晰的话还是很方便的：目的是找密码，hook对的函数触发hook就可以得到密码。

# Ref:

[1] [https://www.52pojie.cn/forum.php?mod=viewthread&tid=1082706](https://www.52pojie.cn/forum.php?mod=viewthread&tid=1082706)

[2] [https://eternalsakura13.com/2020/07/04/frida/](https://eternalsakura13.com/2020/07/04/frida/)

[1]: [https://github.com/n132/Watermalon/blob/master/XCTF/Mobile/app3.ab](https://github.com/n132/Watermalon/blob/master/XCTF/Mobile/app3.ab)

[2]: [https://github.com/nelenkov/android-backup-extractor](https://github.com/nelenkov/android-backup-extractor)