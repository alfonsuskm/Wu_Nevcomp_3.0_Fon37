# Trace Me If You Can
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
[Back to home](./README.md)
