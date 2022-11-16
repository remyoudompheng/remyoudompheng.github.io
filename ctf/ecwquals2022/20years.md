---
title: 20 years of uptime
parent: ECW CTF 2022
grand_parent: CTF writeups
---

# 20 years of uptime

Challenge reverse pendant la finale ECW 2022.

On nous fournit un fichier `os.bin`
et on doit le lancer avec `qemu -fda os.bin`

C'est un crackme x86 sans OS (directement dans un MBR).
C'est un peu compliqué à ouvrir dans Ghidra, mais on peut
s'aider de QEMU pour trouver directement la bonne fonction à reverser:

Pour ça on lance en mode gdbserver:
```
$ qemu-system-i386 -s -fda os.bin
```

Et on s'accroche avec gdb:
```
(gdb) set architecture i386
The target architecture is set to "i386".
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
0x0000b5e9 in ?? ()
(gdb) x/8x $sp
0x7ff4: 0x00007c50      0x00007cf4      0x7c2f0246      0x00000000
0x8004: 0x00000000      0x00000000      0x00000000      0x00000000
```

Avec la pile on peut identifier la fonction intéressante avec l'adresse
de retour 0x7cf4:
```
       0000:7ce8 bb ab 7c        MOV        BX,0x7cab
       0000:7ceb 0f b6 0e a9 7c  MOVZX      CX,byte ptr [0x7ca9]
                             LAB_0000_7cf0
       0000:7cf0 b4 00           MOV        AH,0x0
       0000:7cf2 cd 16           INT        0x16
       0000:7cf4 02 06 a8 7c     ADD        AL,byte ptr [0x7ca8]
       0000:7cf8 32 06 cf 7c     XOR        AL,byte ptr [0x7ccf]
       0000:7cfc 3a 07           CMP        AL,byte ptr [BX]
                             LAB_0000_7cfe+1
       0000:7cfe 75 0a           JNZ        LAB_0000_7d0a
       0000:7d00 43              INC        BX
       0000:7d01 49              DEC        CX
       0000:7d02 83 f9 00        CMP        CX,0x0
       0000:7d05 7e 02           JLE        LAB_0000_7d09
       0000:7d07 eb e7           JMP        LAB_0000_7cf0
```

La fonction prend l'entrée clavier (INT 0x16) et compare `(c + *0x7ca8) ^ *0x7ccf` avec la chaîne à l'adresse 0x7cab
de longueur `*0x7ca9`. On peut afficher le contenu avec GDB:
```
(gdb) x/1bd 0x7ca8
0x7ca8: 13
(gdb) x/1bd 0x7ca9
0x7ca9: 36
(gdb) x/1bd 0x7ccf
0x7ccf: 6
(gdb) x/s 0x7cab
0x7cab: "C;FC9tti<tw@E<G8CB<hEFw<FEuDv@@@vEv;\006\035\tW5\030\030\003\036\031\020W\264\002\210", <incomplete sequence \360\265>
```

Avec `strings` on voit que le binaire dit "Use FLAG{md5(password)} to validate the challenge"

La solution:
```python
In [1]: s = b'C;FC9tti<tw@E<G8CB<hEFw<FEuDv@@@vEv;'

In [2]: bytes((c ^ 6) -13 for c in s)
Out[2]: b'80382eeb-ed96-4187-a63d-36f5c999c6c0'

In [3]: from hashlib import md5

In [4]: md5(b"80382eeb-ed96-4187-a63d-36f5c999c6c0").hexdigest()
Out[4]: '0556c6f9afbb5038a7c52e37ec09c993'

FLAG{0556c6f9afbb5038a7c52e37ec09c993}
```


