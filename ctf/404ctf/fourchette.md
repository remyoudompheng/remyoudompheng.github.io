---
title: Reverse — Fourchette
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

# Fourchette

```
On a reçu ce binaire de la part de Hallebarde, avec un message qui disait:
"Vous êtes tellement mauvais qu'on vous envoie un exécutable qui donne
une information si vous arrivez à le lancer comme il faut... Si vous y
arrivez !" On l'a fait tourner plein de fois sans succès. Pourriez-vous
nous dire ce qu'il cache ?

Attention ce binaire est susceptible de faire planter votre machine.
Maniez-le avec précaution !!
    
Auteur : mh4ckt3mh4ckt1c4s#0705
```

Catégorie: Rétro-ingénierie

Difficulté: Difficile

## Aperçu

Comme le binaire est indiqué comme dangereux, on ne le lance pas.

On peut l'ouvrir avec Ghidra pour avoir un aperçu de son contenu,
on trouve facilement la fonction `main` qui donne ceci dans
le décompilateur:
```
  _Var1 = getpid();
  iVar2 = FUN_00101490(argc,argv,_Var1);
  rand();
  rand();
  do {
    _Var3 = fork();
  } while (_Var3 != 0);
  tVar4 = time(NULL);
  uVar5 = read_inutile();
  _Var3 = getpid();
  if ((_Var3 == iVar2) && ((int)uVar5 == (int)tVar4)) {
    showflag(_Var1,_Var3,(long)(int)uVar5);
    return 0;
  }
  puts("Echec...");
  sleep(1);
  local_34 = rand();
  for (local_38 = 0; local_38 < 100000; local_38 = local_38 + 1) {
    local_34 = FUN_00101420();
  }
                    // WARNING: Subroutine does not return
  exit(local_34);
```

Et la fonction `showflag` (facile à identifier par son printf):
```
  n2_ = n2;
  n1_ = n1;
  local_c = param_1;
  puts(s_Succ_s_!_00102004);
  buf = calloc(8,1);
  A = (n2_ / 100000) * 10000000000;
  B = (long)(n1_ * 1000000);
  C = n2_ - A / 100000;
  local_40 = A + B + C;
  for (i = 0; i < 6; i = i + 1) {
    *(char *)((long)buf + (long)i) = (char)(local_40 >> ((5 - (char)i) * 8 & 63U));
  }
  memcpy(flag,ENCRYPTED_FLAG,44);
  i_ = 0;
  while( true ) {
    flag_len = strlen((char *)flag);
    if (flag_len <= (ulong)(long)i_) break;
    for (j = 0; j < 1341; j = j + 3) {
      flag[i_] = flag[i_] ^ *(byte *)((long)buf + (long)(i_ % 6));
    }
    i_ = i_ + 1;
  }
  printf("Flag : %s\n",flag);
  free(buf);
  sleep(1);
  kill(local_c,9);
  return;
```

## Analyse du code

La fonction showflag semble assez simple: elle opère un XOR sur un flag
chiffré présent dans le programme, via une certain clé de 6 octets.

Chaque XOR est fait `1341 / 3 = 447` fois: il suffit de le faire une
fois.

On a donc un flag chiffré en XOR avec un clé de 6 octets à trouver.

Le flag chiffré est:
```
2060 [0]            FF, BD, D2, 5B
2064 [4]            1D, CD, D9, EF
2068 [8]            93, 45, 59, DC
206c [12]           D9, E8, B3, 1C
2070 [16]           0D, 9A, E8, CE
2074 [20]           F5, 53, 6E, D7
2078 [24]           E6, EA, 87, 77
207c [28]           51, 9D, F8, C5
2080 [32]           D5, 18, 4F, E5
2084 [36]           D8, C5, FD, 18
2088 [40]           53, 91, D6, 00
```

## Solution

Puisque les flags sont de la forme `404CTF{..}` il suffit de faire
apparaître 404CTF:
```
enc = bytes.fromhex("""
ffbdd25b 1dcdd9ef 934559dc d9e8b31c
0d9ae8ce f5536ed7 e6ea8777 519df8c5
d5184fe5 d8c5fd18 5391d6
""")

stub = b"404CTF"

for i in range(30):
    key = [enc[i + (j - i % 6) % 6] ^ stub[(j - i % 6) % 6] for j in range(6)]
    print(i, bytes(key))
    print(bytes(b ^ key[i % 6] for i, b in enumerate(enc)))
```

On obtient immédiatement la solution:
```
15 b'\xab\x9a\xb3(=\xae'
b"T'as cru mdrrr\x00404CTF{SyMp4_l3S_f0rKs_N0n?}"
```

## Note

Le reste du code implémentait en réalité une logique cachée permettant de
déterminer la clé, vous la trouverez dans les autres write-ups.
