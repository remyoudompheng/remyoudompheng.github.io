---
title: Cryptanalyse — Ransomware 4/4
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

(Je n'ai pas pu valider ce challenge, qui était déverrouillé seulement
après son acolyte Hackllebarde Ransomware 3/4)

# Hackllebarde Ransomware 4/4

```
Pendant que vous travailliez sur l'analyse forensique, nos experts en
rétro-ingénierie ont pu extraire le code utilisé pour chiffrer nos
documents. Hélas, pas moyen de retrouver la clé de chiffrement, elle n'a
pas été sauvegardée du tout !! Le département de cryptographie est
formel, les données sont bel et bien perdues. Néanmoins jetez un coup
d'oeil, on ne sait jamais...

Auteur : mh4ckt3mh4ckt1c4s#0705
```

Catégorie: cryptanalyse

Difficulté: difficile

## Description

Sont fournis:

* un fichier `flag.pdf.enc` (151772 octets)
* un fichier source `ransomware.c`

Le protocole de chiffrement est un XOR avec un flux de clé obtenu
en appelant `rand()`

```c
char array[8];
initstate(seed, array, 27);
...
while ((len = fread(&data, sizeof(char), 4, file)) == 4) {
        // on ne peut rien faire contre une clé 100% aléatoire !!!
        key = rand();
        keychar = (char*)&key;
        for(int i=0; i<len; i++) {
                data[i] ^= keychar[i];
        }
        fwrite(&data, sizeof(char), 4, encryptedfile);
}
```

## Le générateur aléatoire

D'après le code de la glibc, le paramètre n=27 dans initstate
va sélectionner le générateur linéaire congruentiel:

```c
#define BREAK_1   32

int
__initstate_r (unsigned int seed, char *arg_state, size_t n,
         struct random_data *buf)
{
...
  else if (n < BREAK_1)
    {
      if (n < BREAK_0)
          goto fail;

      type = TYPE_0;
    }
...
}

int
__random_r (struct random_data *buf, int32_t *result)
{
...
  if (buf->rand_type == TYPE_0)
    {
      int32_t val = ((state[0] * 1103515245U) + 12345U) & 0x7fffffff;
      state[0] = val;
      *result = val;
    }
...
```

À consulter ici:
(random_r.c)[https://sourceware.org/git/?p=glibc.git;a=blob;f=stdlib/random_r.c;hb=glibc-2.31]

Il est donc très facile de reconstituer son état à partir de données
connues: par exemple les 4 premiers octets `%PDF` d'un fichier PDF.

## Solution

```python
import struct
data = open("flag.pdf.enc", "rb").read()
seed = None
dec = []
for (n,) in struct.iter_unpack("<I", data):
    if seed is None:
        seed = n ^ struct.unpack("<I", b"%PDF")[0]
    else:
        seed = ((seed * 1103515245) + 12345) % (2**31)
    dec.append(seed ^ n)
open("flag.pdf", "wb").write(struct.pack("<%dI"%len(dec), *dec))
```

On obtient un fichier PDF contenant une image représentant le flag.
