---
title: Lagima
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

# Lagima

Catégorie: medium-hard

Points: 164

Résolutions: 24

## Énoncé

(voir aussi le défi voisin "Larisa")

You are in the road to learn some interesting cryptosystems, decrypt our cipher!

```python
#!/usr/bin/env sage

from flag import flag

def genperm(n):
    _ = list(range(1, n + 1))
    shuffle(_)
    return _

def genlatrow(n):
    A = []
    for _ in range(n): A.append(genperm(n))
    return A

def prodlat(A, B):
    assert len(A) == len(B)
    C, G = [], SymmetricGroup(len(A))
    for _ in range(len(A)):
        g = (G(A[_]) * G(B[_])).tuple()
        C.append(list(g))
    return C

def powlat(A, n):
    assert n >= 0
    B = bin(n)[2:]
    c, R = len(B), [list(range(1, len(A) + 1)) for _ in range(len(A))]
    if n == 0: return R
    else:
        for b in B:
            if b == '1':
                if c == 1: R = prodlat(R, A)
                else:
                    T = A
                    for _ in range(c - 1): T = prodlat(T, T)
                    R = prodlat(R, T)
            c -= 1
    return R

G = genlatrow(313)
secret = int.from_bytes(flag.lstrip(b'CCTF{').rstrip(b'}'), 'big')
H = powlat(G, secret)

print(f'G = {G}')
print(f'H = {H}')
```

## Description du code

Le drapeau est converti en un grand entier qui sert d'exposant secret.

Un vecteur `G` de 313 permutations aléatoires des entiers de 1 à 313
est choisi.

La fonction `powlat` effectue une exponentiation rapide dans le groupe
symétrique, terme à terme.

## Propriété mathématique

Chaque élément de G est traité séparément. Les puissances d'une
permutation sont faciles à décrire en étudiant la décomposition
en cycles: la permutation agit de manière... cyclique, sur
chaque cycle, on peut donc distinguer ses différentes puissances
en observant leur action sur chaque cycle.

Puisque chaque élément de G agit par décalage de 1 sur chacun de
ses cycles, l'élement correspondant de H agira par un décalage de
`secret % len(cycle)` sur ce cycle.

On obtient ainsi `secret % l` pour différentes valeurs de `l`
entre 2 et 313, ce qui permet de conclure en appliquant le théorème
des restes chinois.

## Solution

Note: SAGE fournit également une fonction générique `discrete_log`.

```python
import json
from sage.all import SymmetricGroup, CRT

with open("output.txt") as f:
    lG = next(f)
    G = json.loads(lG.split("=")[-1])
    lH = next(f)
    H = json.loads(lH.split("=")[-1])

Sn = SymmetricGroup(313)
g = [Sn(x) for x in G]
h = [Sn(x) for x in H]

rems = {}
for i, gi in enumerate(g):
    for c in gi.cycle_tuples():
        l = len(c)
        k = c.index(h[i](c[0]))
        if l in rems:
            assert rems[l] == k
        else:
            rems[l] = k
c = CRT(list(rems.values()), list(rems.keys()))
print(int(c).to_bytes(64, "big").lstrip(b'\0'))
# b'3lGam4L_eNcR!p710n_4nD_L4T!n_5QuarS3!'
```
