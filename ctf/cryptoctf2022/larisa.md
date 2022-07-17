---
title: Larisa
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

# Larisa

Catégorie: medium-hard

Points: 174

Résolutions: 22

First blood! 🩸

## Énoncé

You think you can understand the way our cryptosystem encrypts messages?
Here you can challenge yourself by decrypting this message!

```
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

def pad(msg, n):
    assert len(msg) <= n
    return msg + msg[-1] * (n - len(msg))

def embed(msg, n):
    assert len(msg) < n
    msg = pad(msg, n)
    while True:
        r, s = [randint(2, n) for _ in '__']
        if gcd(r, len(msg)) == 1:
            break
    A = []
    for _ in range(n):
        while True:
            R = genperm(n)
            if R[(_ * r + s) % n] == ord(msg[_]):
                A.append(R)
                break
    return A

def encrypt(A, e = 65537):
    return powlat(A, e)

l, e = 128, 65537
M = embed(flag, l)
C = encrypt(M, e)
print(C)
```

(voir également le défi connexe Lagima).

## Analyse

Les fonctions fournies effectuent des opérations sur des tableaux de
permutations:

* `getlatrow` (non utilisée) tire aléatoirement un vecteur de permutation
* `prodlat` calcule le produit terme à terme de 2 vecteurs de permutations
* `powlat` calcule l'exponentiation rapide, terme à terme, d'un vecteur
  de permutations

La fonction principale est `embed` qui encode un message de la manière
suivante: on choisit des coefficients de mélange `(r, s)` qui définissent
une fonction affine modulo 128 `x → r*x+s` et on tire aléatoirement un
vecteur de permutations `A` tel que `A[i][r*i+s] == msg[i]` pour tout
`i`.

Le chiffrement se fait en élevant le vecteur de permutations à la
puissance 65537.

Les puissances d'une permutation `p` agissent cycliquement sur les cycles de
la décomposition de `p`. On peut donc inverser l'exponentiation en calculant
l'inverse de 65537 modulo la longueur des cycles.

## Solution

On peut utiliser la méthode `multiplicative_order` de SAGE pour ne pas
écrire soi-même le calcul sur chacun des cycles.

On cherche ensuite `r`et `s` par recherche exhaustive, en connaissant le
format du drapeau `CCTF{...}` et en lisant les éléments `A[i][r*i+s]`.

```python
import json
from sage.all import SymmetricGroup

t = json.load(open("enc.txt"))

embed = []
G = SymmetricGroup(128)
for perm in t:
    g = G(perm)
    order = g.order()
    d = pow(65537, -1, order)
    embed.append((g**d).tuple())

for r in range(1, 128, 2):
    for s in range(128):
        txt = bytes(embed[i][(r * i + s) % 128] for i in range(128))
        if b"CCTF" in txt:
            print(txt)
```
