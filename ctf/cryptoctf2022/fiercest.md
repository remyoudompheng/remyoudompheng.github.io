---
title: Fiercest
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

# Fiercest

Catégorie: medium

Points: 142

Résolutions: 29

## Énoncé

Once again, we decided to deploy an artificial fault attack!

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
import sys
from flag import flag

def diff(a, b):
    assert a.bit_length() == b.bit_length()
    w, l = 0, a.bit_length()
    for _ in range(l):
        if bin(a)[2:][_] != bin(b)[2:][_]: w += 1
    return w

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc():
    return sys.stdin.readline().strip()

def main():
    border = "|"
    pr(border*72)
    pr(border, "Hello guys! This is a challenge on fault attack for signatures, our ", border)
    pr(border, "storage can apply at most `l' bit flip-flop on signature modulus, so", border)
    pr(border, "try to locate the critical bits, we'll changed them to forge a sign!", border)
    pr(border*72)

    nbit = 512
    p, q = [getPrime(nbit) for _ in '__']
    n, e = p * q, 65537
    B, l = [int(b) for b in bin(n)[2:]], 2
    
    MSG = "4lL crypt0sy5t3ms suck5 fr0m faul7 atTaCk5 :P"
    m = bytes_to_long(MSG.encode('utf-8'))

    while True:
        pr("| Options: \n|\t[A]pply fault \n|\t[G]et the parameters \n|\t[V]erify the signature \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'a':
            _B = B
            pr(border, f"please send at most {l}-tuple array from indices of bits of modulus, like: 14, 313")
            ar = sc()
            try:
                ar = [int(_) for _ in ar.split(',')]
                if len(ar) <= l:
                    for i in range(len(ar)): _B[ar[i]] = (_B[ar[i]] + 1) % 2
                    N = int(''.join([str(b) for b in _B]), 2)
                else: raise Exception('Invalid length!')
            except: pr(border, "Something went wrong!!")
        elif ans == 'g':
            pr(border, f'e = {e}')
            pr(border, f'n = {n}')
        elif ans == "v":
            pr(border, "please send signature to verify: ")
            _flag, signature = False, sc()
            try:
                signature = int(signature)
                if pow(signature, e, N) == m: _flag = True
                else: pr(border, "Your signature is not valid!!")
            except:
                pr(border, "Something went wrong!!")
            if _flag: die(border, "Congrats! your got the flag: " + flag)
        elif ans == 'q': die("Quitting ...")
        else: die("Bye bye ...")

if __name__ == "__main__": main()
```

## Analyse

Le serveur demande de forger une signature RSA pour un message prédéfini
avec la possibilité de basculer 2 bits du module RSA au moment de la
vérification.

Mathématiquement, il s'agit de déterminer des entiers `i, j` et une
signature `sig` tels que `pow(sig, 65537, n ^ 2**i ^ 2**j) = msg`.

## Stratégie

Le plus simple est de chercher à modifier `n` de manière à obtenir un
nombre premier: il est très simple d'inverser l'exponentiation
modulo un nombre premier.

Comme `n` est un entier de 1024 bits, et que la densité des nombres
premiers autour de `n` est environ de `1 / log(n)` on a une probabilité
très élevée de trouver un nombre premier en essayant de basculer 2 bits
(> 500k combinaisons possibles).

Le plus souvent, un seul bit suffit (1000 combinaisons, pour une densité
de nombres premiers de 1/700 environ).

Comme les tests de primalité sont très rapides, la solution s'obtient
en quelques secondes.

## Solution

On écrit une fonction de recherche, à lancer sur les paramètres
renvoyés par le serveur:

```python
from sage.all import is_prime

MSG = b"4lL crypt0sy5t3ms suck5 fr0m faul7 atTaCk5 :P"
target = int.from_bytes(MSG, "big")

def flip(n):
    length = n.bit_length()
    for i in range(3, 1021):
        for j in range(i+1, 1021):
            if is_prime(n ^ (1<<i) ^ (1<<j)):
                print("flip", length-1-i, length-1-j)
                return i, j, n ^ (1<<i) ^ (1<<j)

def solve(n):
    i, j, p = flip(n)
    d = pow(65537, -1, p-1)
    sig = pow(target, d, p)
    return i, j, sig
```

Note: des participants ont signalé que le code permettait
de basculer plusieurs fois 2 bits (`_B = B`).
