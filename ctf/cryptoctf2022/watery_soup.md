---
title: Watery Soup
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

{%- include mathjax.html -%}

# Watery Soup

Catégorie: medium-hard

Points: 226

Résolutions: 15

## Énoncé

Le défi est un oracle implémenté par ce programme:

```python
from Crypto.Util.number import *
import sys
from flag import flag

flag = bytes_to_long(flag)
assert 256 < flag.bit_length() < 512

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc(): return sys.stdin.readline().strip()

def main():
    border = "|"
    pr(border*72)
    pr(border, "Hi crypto-experts, send us your prime and we will mix the flag with ", border)
    pr(border, "it! Now can you find the flag in the mixed watery soup!? Good luck! ", border)
    pr(border*72)
    while True:
        pr("| Options: \n|\t[S]end the prime! \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 's':
            pr(border, "Send your prime here: ")
            p = sc()
            try: p = int(p)
            except: die(border, "Your input is not valid!!")
            if not (128 <= p.bit_length() <= 224): die(border, "Your prime is out of bounds :(")
            if not isPrime(p): die(border, "Your input is NOT prime! Kidding me!?")
            pr(border, "Send the base here: ")
            g = sc()
            try: g = int(g) % p
            except: die("| Your base is not valid!!")
            if not (64 < g.bit_length() < 128): die(border, "Your base is too small!!")
            result = (pow(g ** 3 * flag, flag - g, p) * flag + flag * flag + g) % p
            pr(border, f"WooW, here is the mixed flag: {result}")
        elif ans == 'q': die(border, "Quitting ...")
        else: die(border, "Bye ...")

if __name__ == '__main__': main()
```

## Analyse

L'oracle permet de calculer pour `p` premier et `g`, de tailles
contraintes, la formule:

$$ O(g) = (g^3 · f) ^ {f-g} · f + f^2 + g \mod p $$

où `f` est le drapeau inconnu.

Le facteur de la forme `f^f` est très difficile à analyser, on essaie
donc de l'éliminer en combinant plusieurs résultats de l'oracle.

On peut diviser deux facteurs:

$$ (g_1^3 · f) ^ {f-g_1} · f / (g_2^3 · f) ^ {f-g_2} · f
= (g_1^3) ^ {f-g_1} / (g_2^3) ^ {f-g_2} · f^{g_2 - g_1} $$

Ou essayer des combinaisons multiplicatives plus complexes:

$$ \big( (g_1^3 · f) ^ {f-g_1} · f \big)^X
   \big( (g_2^3 · f) ^ {f-g_2} · f \big)^Y
   \big( (g_3^3 · f) ^ {f-g_3} · f \big)^Z $$

$$ = (g_1^X g_2^Y g_3^Z) ^ {3f} / f^{g_1X+g_2Y+g_3Z}
   / (g_1^{3X g_1} g_2^{3Y g_2} g_3^{3Z g_3})
$$

$$ =\big( O(g_1) - g_1 - f^2 \big)^X
    \big( O(g_2) - g_2 - f^2 \big)^Y
    \big( O(g_3) - g_3 - f^2 \big)^Z
$$

Peut-on éliminer `f` dans cette dernière expression?

Il faudrait pour cela avoir `g1^X g2^Y g3^Z = 1`
et `g1 X + g2 Y + g3 Z = 0`. On obtiendrait alors une constante,
et la dernière égalité donne une équation polynomiale pour `f^2`.

## Choix des paramètres

Pour reduire le degré du polynôme on choisit des valeurs petites
`X, Y, Z = 1, 2, -3` et on résout modulo `p`:

```
g1 + 2 g2 = 3 g3
g1 * g2^2 = g3 ^ 3
```
(en réalité c'est incorrect, la première équation devrait être modulo
`p-1`: on verra plus loin que cela ne pose pas de problème).

On trouve facilement les solutions:
```
g1 = 4*g3
g2 = - g3/2
```

Choisissons donc pour satisfaire les conditions du serveur:
```
p = 2**127 + ε (nombre premier de 128 bits)
g3 = 2**64
g1 = 2**66
g2 = p - 2**63
```

Alors (attention `f^p = f`)

$$  \big( O(g_1) - g_1 - f^2 \big)^1
    \big( O(g_2) - g_2 - f^2 \big)^2
    \big( O(g_3) - g_3 - f^2 \big)^{-3}
$$

$$ = (g_1 g_2^2 g_3^{-3}) ^ {3f} / f^{g_1+2g_2-3g_3}
   / (g_1^{3 g_1} g_2^{6 g_2} g_3^{-9 g_3})
$$

$$ = f^{- (2^{66} + 2p - 2^{64} - 3·2^{64} = 2p)}
   / (g_1^{3 g_1} g_2^{6 g_2} g_3^{-9 g_3})
$$

$$ = f^{-2} / (g_1^{3 g_1} g_2^{6 g_2} g_3^{-9 g_3})
$$

Soit l'équation de degré 4 d'inconnue `f²`:

$$ f^2 \big( O(g_1) - g_1 - f^2 \big)^1
   \big( O(g_2) - g_2 - f^2 \big)^2
  (g_1^{3 g_1} g_2^{6 g_2} g_3^{-9 g_3})
 = \big( O(g_3) - g_3 - f^2 \big)^3
$$

On résout alors cette équation pour avoir des valeurs
candidates pour `f % p`.

On obtient la solution en répétant l'opération pour
plusieurs valeurs de `p` avec le théorème des restes chinois.

## Solution

```python
from telnetlib import Telnet
from sage.all import primes, Zmod, CRT

c = Telnet("05.cr.yp.toc.tf", 37377)

def oracle(p, g):
    c.read_until(b"uit\n")
    c.write(b"S\n")
    print(c.read_until(b"\n"))
    c.write((str(p) + "\n").encode())
    print(c.read_until(b"\n"))
    c.write((str(g) + "\n").encode())
    line = c.read_until(b"\n")
    print(line)
    return int(line.decode().strip().split()[-1])

primes128 = [int(p) for _, p in zip(range(4), primes(2**127, 2**127+1000))]

roots = []
for p in primes128:
    g3 = 2**64
    g1 = (4 * g3) % p
    g2 = p - g3 // 2

    z1 = (oracle(p, g1) - g1) % p
    z2 = (oracle(p, g2) - g2) % p
    z3 = (oracle(p, g3) - g3) % p

    kp = Zmod(p)
    Rx = Zmod(p)["x"]
    x = Rx.gen()
    gg1 = pow(g1, 3 * g1, p)
    gg2 = pow(g2, 3 * g2, p)
    gg3 = pow(g3, 3 * g3, p)
    P = x * gg1 * (z1 - x) * (gg2 * (z2 - x)) ** 2 - (gg3 * (z3 - x)) ** 3

    root = P.roots(ring=kp)[0][0].sqrt()
    roots.append(int(root))

p1, p2, p3, p4 = primes128
P = p1 * p2 * p3 * p4

def check(rems):
    flag = CRT(rems, primes128)
    for f in range(int(flag), 2**512, P):
        s = f.to_bytes(64, "big")
        if b"CCTF" in s:
            print(s.lstrip(b'\0'))

for sign in range(16):
    check([-roots[b] if sign&(1<<b) else roots[b] for b in range(4)])

# CCTF{Pl34se_S!r_i_w4N7_5omE_M0R3_5OuP!!}
```
