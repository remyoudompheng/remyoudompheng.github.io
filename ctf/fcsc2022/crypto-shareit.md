---
title: Crypto — Share-It
parent: FCSC 2022
grand_parent: CTF writeups
---

Share It
===

La description du challenge indique que le programme est une
"optimisation" d'un programme `sss.c`.

On le retrouve facilement ici:
https://github.com/ANSSI-FR/libecc/blob/master/src/examples/sss/sss.c

Le secret du Shamir's shared secret est un polynôme P à coefficients
modulo p, dont des personnes connaissent des valeurs P(n)
pour différents entiers n.

Lorsque suffisamment de personnes mettent en comun leurs valeurs,
les formules d'interpolation de Lagrange permettent de reconstruire
le polynôme secret.

Reverse et vulnérabilité
---

Le programme modifié a introduit une graine aléatoire faible de 16 bits.

de sorte que les coefficients sont de la forme:
```
a0 = secret
aj = secret * HMAC(key={seed, j}, msg=j, algo=SHA512) / R**(j+2)
```
où seed est la graine 16 bits, et j l'indice du coefficient.
R = 2^256 est la constante de la multiplication de Montgomery,
une technique utilisée pour accélérer la multiplication modulaire
utilisée dans `sss.c`. Un commentaire dans le code indique
que ça modifie la valeur des coefficients générés.

Le polynôme final est donc:
```
P(X) = secret * (1 + Somme(HMAC(seed,j) / R^(j+2) X^j))
P = secret * Q(seed, degré)
```

On trouve le secret par recherche exhaustive sur les 65536 graines
possibles. Le degré du polynôme est inconnu mais d'après l'énoncé,
il est environ 60.

On trouve en 20 secondes en explorant les degrés 5 à 60,
que la graine était de 7086 et le degré de 40.

```python
from base64 import b64decode
import struct
from Crypto.Hash import HMAC, SHA512

PRIME = 2**256 - 2**32 - 977
R = 2**256 # constante de Montgomery

SHARE = b64decode("YuK4miheVQW3k5aeI1wBZjJ5cCnnxL8XeRdlzvznOidFDVBAanRGn5xYoOFNN/AmLJXs+YpUSmaOs5AluuNCwlcxoP00vRME6PySBMy4etC8bw==")
IDX, = struct.unpack(">H", SHARE[:2])
NUMBER = int.from_bytes(SHARE[2:2+32], "big")
assert NUMBER.bit_length() == 256

def generate_polys(IDX: int, mindeg: int, maxdeg: int):
    for seed in range(65536):
        # coeff[0] = 1
        # On fabrique les polynômes de différents degrés
        P = 1
        base = (IDX * pow(R, -1, PRIME)) % PRIME
        exp = pow(R, -2, PRIME)
        for j in range(1, maxdeg):
            b = struct.pack(">HH", seed, j)
            a = HMAC.new(b, msg=b[2:4], digestmod=SHA512).digest()
            a = int.from_bytes(a, "big")
            exp = (exp * base) % PRIME
            P += a * exp
            if j >= mindeg:
                yield seed, j, (P % PRIME)

def main():
    # On a généré une soixantaine, le quorum doit être entre 5 et 60
    for seed, j, p in generate_polys(IDX, 5, 60):
        quo = (NUMBER * pow(p, -1, PRIME)) % PRIME
        msg = quo.to_bytes(32, "big")
        if b"FCSC" in msg:
            print(seed, j, msg)
            break

if __name__ == "__main__":
    main()
```
