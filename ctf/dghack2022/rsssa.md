---
title: RSSSA
parent: DG'h4ck 2022
grand_parent: CTF writeups
---

On nous fournit un script Python qui chiffre un flag avec une clé
dérivée d'une valeur stockée dans un _secret partagé de Shamir_.

Voici une version simplifiée du challenge (accessible par un service réseau):
```python
from random import randint
from hashlib import sha256

N = 0xd73dd1b77ae0bcc27fad3d4977f998e4ea5381f21c64aa39923adf73135f0a270eb1c5c2c10d2a609e0cdee57e50ccb93c2d41d4e3bf6e898885815f574bf4dc4a0a9c4a68245d8f7a2cd2b7fab1b43f9d6f1af208f91ad3535adc087ac3f25bcd926fb85a704697e0e2e7f409693ffce4973fbf2809ae7df2e11ebe258e4fa7a7b718a6d2ef0b64ded43ca7ed2c6682b9db2c9795727bb685b1ee2fc080dd08e262129419a930520ec1a0a4196a6b06ccaa1eadb4ea368bfc97fed2d7f3b367f9d0d7cab97aa4b188126198849db10c52b59a7044515c50f6d67b9810b9244cdb6f7b4e579eac1bd682355a87826bbee880fa49f167fc453b0f8bd4451e716b

s = randint(0, N-1)
a0 = randint(0, N-1)
a1 = pow(a0+s, 3, N)
a2 = pow(a1+s, 3, N)
a3 = pow(a2+s, 3, N)
key = sha256(str(a3).encode()).digest()
def eval_poly(x):
    return (a0 + a1*x + a2*x**2 + a3*x**3) % N

for _ in range(3):
    x = int(input("Enter a point:"))
    print(f"P({x}) = {eval_poly(x)}")
```

La valeur N est publique mais `a0` et `s` sont secrets et générés aléatoirement
à chaque connexion au serveur. Le nombre N n'est pas un nombre premier mais un nombre
composé (à la manière d'une clé RSA).

Il faut trouver la valeur a3 qui sert à dechiffrer le flag.

On peut se référer à la page Wikipédia pour plus d'information:
[Partage de clé secrète de Shamir](https://fr.wikipedia.org/wiki/Partage_de_cl%C3%A9_secr%C3%A8te_de_Shamir)

Il faut en théorie 4 valeurs pour retrouver le polynôme P
mais ici nous avons accès à seulement 3 valeurs (et on ne peut
pas obtenir `a3` directement de cette manière).

Examinons ce qui se passe si on envoie les valeurs 0, 1 et -1
(on peut également résoudre l'exercice en choisissant d'autres valeurs).
```
P(0) = a0
P(1) = a0 + a1 + a2 + a3
P(-1) = a0 - a1 + a2 - a3
(modulo N)
```

On en déduit:
```
2 a2 == P(1) + P(-1) - 2*P(0)
```
donc la valeur de `a2`.

Il suffit maintenant d'avoir `s` pour obtenir `a3`.

On sait que:
```
a2 = ((a0 + s)^3  + s)^3
P(1) - P(-1) = 2*a1 + 2*a3 = 2(a0 + s)^3 + 2(a2 + s)^3
```
c'est-à-dire qu'on a deux équations polynômiales (de degré 9 et 3 respectivement).

On peut obtenir une équation plus simple en calculant le PGCD de ces deux équations:
on obtient à la fin une équation de degré 1 et donc la valeur de s. Le programme
`sage` permet de le calculer:
```
a0 = eval_poly(0)
ap = eval_poly(1)
am = eval_poly(-1)

a2 = (ap + am - 2*a0) * pow(2, -1, N) % N
a1_plus_a3 = (ap - am) * pow(2, -1, N) % N

from sage.all import Zmod
R = Zmod(N)["S"]
S = R.gen()
Eq1 = ((S + a0)**3 + S)**3 - a2
Eq2 = (a0 + S)**3 + (a2 + S)**3 - a1_plus_a3
rem = Eq1 % Eq2
assert rem.degree() == 2
rem2 = Eq2 % rem
assert rem2.degree() == 1
# rem2 est un polynôme de la forme a*S + b
solution = -rem2.monic()[0]
assert solution == s
```

