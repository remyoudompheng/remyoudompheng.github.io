---
title: Diploma
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

# Diploma

Catégorie: medium

Points: 71

Résolutions: 68

First blood! 🩸

## Énoncé

```
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|  Hi all, cryptographers know that the calculation of the order of a  |
|  given element in a group is not easy at all. We are working in the  |
|  group GL(d, p), the group of invertible matrices of order `d' on a  |
|  finite field of order `p'. In each stage send the order matrix M.   |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Generating the parameters for p = 127, please wait...
| M = 
[  4 124  86]
[110  68  93]
[ 29  79  30] 
| Send the order of matrix M: 
```

Un serveur réseau, dont le code source est inconnu, envoie des matrices
apparemment aléatoires et demande leur ordre multiplicatif dans `GL_n(GF(p))`.

## Propriétés mathématiques

Dans le cas favorable, le polynôme caractéristique de M n'a pas de racine
double (son discriminant est nul, probablement avec probabilité 1/127),
et M est diagonalisable dans une clôture algébrique de `GF(p)`.

Si une matrice est diagonale, son ordre multiplicatif est simplement le
PPCM des ordres multiplicatifs de ses valeurs propres.

On factorise donc le polynôme caractéristique de M et on cherche l'ordre
multiplicatif de ses racines. Rappelons que si un polynôme est
irréductible de degré `d`, ses racines existent dans `GF(p^d)`
et sont conjuguées sous l'action du groupe de Galois, et elles ont donc
le même ordre multiplicatif.

En pratique, le serveur semble envoyer des matrices choisies
aléatoirement: leur déterminant est parfois nul (auquel cas il n'y a pas
de solution), et le polynôme caractéristique peut avoir un discriminant
nul. On découvrira que le serveur utilise toujours p=127 et envoie 12
matrices de taille 3 à 14, la probabilité que les matrices soient toutes
inversibles et diagonalisables est donc raisonnables (environ 90% par un
calcul naïf: `(126/127)**12 = 0.909..`).

## Script solution

```python
from telnetlib import Telnet
from sage.all import Matrix, Zmod, lcm, GF

c = Telnet("08.cr.yp.toc.tf", 37313)

rows = []
while True:
    line = c.read_until(b"\n").strip().decode()
    if " p =" in line:
        _, _, l = line.partition(" p = ")
        l, _ ,_ = l.partition(",")
        p = int(l)
        print("prime", p)
        rows = []
    elif line.startswith("["):
        row = [int(x) for x in line.strip("[]").split()]
        print(row)
        rows.append(row)
    elif 'Send the order' in line:
        m = Matrix(Zmod(p), rows)
        print(m.charpoly())
        result = 1
        for f, mult in m.charpoly().factor():
            r = f.roots(GF(p**f.degree()))[0][0]
            r_order = r.multiplicative_order()
            result = lcm(result, r_order)
        print(result)
        c.write(("%d\n" % result).encode())
    else:
        print(line)

# Congrats, you got the flag: CCTF{ma7RicES_4R3_u5EfuL_1n_PUbl!c-k3y_CrYpt0gr4Phy!}
```
