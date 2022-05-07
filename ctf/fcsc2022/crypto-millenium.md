---
title: Crypto — Millenium
parent: FCSC 2022
grand_parent: CTF writeups
---

Millenium
===

Le problème se présente sous la forme d'un répertoire de code
et d'un fichier contenant le résultat de 300000 signatures
faites par une clé privée à trouver.

Les noms des fonctions sont caractéristiques et un moteur de recherche
permet de faire correspondre le code à l'implémentation de référence
de FALCON (Millenium, vous voyez la blague), un algorithme de signature
utilisant des réseaux, présenté à la compétition post-quantique du NIST.

* [Article de présentation de FALCON](https://falcon-sign.info/falcon.pdf)
* [Dépôt Github de la bilbiothèque Python](https://github.com/tprest/falcon.py)

Un diff Git permet de voir les modifications qui ont été apportées:

* les commentaires ont été supprimés
* le module q a été réduit de 12x1024+1 à 6x128+1=729
* les constantes de transformée de Fourier arithmétique (NTT)
  ont été recalculées pour la nouvelle valeur de q

On voit par ailleurs que le degré des polynômes N=128 est plus bas que la
recommandation de FALCON (256 ou 512).

La signature n'a pas été faite en utilisant la fonction de la bibliothèque
et s'accompagne d'un commentaire suspect.
```python
N = 128

# this function has been HIGHLY optimized to be super efficient
def sign(sk, message):
    f, g, F, G = sk
    B0 = [
        [g, neg(f)],
        [G, neg(F)],
    ]

    r = os.urandom(40)
    point = hash_to_point(r, message)
    n = len(point)

    B0_fft = [[fft(elt) for elt in row] for row in B0]
    [[a, b], [c, d]] = B0_fft

    point_fft = fft(point)
    t0_fft = [(point_fft[i] * d[i]) / q for i in range(n)]
    t1_fft = [(-point_fft[i] * b[i]) / q for i in range(n)]

    z0 = [round(elt) for elt in ifft(t0_fft)]
    z1 = [round(elt) for elt in ifft(t1_fft)]

    z_fft = [fft(z0), fft(z1)]
   
    v0_fft = add_fft(mul_fft(z_fft[0], a), mul_fft(z_fft[1], c))
    v1_fft = add_fft(mul_fft(z_fft[0], b), mul_fft(z_fft[1], d))
    v0 = [int(round(elt)) for elt in ifft(v0_fft)]
    v1 = [int(round(elt)) for elt in ifft(v1_fft)]

    s = [sub(point, v0), neg(v1)]
    return r, s
```

Or l'article FALCON (section 3.9.1) indique que:
```
A naive way to find such short values `(s1, s2)` would be to compute
`t ← (c,0)·B^-1`, round it coefficient-wise to a vector z = ⌊t⌉ and output
`(s1, s2) ← (t − z)B`; it fulfils all the requirements to be a legitimate
signature, but this method is known to be insecure and to leak the private key.
```
ce qui est précisément ce qui se passe ici.

L'attaque est référencée dans la section 2.2 (_Learning a parallelepiped:
Cryptanalysis of GGH and NTRU signatures_ de Nguyen et Redev).

# Brève description du système

Le système de signature FALCON est "seulement" une modification de l'algorithme
de signature permettant d'éviter la fuite statistique exploitée par l'attaque de
Nguyen-Redev, le système reste le même, donc les signatures "Millenium"
sont exactement les signatures NTRU vulnérables à l'attaque.

Les réseaux NTRU utilisés ici sont composés de couples de polynômes (s1,s2)
modulo `x^128+1` satisfaisant l'équation `s1 + s2 * h = 0 mod q`
où h est un polynôme modulo q qui sert de clé publique, dans l'anneau
`R = Z[x]/(x^128+1)`.

Les calculs modulo `x^128+1` peuvent de faire facilement par transformée de Fourier,
mais cela ne change pas le principe du système.

Les couples correspondants sont de la forme `(s1, s2) = A (-h, 1) + B (q, 0)`
et forment donc un réseau (_lattice_).

Le principe de signature est le suivant:

* on hache un message avec un sel pour fabriquer un vecteur aléatoire `(m1, m2)`
  dont les coefficients sont inférieurs à q
* on construit une paire du réseau `(v1, v2)` très proche de `(m1, m2)`
  (avec une constrainte très forte `|v-m|² < 2qN`)
* la signature est le vecteur m-v

Pour construire la paire très petite, on utilise une clé secrète: une base
du réseau formée de vecteur très petits (judicieusement choisis)
`(g, -f)` et `(G, -F)` avec les équations NTRU:
```
g - fh = 0 mod q   # h = g/f dans Zq[x]/(x^128+1)
fG - gF = q mod (x^128+1)
```
La deuxième condition vient du fait que `|det((-h, 1), (q, 0))| = q` et que toutes
les bases doivent avoir ce déterminant.

# Attaque de Nguyen et Redev

[Article de référence](https://cims.nyu.edu/~regev/papers/gghattack.pdf)

L'attaque utilise le principe que le résultat du hash est aléatoire et uniformément
réparti dans le choix des coefficients < q, et que la méthode de signature naïve
va chercher le point du réseau dont les coordonnées sont les entiers les plus proches
dans la base secrète `(g, -f)` et `(G, -F)`.

Les hash possibles remplissent donc une sorte de "cube" dont les arêtes sont
déterminées par les vecteurs de la base secrète.

Elle utilise le fait qu'une certaine fonction:
```
moment: x → Moyenne(|x-v|^4, v dans le cube)
```
est minimale exactement lorsqu'on atteint le centre d'une face du cube, et on
résout ce minimum par une descente de gradient. Pour l'appliquer, il faut
d'abord normaliser les coordonnées par une certaine matrice (obtenue par la
décomposition de Cholesky de la matrice de covariance), intitulé dans l'article
le _morphing_ du parallélépipède.

Le gradient est:
```
grad: x → Moyenne(4 * v * |x-v|^3, v dans le cube)
```
à projeter sur la sphère unité (g → g - <g,x>x)

Heureusement, en Python, `numpy` permet de faire toutes ces opérations très rapidement
sans connaître tout le détail de l'implémentation.

L'attaque réussit en moins de 10 minutes (souvent, le résultat de la descente de gradient
est petit, mais trop grand pour la fonction ntrusolve). Un processeur de bureau ordinaire
avec une librairie Numpy par défaut (sans vectorisation) suffit à calculer une dizaine
de gradients par seconde.

Pour accélérer les calculs, on place les 300000 signatures dans une grande matrice,
ce qui permet de calculer tous les produits scalaires en une ligne de Python.

```python
import math
import time
import numpy as np
import sys

sys.path.append("millenium/secure_code")
from ntrugen import gs_norm, ntru_solve

PUB = [ 98, 400, 372, 55, 636, 461, 48, 248, 305, 739, 669, 439, 418, 97, 529,
    518, 461, 238, 121, 326, 602, 49, 724, 470, 82, 423, 537, 254, 21, 222,
    308, 115, 510, 139, 640, 537, 265, 338, 492, 607, 107, 14, 198, 124, 331,
    639, 177, 271, 304, 316, 283, 621, 47, 598, 672, 517, 521, 697, 549, 498,
    343, 626, 300, 386, 658, 410, 689, 548, 114, 654, 89, 139, 196, 424, 65,
    175, 496, 495, 518, 242, 607, 313, 451, 115, 385, 732, 489, 522, 198, 423,
    260, 411, 184, 154, 366, 612, 743, 401, 378, 445, 673, 418, 651, 741, 311,
    251, 290, 103, 499, 337, 285, 68, 125, 343, 139, 729, 550, 454, 165, 10,
    425, 144, 467, 293, 14, 109, 682, 732 ]

PRIME = 769

MAX_NORM = round(1.17**2 * PRIME, 4) # 1052

DIM = 256
SAMPLES = 300000

def mul(p, q):
    # produit modulo X^128+1
    z = np.convolve(p, q)  # length 255
    np.add(z[:127], -z[128:], out=z[:127])
    return z[:128]


def init():
    global DIM, SAMPLES, morphed, Linv

    t = time.time()
    sigs = np.load("/tmp/sigs.npy", allow_pickle=True)
    print("signatures loaded in %.2fs" % (time.time() - t))
    # on fait une grosse matrice contenant signature*2
    # 300000 * 256 * float64 => 614MB
    DIM = 256
    SAMPLES = len(sigs)
    V = np.zeros((len(sigs), DIM), dtype=np.float64)
    for i, (salt, s) in enumerate(sigs):
        V[i, :] = s[0] + s[1]
    V *= 2.0
    V = np.asmatrix(V)

    # On calcule la covariance
    cov = V.T * V
    cov *= 3 / SAMPLES
    print(cov.shape)
    print(cov)

    # Décomposition de Cholesky
    t = time.time()
    L = np.linalg.cholesky(np.linalg.inv(cov))
    # L * L.T = cov-1
    print(L)
    print("Cholesky computed in %.2fs" % (time.time() - t))

    morphed = V * L

    Linv = np.linalg.inv(L)
    MAGNITUDE = np.max(np.abs(Linv))
    print("L^-1 coefficient size =", int(MAGNITUDE))
    # < 100

def moment_grad(x):
    # <x,p> for p in samples
    dots = morphed * x.reshape((DIM, 1))
    # Sum p <x,p>³
    dots = np.array(dots).reshape(SAMPLES)
    cube = dots**3
    moment = float(np.dot(dots, cube))
    grad = cube.reshape((1, SAMPLES)) * morphed
    grad /= SAMPLES
    # projeter sur x _|_
    grad = np.array(grad).reshape(DIM)
    grad = grad - np.dot(grad, x) * x
    return moment / SAMPLES, grad


def descent(x):
    ng = 1e99
    for i in range(800):
        moment, g = moment_grad(x)
        # print(g.shape)
        ng = np.linalg.norm(g)
        if i < 10 or i % 10 == 0:
            print("iter", i, "|grad| = %.6g" % ng, end="")
            print(" moment = 0.2 + %.3g" % (moment - 0.2))
        dx = 0.8 * g
        x = np.array(x) - dx
        x /= np.linalg.norm(x)
        # Si le gradient est < 1e-8, les coefficients ne bougeront plus.
        if ng < 1e-8:
            break
    if ng > 1e-6:
        print("too slow, abort")
        return

    print("Reached minimum ?")
    # print(x)
    rev = x * Linv
    rev = np.array(rev).reshape(DIM)
    print("x =", [round(1000 * x) / 1000.0 for x in rev])
    candidate = np.round(rev).astype(np.int64)
    print("Integer candidate at distance %.2f" % np.linalg.norm(candidate - rev))
    # check a+bh = 0
    g = candidate[:128]
    f = -candidate[128:]
    print("candidate f =", list(f))
    print("candidate g =", list(g))
    rem = (g - mul(f, PUB)) % 769
    print("g-fh mod 769 =", rem)
    if np.sum(rem) != 0:
        print("fail")
        return
    f = [int(_w) for _w in f]
    g = [int(_w) for _w in g]
    print("GS norm", gs_norm(f, g, PRIME), "bound", MAX_NORM)
    try:
        F, G = ntru_solve(f, g)
        print("success")
        print("F =", F)
        print("G =", G)
        sys.exit(0)
    except:
        print("Fails NTRU test")


if __name__ == "__main__":
    init()
    for i in range(400):
        print("Trying start vector number", i + 1)
        x = np.random.random(DIM)
        x /= np.linalg.norm(x)
        descent(x)
```

