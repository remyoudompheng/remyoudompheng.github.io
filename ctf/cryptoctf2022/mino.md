---
title: Mino
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

{%- include mathjax.html -%}

# Mino

Catégorie: medium

Points: 169

Résolutions: 23

## Énoncé

You cannot have a good cryptosystem without mathematics! This task is an
easy coding system!

```
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Hi crypto programmers! I'm looking for some very special permutation |
| p name MINO such that sum(p(i) * (-2)^i) = 0 from 0 to n - 1, for    |
| example for n = 6, the permutation p = (4, 2, 6, 5, 3, 1) is MINO:   |
| 4*(-2)^0 + 2*(-2)^1 + 6*(-2)^2 + 5*(-2)^3 + 3*(-2)^4 + 1*(-2)^5 = 0  |
| In each step find such permutation and send to server, if there is   |
| NOT such permutation for given n, just send `TINP', good luck :)     |
||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
| Send a MINO permutation of length = 3 separated by comma: 
```

```python
#!/usr/bin/env python3

import sys
from flag import flag

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
    pr(border, "Hi crypto programmers! I'm looking for some very special permutation", border)
    pr(border, "p name MINO such that sum(p(i) * (-2)^i) = 0 from 0 to n - 1, for   ", border)
    pr(border, "example for n = 6, the permutation p = (4, 2, 6, 5, 3, 1) is MINO:  ", border)
    pr(border, "4*(-2)^0 + 2*(-2)^1 + 6*(-2)^2 + 5*(-2)^3 + 3*(-2)^4 + 1*(-2)^5 = 0 ", border)
    pr(border, "In each step find such permutation and send to server, if there is  ", border)
    pr(border, "NOT such permutation for given n, just send `TINP', good luck :)    ", border)
    pr(border*72)
    step, final = 3, 40
    while True:
        pr(border, f"Send a MINO permutation of length = {step} separated by comma: ")
        p = sc().split(',')
        if step % 3 == 1:
            if p == ['TINP']:
                if step == final: die(border, f"Congrats, you got the flag: {flag}")
                else:
                    pr(border, "Great, try the next level :)")
                    step += 1
            else:
                die(border, "the answer is not correct, bye!!!")
        elif len(p) == step:
            try:
                p = [int(_) for _ in p]
            except:
                pr(border, "the permutation is not valid")
            if set(p) == set([_ for _ in range(1, step + 1)]):
                S = 0
                for _ in range(step):
                    S += p[_] * (-2) ** _
                if S == 0:
                    if step == final: 
                        die(border, f"Congrats, you got the flag: {flag}")
                    else:
                        pr(border, "Great, try the next level :)")
                        step += 1
                else:
                    die(border, "the answer is not correct, bye!!!")
            else:
                pr(border, "the permutation is not valid!!!")
        else:
            die(border, f"the length of permutation is not equal to {step}")

if __name__ == "__main__":
    main()
```

## Analyse

Le serveur nous demande de fournir pour tout `n = 3..40` une permutation
des entiers `(1, 2, ..., n)` telle que

$$ \sum_{i=1}^n p_i (-2)^i = 0 $$

Le code source nous donne une indication: il n'y a pas de solution si
`n % 3 == 1`. On peut comprendre facilement pourquoi en calculant modulo
3:

$$ \sum_{i=1}^n p_i (-2)^i = \sum_{i=1}^n p_i = \frac{n(n+1)}{2} = 1 \neq 0 $$

Observons expérimentalement ce qui se passe pour de petites valeurs de
`n`

```python
for n in (3,5,6,8):
    print("=== LENGTH", n, "===")
    G = SymmetricGroup(n)
    c = 0
    for g in G:
        t = g.tuple()
        if sum(t[i] * (-2)**i for i in range(n)) == 0:
            print(t)
            c += 1
```

```
=== LENGTH 3 ===
(2, 3, 1)
=== LENGTH 5 ===
(2, 3, 5, 4, 1)
(2, 5, 4, 3, 1)
=== LENGTH 6 ===
(2, 3, 5, 6, 4, 1)
(4, 2, 6, 5, 3, 1)
(2, 5, 4, 1, 6, 3)
(6, 3, 2, 5, 4, 1)
(6, 5, 3, 1, 4, 2)
(6, 1, 3, 4, 5, 2)
(6, 1, 5, 3, 4, 2)
(2, 5, 6, 4, 3, 1)
(4, 2, 6, 1, 5, 3)
=== LENGTH 8 ===
(2, 5, 4, 1, 6, 7, 8, 3)
(8, 4, 2, 1, 6, 5, 7, 3)
(6, 3, 4, 8, 1, 5, 7, 2)
(2, 5, 4, 1, 8, 6, 7, 3)
(8, 2, 3, 6, 4, 7, 5, 1)
```

## Construction de solutions

On constate que certaines solutions semblent «apparentées»
Par exemple:

```
(2, 3, 1) <=> (2, 3, 5, 4, 1)

(2, 3, 5, 4, 1) <=> (2, 3, 5, 6, 4, 1)

(2, 5, 4, 1, 6, 3) <=> (2, 5, 4, 1, 6, 7, 8, 3)
(4, 2, 6, 5, 3, 1) <=> (4, 2, 6, 7, 8, 5, 3, 1)
```

Ce qui suggère l'existence d'un procédé pour «agrandir» une solution de
taille `n` en une solution de taille `n+1` ou `n+2`.

Calculons l'effet de l'insertion de `n+1` sur une solution:

$$ S(p_1, .., p_n) = \sum_{i=1}^n p_i (-2)^i = 0 $$

Après insertion:

$$ \sum_{i=1}^{k-1} p_i (-2)^i + (n+1) (-2)^k + \sum_{i=k}^n p_i (-2)^{i+1} $$

$$ = - \sum_{i=k}^n p_i (-2)^i + (n+1) (-2)^k + \sum_{i=k}^n p_i (-2)^{i+1} $$

$$ = (-2)^k \Big( (n+1) + \sum_{i=k}^n p_i (-2)^{i+1-k} - \sum_{i=k}^n p_i (-2)^{i-k} \Big) $$

$$ = (-2)^k \Big( (n+1) - 3 \sum_{i=k}^n p_i (-2)^{i-k} \Big) $$

Ainsi l'insertion de `n+1` préserve la propriété si et seulement si:

$$ S(p_k, ..., p_n) = \frac{n+1}{3} $$

De même examinons le cas de l'insertion de `(n+1, n+2)`:

$$ \sum_{i=1}^{k-1} p_i (-2)^i + (n+1) (-2)^k + (n+1) (-2)^{k+1} + \sum_{i=k}^n p_i (-2)^{i+2} $$

$$ = - \sum_{i=k}^n p_i (-2)^i + (n+1) (-2)^k + (n+2) (-2)^{k+1} + \sum_{i=k}^n p_i (-2)^{i+2} $$

$$ = (-2)^k \Big( -(n+3) + \sum_{i=k}^n p_i (-2)^{i+2-k} - \sum_{i=k}^n p_i (-2)^{i-k} \Big) $$

$$ = (-2)^k \Big( -(n+3) + 3 \sum_{i=k}^n p_i (-2)^{i-k} \Big) $$

Ainsi l'insertion de `(n+1, n+2)` préserve la propriété si et seulement si:

$$ S(p_k, ..., p_n) = \frac{n+3}{3} $$

## Solution

On construit les solutions récursivement en partant de la solution
`(2, 1)` ou `(2, 3, 1)` avec les opérations:

* si `n = 3k+2` on insère `n+1` en `i` si `S(p_i, ..., p_n) = k+1`
* si `n = 3k` on insère `n+1, n+2` en `i` si `S(p_i, ..., p_n) = k+1`

```python
def sum_(t):
    return sum(t[i] * pow(-2, i) for i in range(len(t)))

def children(t):
    n = len(t)
    if n % 3 == 2:
        k = (n+1)//3
        for i in range(n):
            if sum_(t[-i:]) == k:
                child = t[:-i] + [3*k] + t[-i:]
                assert sum_(child) == 0
                yield child
    else:
       k = n//3
       for i in range(n):
           if sum_(t[-i:]) == k:
               child = t[:-i] + [3*k+2, 3*k+1] + t[-i:]
               assert sum_(child) == 0
               yield child
           elif sum_(t[-i:]) == k + 1:
               child = t[:-i] + [3*k+1, 3*k+2] + t[-i:]
               assert sum_(child) == 0
               yield child

p = [2, 3, 1]
assert sum_(p) == 0
print(",".join(str(n) for n in p))
print("TINP")
for i in range(40):
    p = next(children(p))
    print(",".join(str(n) for n in p))
    if len(p) % 3 == 0:
        print("TINP") # for len(p)+1
    if len(p) == 39:
        break
```

On obtient la suite de solutions:
```
2,3,1
TINP
2,3,5,4,1
2,3,5,6,4,1
TINP
2,3,5,6,8,7,4,1
2,3,5,6,8,9,7,4,1
TINP
2,3,5,6,8,9,11,10,7,4,1
2,3,5,6,8,9,11,12,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,19,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,22,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,22,19,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,25,22,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,25,22,19,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,28,25,22,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,28,25,22,19,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,32,31,28,25,22,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,32,33,31,28,25,22,19,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,32,33,35,34,31,28,25,22,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,32,33,35,36,34,31,28,25,22,19,16,13,10,7,4,1
TINP
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,32,33,35,36,38,37,34,31,28,25,22,19,16,13,10,7,4,1
2,3,5,6,8,9,11,12,14,15,17,18,20,21,23,24,26,27,29,30,32,33,35,36,38,39,37,34,31,28,25,22,19,16,13,10,7,4,1
TINP
# Congrats, you got the flag: CCTF{MINO_iZ_4N_3a5Y_Crypto_C0d!n9_T4sK!}
```
