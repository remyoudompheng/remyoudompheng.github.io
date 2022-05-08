---
title: Crypto — Khal Hash
parent: FCSC 2022
grand_parent: CTF writeups
---

Khal Hash
===

On demande de répondre à ce challenge:

```python
#!/usr/bin/env python3.9
try:
	flag = tuple(open("flag.txt", "rb").read())
	assert len(flag) == 70

	challenge = hash(flag)
	print(f"{challenge = }")

	T = tuple(input(">>> ").encode("ascii"))
	if bytes(T).isascii() and hash(T) == challenge:
		print(flag)
	else:
		print("Try harder :-)")
except:
	print("Error: please check your input")
```

Une chaîne ASCII est transformée en tuple d'entiers `b < 128`
et hachée avec la fonction `hash()` de Python. On sait que
le hash des entiers est lui-même et la fonction de hash des tuples
est définie dans le fichier source `Objects/tupleobject.c` de CPython.

Fonction de hash des entiers: [Objects/longobject.c](https://github.com/python/cpython/blob/v3.9.12/Objects/longobject.c#L3043)

Fonction de hash des tuples: [Objects/tupleobject.c](https://github.com/python/cpython/blob/v3.9.12/Objects/tupleobject.c#L330)

Voici une traduction en Python:
```python
P1 = 11400714785074694791
P2 = 14029467366897019727
P5 = 2870177450012600261
M = 2**64

def rotate(x):
    return (x >> 33) | (x << 31) & (M-1)

def pyhash(tup):
    x = P5
    for b in tup:
        x += P2 * b
        x &= M-1
        x = rotate(x)
        x *= P1
        x &= M-1
    x += (P5 ^ 3527539 ^ len(tup))
    return x & (M-1)
```

Comme la taille du hash est de 64 bits, et que la racine carrée
est `2^32` qui est abordable sur un ordinateur standard, on peut
tenter une attaque par le principe des anniversaires, de type
_meet-in-the-middle_ (les tours de hachage sont inversibles).

On calcule donc environ 2^32 résultats de la fonction de hash vers
l'avant, et environ autant, en partant de la cible choisie,
en appliquant la fonction à l'envers.

Pour accélérer l'attaque, on peut voir que si on divise par P2,
l'ajout d'un octet devient simplement `x += b`. On peut donc
"ignorer" l'octet du milieu qu'on complétera simplement avec la
différence.

On utilisera des tuples de longueur fixe 10 et le schéma suivant
```
P5 → Round(c1) → ... → Round(c5=a..h) → / P2 ⇒ R1
H → InvRnd(c10) → ... → InvRnd(c7) → / P1 → ROR(31) → / P2 ⇒ R2
```

Alors si `R1 + c6 = R2`, `H = hash((c1..c10))`.

Pour R1, on construit 2^31 possibilités (4x7+3).
Pour R2, on construit 2^28 possibilités (4x7).
Ce qui suffit largement à provoquer une collision sur 56 bits.

Le calcul étant intensif, on utilisera un programme en Go plutôt que
Python. Pour être économe en mémoire, on effectue la recherche en deux passes:

* Conserver uniquement les 34 bits de poids fort de R1 observés
  (une bitmap de 2GB suffit)
* Conserver une bitmap plus petite avec les collisions observées sur ces
  34 bits avec R2 et les entrées ayant produit ces R2 (quelques dizaines
  de millions, moins de 1GB)
* Régénérer les valeurs de R1 en effectuant une comparaison exacte
  sur les 64-7 bits de poids fort.

Code de la solution:
```go
package main

import (
    "fmt"
    "math/bits"
    "os"
    "strconv"
    "time"
)

const (
    P1 = 11400714785074694791
    P2 = 14029467366897019727
    P5 = 2870177450012600261

    P1inv = 614540362697595703   // pow(P1, -1, 2**64)
    P2inv = 839798700976720815   // pow(P2, -1, 2**64)
    P5inv = 14236653164957433613 // pow(P5, -1, 2**64)
)

func main() {
    challenge, err := strconv.ParseUint(os.Args[1], 10, 64)
    if err != nil {
        panic(err)
    }

    const BITMAP_SIZE = 34
    bitmap := make([]uint64, 1<<34/64)  // 2048MB
    bitmap2 := make([]uint64, 1<<32/64) // 512MB
    collisions := make(map[uint64][4]byte)
    // Forward map (31 bits)
    // P5 => round1 => round2 => round3 => round4 => round5 / P2 = A
    t0 := time.Now()
    h0 := uint64(P5)
    for c1 := uint64(0); c1 < 128; c1++ {
        if c1%8 == 0 {
            fmt.Println("c1 = ", c1)
        }
        h1 := round(h0, c1)
        for c2 := uint64(0); c2 < 128; c2++ {
            h2 := round(h1, c2)
            for c3 := uint64(0); c3 < 128; c3++ {
                h3 := round(h2, c3)
                for c4 := uint64(0); c4 < 128; c4++ {
                    h4 := round(h3, c4)
                    for c5 := 'a'; c5 <= 'h'; c5++ {
                        h5 := round(h4, uint64(c5))
                        mid := h5 * P2inv
                        mid >>= (64 - BITMAP_SIZE)
                        bitmap[mid/64] |= 1 << (mid % 64)
                    }
                }
            }
        }
    }
    fmt.Println("forward bitmap generated in", time.Since(t0).Round(time.Second/10))
    // Backward map (28 bits)
    // Challenge => round10inv => round9inv => round8inv => round7inv / P1 invrot / P2 = B
    t0 = time.Now()
    h10 := challenge - (10 ^ P5 ^ 3527539)
    for c10 := uint64(0); c10 < 128; c10++ {
        if c10%8 == 0 {
            fmt.Println("c10 = ", c10)
        }
        h9 := bits.RotateLeft64(h10*P1inv, 33) - c10*P2
        for c9 := uint64(0); c9 < 128; c9++ {
            h8 := bits.RotateLeft64(h9*P1inv, 33) - c9*P2
            for c8 := uint64(0); c8 < 128; c8++ {
                h7 := bits.RotateLeft64(h8*P1inv, 33) - c8*P2
                for c7 := uint64(0); c7 < 128; c7++ {
                    h6 := bits.RotateLeft64(h7*P1inv, 33) - c7*P2
                    // h6 == rotate(h5 + c6 * P2) * P1
                    // invrot(h6 * P1inv) * P2inv == h5 * P2inv + c6
                    mid := bits.RotateLeft64(h6*P1inv, 33) * P2inv
                    m := mid >> (64 - BITMAP_SIZE)
                    if bitmap[m/64]&(1<<(m%64)) != 0 {
                        collisions[mid>>7] = [4]byte{byte(c7), byte(c8), byte(c9), byte(c10)}
                        bitmap2[mid>>32/64] |= 1 << ((mid >> 32) % 64)
                    }
                }
            }
        }
    }
    fmt.Println("backward bitmap generated in", time.Since(t0).Round(time.Second/10))
    fmt.Println(len(collisions), "possible collisions")

    // Forward map (31 bits)
    // Resolve A + c6 == B
    t0 = time.Now()
    h0 = uint64(P5)
Loop:
    for c1 := uint64(0); c1 < 128; c1++ {
        if c1%8 == 0 {
            fmt.Println("c1 = ", c1)
        }
        h1 := round(h0, c1)
        for c2 := uint64(0); c2 < 128; c2++ {
            h2 := round(h1, c2)
            for c3 := uint64(0); c3 < 128; c3++ {
                h3 := round(h2, c3)
                for c4 := uint64(0); c4 < 128; c4++ {
                    h4 := round(h3, c4)
                    for c5 := 'a'; c5 <= 'h'; c5++ {
                        h5 := round(h4, uint64(c5))
                        mid := h5 * P2inv
                        // check bitmap (fast path)
                        m := mid >> 32
                        if (bitmap2[m/64]>>(m%64))&1 == 0 {
                            continue
                        }
                        // check map
                        if tail, ok := collisions[mid>>7]; ok {
                            for c6 := uint64(0); c6 < 128; c6++ {
                                word := [10]byte{
                                    byte(c1), byte(c2), byte(c3), byte(c4),
                                    byte(c5), byte(c6), tail[0], tail[1],
                                    tail[2], tail[3]}
                                if hash(word[:]) == challenge {
                                    fmt.Printf("%q => %d\n", word[:], challenge)
                                    break Loop
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fmt.Println("explored collisions in", time.Since(t0).Round(time.Second/10))
}

func hash(s []byte) uint64 {
    h := uint64(P5)
    for _, b := range s {
        h = round(h, uint64(b))
    }
    h += uint64(len(s)) ^ P5 ^ 3527539
    return h
}

func round(acc uint64, c uint64) uint64 {
    acc += c * P2
    acc = bits.RotateLeft64(acc, 31)
    acc *= P1
    return acc
}
```

Solution en 2 minutes
```
$ go run khalhash-solve.go 123456789
c1 =  0
...
c1 =  120
forward bitmap generated in 1m33.3s
c10 =  0
...
c10 =  120
backward bitmap generated in 25.5s
31270957 possible collisions
c1 =  0
c1 =  8
c1 =  16
c1 =  24
"\x1at\x14:e\a#4d{" => 123456789
explored collisions in 11.8s

$ python
>>> hash(tuple(b"\x1at\x14:e\a#4d{"))
123456789
```
