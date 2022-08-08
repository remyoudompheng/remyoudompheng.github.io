---
title: crypto/luckyguess
parent: corCTF 2022
grand_parent: CTF writeups
---

# Lucky guess

Category: crypto

Solves: 150

Points: 118

## Overview

We are asked to retrieve the flag from a server doing this:
```python
p = 2**521 - 1
a = getrandbits(521)
b = getrandbits(521)
print("a =", a)
print("b =", b)

try:
    x = int(input("enter your starting point: "))
    y = int(input("alright, what's your guess? "))
except:
    print("?")
    exit(-1)

r = getrandbits(20)
for _ in range(r):
    x = (x * a + b) % p

if x == y:
    print("wow, you are truly psychic! here, have a flag:", open("flag.txt").read())
```

# Solution

It is enough to send an invariant number.
The formula for that is `b/(1-a)`:
```python
x = (b * pow(1-a, -1, p)) % p
assert x == (a*x + b) % p
```

Then send the same number for x and y and get the flag:
```
corctf{r34l_psych1c5_d0nt_n33d_f1x3d_p01nt5_t0_tr1ck_th15_lcg!}
```
