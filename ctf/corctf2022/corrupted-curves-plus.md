---
title: crypto/corrupted-curves+
parent: corCTF 2022
grand_parent: CTF writeups
---

# Corrupted curves +

Category: crypto

Solves: 15

Points: 281

## Overview

We are given access to a remote server with the
following code

```python
print("Generating parameters...")
while True:
    p = getPrime(512)
    a, b = randbits(384), randbits(384)
    try:
        E = EllipticCurve(p, a, b)
        fy = E.lift_x(flag)
        print(f"p = {p}")
        print(f"flag y = {fy}")
        break
    except:
        continue
checked = set()
count = 0
while count < 2022:
    x = randrange(2, p)
    if int(x) in checked or x < 2**384 or abs(x - p) < 2**384:
        print(">:(")
        continue
    try:
        e = randbits(48)
        print(f"e = {e}")
        E = EllipticCurve(p, a^e, b^e)
        py = E.lift_x(x)
        checked.add(x)
        print(f"x = {x}")
        print(f"y = {py}")
        count += 1
    except:
        print(":(")
    more = input("more> ")
    if more.strip() == "no":
        break
print("bye!")
```

This can be solved using the solver for
[corrupted-curves](corrupted-curves)

Again, only 3 outputs are required to make it work.
