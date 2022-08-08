---
title: crypto/corrupted-curves
parent: corCTF 2022
grand_parent: CTF writeups
---

{%- include mathjax.html -%}

# Corrupted curves

Category: crypto:

Solves: 20

Points: 245

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
while count < 64:
    x = int(input("x = ")) % p
    if int(x) in checked or x < 2**384 or abs(x - p) < 2**384:
        print(">:(")
        continue
    e = randbits(64)
    print(f"e = {e}")
    try:
        E = EllipticCurve(p, a^e, b^e)
        py = E.lift_x(x)
        checked.add(int(x))
        print(f"y = {py}")
        count += 1
    except:
        print(":(")
print("bye!")
```

## Strategy

To handle this challenge, we have to know that this is not SAGE syntax,
but regular Python, so operator `^` is the regular bitwise XOR.

So let's write:

$$ a \oplus e = a + e - \epsilon_a $$

Since `e` is small, we can attempt a LLL-based solution.

What happens if we have 3 samples from the server?

$$ y^2 = x^3 + a x + e x - \epsilon_a x + b + e - \epsilon b $$

We can eliminate `b` using 2 samples:

$$ M_i = x_i^3 + e_i x_i + e_i - y_i^2 $$

$$ -M_i = a x_i - \epsilon_a x_i + b - \epsilon_b $$

$$ M_0 - M_i = a (x_0 - x_i) + \epsilon_{0,a} x_0 - \epsilon_{i,a} x_i
 + \epsilon_{0,b} - \epsilon_{1,b} $$

We can use this to solve for `a` using LLL:
the unknowns are `a`, `e_0,a`, `e_i,a`
and several multiples of `p` because equation is modulo `p`.

We expect a linear combination to be of size 64 bits.

```python
def guess(p, results):
    # Generate many vectors:
    # (M, u, w)
    # such that: a u + small x0 + small w + epsilon = kp + M
    e0, x0, y0 = results[0]
    M0 = x0**3 + e0 * x0 + e0 - y0**2

    vectors = []
    for i in range(1, len(results)):
        ei, xi, yi = results[i]
        Mi = xi**3 + ei * xi + ei - yi**2
        vectors.append((M0 - Mi, xi - x0, xi))

    N = len(vectors)
    M = Matrix(QQ, 3*N+2, 3*N+2)
    for i in range(N):
        M[0,i] = vectors[i][1]
    M[0,3*N+1] = 1 / QQ(2**384)
    for i in range(N):
        M[i+1,i] = x0
        M[i+1,N+i] = 1 # coefficient must be small
    for i in range(N):
        M[i+1+N,i] = vectors[i][2]
        M[i+1+N,2*N+i] = 1 # coefficient must be small
    for i in range(N):
        M[i+1+2*N,i] = p
    for i in range(N):
        M[3*N + 1,i] = -vectors[i][0]
    M[3*N + 1, 3*N] = 2**64 # force coefficient of M to be 1

    M = M.LLL()
    for i in range(3*N+2):
        M[i,3*N+1] *= 2**384

    r = M.row(1)
    aguess = abs(r[-1])
    return aguess
```

On simulated results this gives an estimate of `a` up to a 64-bit error.

Now that we have the estimate of `a`, we can get more by trying to solve
for `b`. Since all points must have the same b, and a small error on
`a` gives larges changes in values, this gives additional information on
`a` (even with only 2 equations, any error in `a` will make solutions
impossible).

$$ y^2 = x^3 + a x + (e-\epsilon_a) x + b + e - \epsilon b $$

This time solve for `e-e_a` and `b`.

```python
def solve(p, results, aguess):
    N = 2 # or len(results)
    M = Matrix(QQ, 2*N+2, 2*N+2)
    for i in range(N):
        e, x, y = results[i]
        # term y^2 - x^3 - a x
        M[0, i] = (y**2 - x**3 - aguess * x) % p
        # term b
        M[1, i] = 1
        # term p
        M[2+i, i] = p
        # term 2(a&e) x => not always the same!
        M[2+i+N, i] = x
        M[2+i+N, i+N] = 1 # force small coefficient

    M[0, 2*N] = 2**64 # only 1x the large term
    M[1, 2*N+1] = 1 / QQ(2**384)

    M = M.LLL()
    for i in range(2*N+1):
        M[i,2*N+1] *= 2**384

    r = M.row(1)
    bguess = abs(r[-1])

    # Now consider result 0
    e0, x0, y0 = results[0]
    ae = r[N]
    # y^2 = x^3 + a x + ae * x + bguess + small
    aguess2 = Integer(aguess+ae) ^^ Integer(e0)
    # y^2 = x^3 + (a^e) x + (b^e)
    bguess2 = (y0**2 - x0**3 - (Integer(aguess2) ^^ Integer(e0)) * x0) % p
    bguess2 = bguess2 ^^ Integer(e0)
    return aguess2, bguess2
```

It can be checked on simulations that this works.

Now connect to the server to retrieve 3 points, solve for `a` and `b`
and obtain the flag:
```
corctf{i_h0pe_you_3njoyed_p1ecing_t0geth3r_th4t_curv3_puzz1e_:)}
```
