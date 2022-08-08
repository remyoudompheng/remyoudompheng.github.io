---
title: crypto/generous
parent: corCTF 2022
grand_parent: CTF writeups
---

{%- include mathjax.html -%}

# Generous

Category: crypto

Solves: 49

Points: 163

## Overview

We are given a 1-bit oracle implemented as follows:
```python
def gen_keypair():
	p, q = getPrime(512), getPrime(512)
	n = (p**2) * q
	while True:
		g = randrange(2, n)
		if pow(g, p-1, p**2) != 1:
			break
	h = pow(g, n, n)
	return (n, g, h), (g, p, q)

def encrypt(pubkey, m):
	n, g, h = pubkey
	r = randrange(1, n)
	c = pow(g, m, n) * pow(h, r, n) % n
	return c

def decrypt(privkey, c):
	g, p, q = privkey
	a = (pow(c, p-1, p**2) - 1) // p
	b = (pow(g, p-1, p**2) - 1) // p
	m = a * inverse(b, p) % p
	return m

def oracle(privkey, c):
	m = decrypt(privkey, c)
	return m % 2

pub, priv = gen_keypair()
n, g, h = pub
print(f"Public Key:\n{n = }\n{g = }\n{h = }")
print(f"Encrypted Flag: {encrypt(pub, bytes_to_long(flag))}")
while True:
	inp = int(input("Enter ciphertext> "))
	print(f"Oracle result: {oracle(priv, inp)}")
```

## LSB oracle attack

The situation is typical of a **LSB oracle**.

See an example here:
[https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack](
https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack)

In this case, the technique is well-known and relies on the following
simple property: if $$ 0 < x < p $$ where $$ p $$ is an odd number,
then $$ 2x \mod p $$ is odd if and only if $$ x < p/2 $$.

Let's see how it can be applied here: we can observe that decryption
computes powers modulo p².

This is a group morphism:

$$ \mathbb Z / p \mathbb Z \to (\mathbb Z / p^2 \mathbb Z)^{\times p-1} $$

$$ a \to 1 + ap  $$

$$ \frac{x - 1} {p} \leftarrow x $$

So using squares modulo $$ p^2 $$ is equivalent to computing the double
modulo $$ p $$ through `decrypt`.

The following function is also a group morphism:

$$ D: x \in (\mathbb Z / p^2 \mathbb Z)^\times \to
   \frac{x^{p-1} - 1} {p} \in \mathbb Z / p \mathbb Z $$

So we have the following identities:

```
decrypt(ct) = D(ct) / D(g) = flag
decrypt(ct**2) = D(ct**2) / D(g) = (2 * flag) % p
...
decrypt(ct**(2**k)) = D(ct**(2**k)) / D(g) = (2**k * flag) % p
```

The recovery through a LSB oracle attack can be formulated mathematically
like this: write the fraction with binary digits

$$ \frac k p = 0.b_0 b_1 b_2 ... b_i ... $$

Then $$ b_i = 0 $$ means that $$ (2^i k) \mod p < p / 2 $$.

## Solution

The above remarks say that bit $$ b_i $$ is exactly what the oracle
will return for input $$ \text{pow}(ct, 2^{i + 1}) $$.

We are now ready to perform the attack: send iterated squared
of the encrypted flag to the oracle, which gives the binary
digits of `flag / p`.

Once we have 1024 bits (twice the size of $$ p $$),
recovery of `flag` and $$ p $$ is instantaneous via
continued fraction expansion.

As a bonus, you obtain the factorization of n, which is supposed to be
secret.

```python
from telnetlib import Telnet
from sage.all import Integer, continued_fraction, QQ
from tqdm import tqdm

c = Telnet("be.ax", 31244)
while True:
    line = c.read_until(b"\n").decode()
    if "n =" in line:
        n = int(line.strip().split()[-1])
    elif "Flag:" in line:
        ct = int(line.strip().split()[-1])
        break
c.read_until(b"ciphertext> ")
print("n =", n)
print("ct =", ct)

def oracle(x: int):
    c.write(str(x).encode() + b"\n")
    line = c.read_until(b"\n").decode()
    if " 1" in line:
        return 1
    else:
        return 0

x = ct
bits = []
for k in tqdm(range(1024)):
    x = (x*x)%n
    bit = oracle(x)
    bits.append(bit)
assert len(bits) == 1024

num = sum(b * 2**(1023-i) for i, b in enumerate(bits))
cf = continued_fraction(QQ(num) / QQ(2**1024))
for f in cf.convergents():
    a = int(f.numerator())
    b = int(f.denominator())
    if Integer(b).is_prime() and b.bit_length() == 512:
        print("p =", b)
        p = b
        print("msg =", a.to_bytes(50, "big"))
assert n % (p*p) == 0
print("factors of n")
print(p)
print(p)
print(n // (p*p))
```

Sample output:
```
n = 382117011456038221410328128694247757137353385107547801442167291131692445852014961496469548870495011643760778373587709173975160132235045978364230956321392904471020451180820926376747259091050543730341148327632684981188263791129579200368138856381929113409794029012000320474376470150687073962615837765648041859285189924224283209636208026411187069739227898055436888993780781402409999497594918931116218946800189439759957832363606985734064197275299815137081256276457029
ct = 271753346662223698656541527251751086596940663599841631819308477578779722575767529958891723115984896269515872561634903533906633582535866141422430833815043550342342875281297721342898166627108970884433029990644228835812182108300055219312582374571224646085836164020700223063875190530313800522997657148612308347775168295194074555835808881679815362111109422376032772976194513560325870259003895119412599834545250788898041644373126535831044731963613182511717154097515770

p = 7258573487882539665926275836350292713078118035457370786331051440423991926454774476573264628112748782660143038376984025079745626790021928165265635381408613
msg = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00corctf{see?1_bit_is_very_generous_of_me}'
factors of n
7258573487882539665926275836350292713078118035457370786331051440423991926454774476573264628112748782660143038376984025079745626790021928165265635381408613
7258573487882539665926275836350292713078118035457370786331051440423991926454774476573264628112748782660143038376984025079745626790021928165265635381408613
7252601513123043187053932535843576998053006908527140935039474417071226993304660873821734957206089942267083251155543184940978473308477755352245953699902541
```
