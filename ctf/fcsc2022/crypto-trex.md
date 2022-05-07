---
title: Crypto — T-Rex
parent: FCSC 2022
grand_parent: CTF writeups
---

T-Rex
===

Il s'agit de déchiffrer un flag obtenu par le script suivant:

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class TRex:
	def __init__(self, key):
		N = len(key)
		M = 2 ** (8 * N)
		self.key = key
		self.iv = int.from_bytes(key, "big")
		R = lambda x: ((2 * x + 1) * x)
		for _ in range(31337):
			self.iv = R(self.iv) % M
		self.iv = int.to_bytes(self.iv, N, "big")

	def encrypt(self, data):
		E = AES.new(self.key, AES.MODE_CBC, iv = self.iv)
		return self.iv + E.encrypt(pad(data, 16))

if __name__ == "__main__":
	E = TRex(os.urandom(16))
	flag = open("flag.txt", "rb").read().strip()
	c = E.encrypt(flag)
	print(c.hex())

```

Le code indique que le vecteur d'initialisation a été obtenu
à partir de la clé en itérant 31337 fois la fonction
`x → x + 2x² mod 2^128`.

Cette fonction est inversible et on peut trouver ses préimages
facilement de façon itérative (c'est une fonction «triangulaire»
sur la représentation binaire).

On part de la valeur de `x` et tant que `x+2x²` ne vaut pas la bonne
valeur, on bascule le bit incorrect de poids le plus faible:
```python
M = 2**128
def Rinv(x):
    y = x
    while (y + 2 * y * y) % M != x:
        diff = (y + 2 * y * y) ^ x
        bit = ((diff ^ (diff - 1)) >> 1) + 1
        y ^= bit
    return y % M
```

On obtient ainsi la solution en une seconde (sur un ordinateur de bureau
standard):
```python
from Cryptodome.Cipher import AES

out = bytes.fromhex(...)
iv = int.from_bytes(out[:16], "big")
key = iv
for i in range(31337):
    key = Rinv(key)

keyb = key.to_bytes(16, "big")
msg = AES.new(keyb, AES.MODE_CBC).decrypt(out)
print(msg[16:].decode())
```
