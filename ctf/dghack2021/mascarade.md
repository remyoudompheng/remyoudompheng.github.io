---
title: Mascarade
parent: DG'h4ck 2021
grand_parent: CTF writeups
---

Le but est d'extraire la valeur en clair du flag, étant
donné un petit serveur, accessible en TCP, qui en fournit
une version chiffrée suite à un protocole d'*échange de clés*.
(voir [le fichier source](ake_server.rs))

En pseudocode, on peut résumer le protocole de cette manière:
```
alice_static_public = constante connue
bob_static_secret = constante connue
alice_public = recv() # envoyé par le client
bob_secret = random()

s1 = DiffieHellman(bob_secret, alice_public)
s2 = DiffieHellman(bob_static_secret, alice_static_public)
s3 = DiffieHellman(bob_static_secret, alice_public)

key = Blake2b(s1 + s2 + s3)

send(ChachaPoly1305(key, flag, nonce=0))
```

On ne peut pas facilement (en théorie) connaître la valeur aléatoire
de `bob_secret`. En revanche, on sait que le calcul de `bob_secret × P`
dans la courbe elliptique donnera un résultat connu si P est le point
d'origine de la courbe.

On valide cette hypothèse avec quelques prints, en envoyant
la valeur nulle (32 octets NUL) pour `alice_public`:
```rust
println!("{:?}", shared_ephemeral_secret.as_bytes());
println!("{:?}", shared_static_secret.as_bytes());
println!("{:?}", shared_static_ephemeral_secret.as_bytes());
```
affiche
```
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
[59, 139, 168, 244, 116, 60, 183, 239, 4, 6, 177, 231, 69, 203, 243, 35, 102, 54, 215, 51, 237, 15, 14, 94, 72, 240, 16, 145, 127, 4, 1, 112]
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```
à chaque exécution.

On peut alors obtenir une clé de chiffrage connue:
```
[237, 144, 233, 44, 205, 221, 128, 139, 70, 139, 175, 158, 214, 183, 10, 215, 92, 60, 161, 229, 31, 91, 96, 99, 48, 71, 89, 201, 95, 70, 101, 219]
```

Il suffit alors d'écrire un petit client Python
```python

import socket
import Cryptodome.Cipher.ChaCha20_Poly1305 as chacha

s = socket.create_connection(("localhost", 7878))
s.recv(64)
# b'Hello Alice!\n'
s.sendall(b"Hello Bob!\n")
s.recv(64)
# bob_ephemereal_public
s.sendall(32 * b"\x00")
crypt = s.recv(64)
# b'\x96R\xa1\xdb`\xb1\x01\xe7\xba\x88\x1cSL\xb7\xb0\x8cz\x8d\xda\xfeC\xd7g_.u\xe6\xa8\x08\xc8\xf8v\x05w2\x86\x97\xa5\xc5~?u\x85\r\xcc=\x99\x05\x8a.\x89\x92]\xfb\x1a\x19'
key = bytes([237, 144, 233, 44, 205, 221, 128, 139, 70, 139, 175, 158, 214,
  183, 10, 215, 92, 60, 161, 229, 31, 91, 96, 99, 48, 71, 89, 201, 95, 70,
  101, 219])
nonce = 12 * b"\x00"
c = chacha.new(key=key, nonce=nonce)
print(c.decrypt(crypt))

```

