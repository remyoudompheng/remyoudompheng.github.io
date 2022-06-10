---
title: Cryptanalyse — Dégâts collatéraux
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

# Dégâts collatéraux

```
Bonjour Agent,

Nous avons réussi à infiltrer une connexion sécurisée d'Hallebarde via
une attaque MITM. Malheureusement, cette connexion est chiffrée via un
protocole qui semble très similaire à PGP, et même si nous avons un
certain contrôle sur les informations qui transitent, nous n'avons pas
réussi à exploiter notre position. Nous vous avons résumé tout ce que
nous avons compris du fonctionnement de cette session dans le fichier
ci-joint. Il nous manque quelques détails, mais il doit être presque
complet. Voyez si vous pouvez faire quelque chose !

Auteur : Alternatif#7526
nc challenge.404ctf.fr 30762
```

Thématique: Cryptanalyse
Difficulté: Extrême

## Description

Le challenge est fourni sous la forme d'un script Python
qui implémente un chiffrement de type ElGamal
(https://en.wikipedia.org/wiki/ElGamal_encryption)

On définit une clé de type DSA: un grand nombre premier `p`,
un générateur `g`, un exposant secret `x`.
```
def genkey():
    p = ...
    g = randint(2, p)
    x = getrandbits(1024)
    y = pow(g, x, p)
    return ((g, p, y), x)
```

Et on tire aléatoirement une clé de session:
```
def create_session( plaintext, pubkey ):
    while True:
        sess_key = urandom(16)
        if is_session_key_valid(sess_key):
            break
    aes = AES.new(sess_key, AES.MODE_CBC, iv=iv)
    cipher = aes.encrypt(pad(plaintext, 16))
    ciphered_key = EGEncrypt(sess_key, pubkey)
    return cipher, ciphered_key, sess_key

def EGEncrypt( m, pubkey ):
    g, p, y = pubkey
    k = randint(2, p - 2)
    c0 = pow(g, k, p)
    c1 = (bytes_to_long(pad(m, 16)) * pow(y, k, p))
    return (c0, c1)

def is_session_key_valid( session_key ):
    if len(session_key) == 16 and sum(session_key) % 31 == 0:
        return True
    return False
```

Le serveur implémente un oracle et il est possible de customiser
tous les arguments fournis à l'oracle.
```
def EGDecrypt( c0, c1, g, p, x ):
    m1 = (c1 * pow(c0, -x, p)) % p
    m = unpad(long_to_bytes(m1), 16)
    return m

def oracle( pubkey, privkey, cipher, ciphered_key ):
    g, p, y = pubkey
    if p.bit_length() != 2049:
        return "Erreur: le module ne fait pas 2049 bits"
    c0, c1 = ciphered_key
    try:
        key2 = EGDecrypt(c0, c1, g, p, privkey)
    except:
        return "Erreur dans le déchiffrement, le fichier est peut-être corrompu"
    if not (is_session_key_valid(key2)):
        return "Erreur dans le déchiffrement, le fichier est peut-être corrompu"
    # Il semble qu'arrivé ici le serveur qui gère l'oracle lance d'autres fonctions / processus, mais nous n'avons pas
    # pu déterminer quoi
    ...
```

## Analyse du comportement

Le serveur tire au hasard un clé secrète et une clé de session chiffrée,
puis donne accès à l'oracle.

Par défaut, l'oracle va se lancer sur la clé choisie et répond après
environ une seconde.

Si on customise les entrées en mettant des nombres au hasard
on voit que l'oracle répond immédiatement
"Erreur dans le déchiffrement".

On en déduit la logique suivante:
* si le déchiffrement réussit et que la clé de session est valide
  la réponse revient en une seconde
* sinon, la réponse revient très vite

## Stratégie d'attaque

On a un vecteur d'attaque qui ressemble aux problèmes de type
_padding oracle_.

On va essayer d'obtenir les bits de la clé progressivement.

Pour cela il faut réussir à construire des entrées qui produisent
une clé de session valide.

On se fixe une clé de session `m` précise:
```
m = bytes.fromhex("08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18")
mpad = pad(m, 16)
```

Pour passer le test de l'oracle on peut envoyer des nombres c0, c1, p
avec l'équation:
```
# x est secret dans le serveur
(c1 * pow(c0, -x, p)) % p == bytes_to_long(mpad)
```

Mais si `c0**2 % p == 1`, `pow(c0, x, p) == pow(c0, x%2, p)`
ce qui permet d'extraire le LSB de x en choisissant correctement
`c0` et `c1`.

Pour se simplifier la vie, on va travailler avec `p = 2**2048`
il n'est pas premier mais il est de la bonne taille (2049 bits)
et il a l'avantage de proposer des calculs rapides:
`pow(1 + (x<<1024), y, p) == 1+(x*y)<<1024`

## Extraction du bit de poids faible

Dans les formules précédentes, on choisit donc:
```
m = bytes.fromhex(...)
M = bytes_to_long(pad(m, 16))

p = 2**2048
c0 = 1 + (1<<shift)
c1 = M * pow(c0, x, p)
```

Avec le padding, le nombre M est de la forme
`0x08090a...10101010` qui est multiple de 16,
on va donc "perdre" 4 bits de poids fort dans la multiplication par M.

Pour le premier bit on choisit:
```
p = 2**2048
c0 = 1 + (1<<2043)
c1 = M * pow(c0, x, p)
```

Il n'y a que deux possibilités pour x parce que
```
16*pow(c0, 1, p) = 16 + (1<<2047)
16*pow(c0, 2, p) = 16
16*pow(c0, 3, p) = 16 + (1<<2047)
etc.
```

En envoyant au serveur ces deux possibilités de `(c0, c1)`
on peut savoir si le LSB de x est 0 ou 1.

De manière générale, si on choisit:
```
p = 2**2048
c0 = 1 + (1<<(2047 - L - 4))
c1 = M * pow(c0, x, p)
```
seuls les L bits de poids faible de x comptent. Donc si on connaît
déjà une partie de x, on peut tester les différentes possibilités sur le
serveur.

## Implémentation finale

Pour aller un peu plus vite, on teste les bits par groupe de 4
(une seconde c'est long).
Et voilà le script en Python:
```
import time
from pwn import remote, log
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Calculs
testmsg = bytes(range(8, 24))
assert len(testmsg) == 16
assert sum(testmsg) % 31 == 0
targetN = bytes_to_long(pad(testmsg, 16))
assert unpad(long_to_bytes(targetN), 16) == testmsg
Mod = 2**2048

def compute_c1(c0, x):
    return (targetN * pow(c0, x, Mod)) % Mod

s = remote("challenge.404ctf.fr", 30762)
# Intro
s.recvuntil(b"en question:\n")
ciph = s.recvline()
ciph = ciph.decode().strip()
log.info(f"Chiffré: {ciph}")
# Paramètres (g, p, y) on les ignore
s.recvline()
str_g = s.recvline().decode()
str_p = s.recvline().decode()
str_x = s.recvline().decode()
# Fausse clé
fake_key = f"(1, {Mod}, 1)"


STEP = 4
key = 0
start = time.time()
for idx in range(260):
    expsize = STEP * (idx + 1)
    c0 = 1 + (1 << (2048 - expsize - 4))
    candidate = 0
    for k in range(1 << STEP):
        candidate = key + (k << (STEP * idx))
        c1 = compute_c1(c0, candidate)

        l = s.recv(800)
        # log.info(str(l))
        s.sendline(fake_key.encode())
        l = s.recvuntil(b"\n>")
        # log.info(l)
        s.sendline(f"({c0}, {c1})".encode())
        s.recvuntil(b"\n>")
        t = time.time()
        s.send(b"\n")
        s.recvuntil(b"corrompu")
        dt = time.time() - t
        if dt > 0.8:
            total = time.time() - start
            log.info(
                f"hex[{idx}]={k:x} oracle {dt:.2f}s ({expsize} bits, écoulé {total:.2f}s)"
            )
            key = candidate
            log.info(f"current guess: 0x{key:x}")
            break
    if key != candidate:
        log.error("FAIL")
# copié de session.py
def decrypt_flag(enc, x):
    hash = SHA256.new(data=long_to_bytes(x)).digest()
    aes = AES.new(hash[:16], AES.MODE_CBC, iv=hash[16:32])
    plaintext = unpad(aes.decrypt(bytes.fromhex(enc)), 16)
    return plaintext

print(decrypt_flag(ciph, key))
```
