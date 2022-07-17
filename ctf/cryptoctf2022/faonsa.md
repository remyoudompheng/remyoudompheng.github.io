---
title: Faonsa
parent: CryptoCTF 2022
grand_parent: CTF writeups
---

# Faonsa

Catégorie: medium

Points: 180

Résolutions: 21

## Énoncé

Deploying the fault attack in real life is hard, we deployed it artificially!

```python
from Crypto.Util.number import *
from math import gcd
import sys
from flag import flag

def diff(a, b):
    assert a.bit_length() == b.bit_length()
    w, l = 0, a.bit_length()
    for _ in range(l):
        if bin(a)[2:][_] != bin(b)[2:][_]: w += 1
    return w

def sign_esa(pubkey, x, m):
    g, p, y = pubkey
    while True:
        k = getRandomRange(2, p-1)
        if gcd(k, p-1) == 1:
            break
    u = pow(g, k, p)
    v = (m - x * u) * inverse(k, p - 1) % (p - 1)
    return (u, v)

def verify_esa(pubkey, sgn, m):
    g, p, y = pubkey
    u, v = sgn
    return pow(y, u, p) * pow(u, v, p) % p == pow(g, m, p)

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
    pr(border, "Hello guys! This is a another challenge on fault attack too, again  ", border)
    pr(border, "our storage could apply at most `l' bit fault on ElGamal modulus, p,", border)
    pr(border, "try to sign the given message and get the flag! Have fun and enjoy!!", border)
    pr(border*72)
    pr(border, "Generating the parameters, it's time consuming ...")
    nbit = 256
    while True:
        _p = getPrime(255)
        p = 2 * _p + 1
        if isPrime(p):
            g = 2
            if pow(g, _p, p) != 1: break
            else: g += 1
    x = getRandomRange(2, p // 2)
    y = pow(g, x, p)

    B, l = [int(b) for b in bin(p)[2:]], 30
    
    MSG = "4lL crypt0sy5t3ms suck5 fr0m faul7 atTaCk5 :P"
    m = bytes_to_long(MSG.encode('utf-8'))

    while True:
        pr("| Options: \n|\t[A]pply fault \n|\t[G]et the parameters \n|\t[S]ign the message \n|\t[V]erify the signature \n|\t[Q]uit")
        ans = sc().lower()
        if ans == 'a':
            _B = B
            pr(border, f"please send at most {l}-tuple array from indices of bits of ElGamal modulus, like: 5, 12, ...")
            ar = sc()
            try:
                ar = [int(_) for _ in ar.split(',')]
                if len(ar) <= l:
                    for i in range(len(ar)): _B[ar[i]] = (_B[ar[i]] + 1) % 2
                    P = int(''.join([str(b) for b in _B]), 2)
                    Y = pow(g, x, P)
                else: raise Exception('Invalid length!')
            except: pr(border, "Something went wrong!!")
        elif ans == 'g':
            pr(border, f'p = {p}')
            pr(border, f'g = {g}')
            pr(border, f'y = {y}')
        elif ans == "v":
            pr(border, "please send signature to verify: ")
            _flag, signature = False, sc()
            try:
                signature = [int(_) for _ in signature.split(',')]
                if verify_esa((g, P, Y), signature, m): _flag = True
                else: pr(border, "Your signature is not valid!!")
            except:
                pr(border, "Something went wrong!!")
            if _flag: die(border, "Congrats! your got the flag: " + flag)
        elif ans == 's':
            pr(border, "Please send your message to sign: ")
            msg = sc().encode('utf-8')
            if msg != MSG.encode('utf-8'):
                _m = bytes_to_long(msg)
                try:
                    sgn = sign_esa((g, P, Y), x, _m)
                    pr(border, f'sign = {sgn}')
                except:
                    pr(border, "Something went wrong!!")
            else:
                pr(border, "Kidding me!? Really?")
        elif ans == 'q': die("Quitting ...")
        else: die("Bye bye ...")

if __name__ == "__main__": main()
```

## Analyse

Le serveur implémente un schéma de signature de type El Gamal

Voir [Wikipédia](https://en.wikipedia.org/wiki/ElGamal_encryption)

On se donne ainsi:
```
Un nombre premier p public
Un générateur multiplicatif g (public)
Un exposant secret x
La valeur publique de g^x
```

Pour un message m, une signature est un couple `(u,v)` tel que
`y^u * u^v = g^m`.

Le serveur choisit p de taille 256 bits avec la propriété
classique `p-1 = 2q` où q est premier, pour éviter d'avoir un logarithme
discret rapide.

On nous donne la possibilité de basculer 30 bits du nombre `p`, puis
on doit envoyer au serveur une signature du message `m` connu.

Après l'attaque par fautes, il est aussi possible de demander au serveur
la signature d'un message différent de `m`.

## Stratégie

Le chemin le plus naturel pour fabriquer une signature est de trouver
la valeur de l'exposant secret `x`.

Malheureusement, lorsqu'on attaque le nombre premier `p` pour le modifié,
la valeur de `y = g^x mod p` est recalculée et n'est plus accessible.
En revanche, le serveur permet de fabriquer des signatures (pour des
messages différents de m).

Dans un premier temps, on cherche à modifier `p` pour que `p-1` soit
lisse. Comme on peut basculer 30 bits:

* on met à zéro les bits de poids faible (en moyenne, la moitié des bits
  est à 1) de sorte que p-1 soit divisible par `2^k` avec `k > 50`

* on met à zéro des bits de poids plutôt fort, en les choississant
  de sorte que `p-1` soit le plus lisse possible

Comme p est de taille 256 bits, un bon compromis est de modifier
26 bits de poids faible (alors p-1 se termine par au moins 50 zéros),
et d'utiliser les 4 autres pour rechercher un nombre premier lisse.
Avec un espace de recherche de taille au moins `200^4` on espère trouver
facilement des candidats.

De plus, grâce au facteur `2^50` la factorisation de `p-1` se ramène à
des nombres de taille plus petite (environ 200 bits).

Expérimentalement, il suffit d'une minute pour trouver `p` tel que
les facteurs possèdent au plus 17 chiffres.

Une fois un tel `p` trouvé, on doit extraire de l'information:
en réalité il n'est pas absolument nécessaire de connaître `x` ou `y`,
on peut fabriquer une signature en utilisant une astuce de masquage.

Étant donné une signature:
```
y^u * u^v = g^m
```
La connaissance du logarithme discret `g = u^z` permet de fabriquer
d'autres signatures:
```
y^u * u^(v+kz) = g^(m+k)
```

Il suffit donc par exemple de signer le message `m-1`
(en remplaçant le 'P' final par la lettre 'O'), puis
de renvoyer `(u, v+z)`

## Solution

```python
from sage.all import factor, is_prime, Zmod
from telnetlib import Telnet
import itertools
import ast

g = 2

c = Telnet("06.cr.yp.toc.tf", 31117)
print(c.read_until(b"uit\n"))

# Lecture des params

c.write(b"G\n")
while True:
    line = c.read_until(b"\n").decode()
    if "uit" in line:
        break
    if "p =" in line:
        p = int(line.split()[-1])
    if "y =" in line:
        y = int(line.split()[-1])

print("got params")
print("g = 2")
print("p =", p)
print("y =", y)

length = p.bit_length()

# Cherche un flip sympa

bits = [i for i in range(1, 200) if (p>>i) & 1]

for choice in itertools.combinations(bits[26:], 4):
    faults = bits[:26] + list(choice)
    #print(faults)
    pflip = p - sum(1<<i for i in faults)
    if not is_prime(pflip):
        continue
    print("prime", faults)
    factors = factor(pflip-1)
    print(factors)
    if all(f < 1e17 for f, _ in factors):
        print("lisse => gagné")
        break

print("faults", faults)
print("flipped P", pflip)

# On envoie les fautes

c.write(b"A\n")
print(c.read_until(b"\n"))
faults_str = ",".join(str(length-1-b) for b in faults)
c.write((faults_str + "\n").encode())
print(c.read_until(b"uit\n"))

# On signe m-1

MSG_MINUS_ONE = "4lL crypt0sy5t3ms suck5 fr0m faul7 atTaCk5 :O"
c.write(b"S\n")
print(c.read_until(b"\n"))
c.write((MSG_MINUS_ONE + "\n").encode())
sig_str = c.read_until(b"\n").decode()
u, v = ast.literal_eval(sig_str.split("=")[-1])
print(f"signature(MSG-1) = ({u}, {v})")
print(c.read_until(b"uit\n"))

dlog = Zmod(pflip)(g).log(u)
v += dlog

c.write(b"V\n")
c.write(("%s,%s\n" % (u,v)).encode())

print(c.read_until(b"\n"))
print(c.read_until(b"\n"))
```

Exemple de sortie:
```
g = 2
p = 63558542919681679657827509812151026228657575786278721651088204705887423094019
y = 56305067584657944939138280017722781136893024438679815887320125089936809511003
...
prime [1, 8, 10, 11, 12, 14, 15, 19, 23, 24, 25, 28, 32, 33, 34, 35, 36, 37, 38, 39, 45, 48, 52, 53, 56, 57, 59, 70, 83, 131]
2^72 * 3 * 7^2 * 101 * 113177 * 127681 * 209263 * 3157188179 * 88811450443 * 1069126771864087
lisse => gagné

faults [1, 8, 10, 11, 12, 14, 15, 19, 23, 24, 25, 28, 32, 33, 34, 35, 36, 37, 38, 39, 45, 48, 52, 53, 56, 57, 59, 70, 83, 131]
flipped P 63558542919681679657827509812151026225935316850911204270793252846594275934209
b'| please send at most 30-tuple array from indices of bits of ElGamal modulus, like: 5, 12, ...\n'
b'| Options: \n|\t[A]pply fault \n|\t[G]et the parameters \n|\t[S]ign the message \n|\t[V]erify the signature \n|\t[Q]uit\n'
b'| Please send your message to sign: \n'
signature(MSG-1) = (39168832821243646424877677228052654160940445777491337832834889770336825592500, 9638551011955447360951672204231232505283569332270235659820346627565410439715)

(une ou deux minutes de calcul)

b'| Options: \n|\t[A]pply fault \n|\t[G]et the parameters \n|\t[S]ign the message \n|\t[V]erify the signature \n|\t[Q]uit\n'
b'| please send signature to verify: \n'
b'| Congrats! your got the flag: CCTF{n3W_4t7aCk_8y_fAuL7_!nJ3cT10N_oN_p!!!}\n'
```

Note: des participants ont signalé que le serveur permettait
d'accumuler plus de fautes que prévu (à caause de `_B = B`,
comme dans le défi 'Fiercest').
