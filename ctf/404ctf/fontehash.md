---
title: Cryptanalyse — Dégâts collatéraux
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

# La fonte des hashs

```
Nos experts ont réussi à intercepter un message de Hallebarde : 18f2048f7d4de5caabd2d0a3d23f4015af8033d46736a2e2d747b777a4d4d205

Malheureusement il est haché ! L'équipe de rétro-ingénierie vous a laissé cette note :

Voici l'algorithme de hachage. Impossible de remonter le haché mais
vous, vous trouverez peut être autre chose. Voici comment lancer le
hachage : python3 hash.py [clair]

PS : Les conversations interceptées parlaient d'algorithme "très frileux" ...

Auteur : seaweedbrain#1321
```

Thématique: Cryptanalyse

Difficulté: Difficile

## Description

Le code fourni est un script Python un peu obfusqué:
```
import base64, codecs
magic = 'IyEvdXNyL...'
love = 'RjZQRkZGRa...'
god = 'MTExMDEwM...'
destiny = 'NjZQNjZFp...'
joy = '\x72\x6f\x74\x31\x33'
trust = eval('\x6d\x61\x67\x69\x63') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x6c\x6f\x76\x65\x2c\x20\x6a\x6f\x79\x29') + eval('\x67\x6f\x64') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x64\x65\x73\x74\x69\x6e\x79\x2c\x20\x6a\x6f\x79\x29')
eval(compile(base64.b64decode(eval('\x74\x72\x75\x73\x74')),'<string>','exec'))
```

## Déobfuscation

On peut reconstruire le script en vérifiant quelques choses dans un shell
Python:
```
joy = "rot13"
trust = magic + codecs.decode(love, joy) + god + codecs.decode(destiny, joy)
print(base64.b64decode(trust).decoed())
```

On obtient le script suivant:
```
#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys



# from https://asecuritysite.com/subjects/chapter88
sbox = ['01100011', '01111100', '01110111', '01111011', '11110010', '01101011', '01101111', '11000101', '00110000', '00000001', '01100111', '00101011', '11111110', '11010111', '10101011', '01110110', '11001010', '10000010', '11001001', '01111101', '11111010', '01011001', '01000111', '11110000', '10101101', '11010100', '10100010', '10101111', '10011100', '10100100', '01110010', '11000000', '10110111', '11111101', '10010011', '00100110', '00110110', '00111111', '11110111', '11001100', '00110100', '10100101', '11100101', '11110001', '01110001', '11011000', '00110001', '00010101', '00000100', '11000111', '00100011', '11000011', '00011000', '10010110', '00000101', '10011010', '00000111', '00010010', '10000000', '11100010', '11101011', '00100111', '10110010', '01110101', '00001001', '10000011', '00101100', '00011010', '00011011', '01101110', '01011010', '10100000', '01010010', '00111011', '11010110', '10110011', '00101001', '11100011', '00101111', '10000100', '01010011', '11010001', '00000000', '11101101', '00100000', '11111100', '10110001', '01011011', '01101010', '11001011', '10111110', '00111001', '01001010', '01001100', '01011000', '11001111', '11010000', '11101111', '10101010', '11111011', '01000011', '01001101', '00110011', '10000101', '01000101', '11111001', '00000010', '01111111', '01010000', '00111100', '10011111', '10101000', '01010001', '10100011', '01000000', '10001111', '10010010', '10011101', '00111000', '11110101', '10111100', '10110110', '11011010', '00100001', '00010000', '11111111', '11110011', '11010010', '11001101', '00001100', '00010011', '11101100', '01011111', '10010111', '01000100', '00010111', '11000100', '10100111', '01111110', '00111101', '01100100', '01011101', '00011001', '01110011', '01100000', '10000001', '01001111', '11011100', '00100010', '00101010', '10010000', '10001000', '01000110', '11101110', '10111000', '00010100', '11011110', '01011110', '00001011', '11011011', '11100000', '00110010', '00111010', '00001010', '01001001', '00000110', '00100100', '01011100', '11000010', '11010011', '10101100', '01100010', '10010001', '10010101', '11100100', '01111001', '11100111', '11001000', '00110111', '01101101', '10001101', '11010101', '01001110', '10101001', '01101100', '01010110', '11110100', '11101010', '01100101', '01111010', '10101110', '00001000', '10111010', '01111000', '00100101', '00101110', '00011100', '10100110', '10110100', '11000110', '11101000', '11011101', '01110100', '00011111', '01001011', '10111101', '10001011', '10001010', '01110000', '00111110', '10110101', '01100110', '01001000', '00000011', '11110110', '00001110', '01100001', '00110101', '01010111', '10111001', '10000110', '11000001', '00011101', '10011110', '11100001', '11111000', '10011000', '00010001', '01101001', '11011001', '10001110', '10010100', '10011011', '00011110', '10000111', '11101001', '11001110', '01010101', '00101000', '11011111', '10001100', '10100001', '10001001', '00001101', '10111111', '11100110', '01000010', '01101000', '01000001', '10011001', '00101101', '00001111', '10110000', '01010100', '10111011', '00010110']




def string2bits(s=''):
    tmp = []
    for x in s :
        byte = bin(ord(x))[2:]
        if len(byte) > 8:
            indices = [i for i in range(0, len(byte), 8)]
            parts = ["".join(byte[i:j]).zfill(8) for i,j in zip(indices, indices[1:]+[None])]
            tmp += (parts)
        else :
            byte = byte.zfill(8)
            tmp.append(byte)
    return tmp

def padding(binary):
    if((len(binary) + 1 ) % 32 == 0):
        binary.append('00000001')
        binary.append('00000000')
    if(len(binary)%32 != 0 or len(binary) == 0):
        binary.append('00000001')
        while len(binary)%32 != 0:
            binary.append('00000000')

def xor(a,b):
    res = ""
    for i in range(len(a)):
            res += str(int(a[i]) ^ int(b[i]))
    return res

def sbox_ope(binary):
    for i in range(len(binary)):
        index = int(binary[i],2)
        binary[i] = sbox[index]

def phase1(binary):
    m = int(len(binary) / 32)
    tmp = []
    for i in range(0, len(binary), m):
        tmp.append(xor(binary[i], binary[i+1]))
    return tmp

def phase2(binary):
    for i in range(1,len(binary)):
        for j in range(i):
            binary[i] = xor(binary[i], binary[j])

def bits2hex(binary):
    hex_str = ""
    for bit in binary:
        hex_str += format(int(bit, 2), '02x')
    return hex_str

def h(m):
    plain = m
    binary = string2bits(plain)
    padding(binary)
    if len(binary) > 32:
        binary = phase1(binary)
    print(bits2hex(binary))
    phase2(binary)
    print(bits2hex(binary))
    phase2(binary)
    print(bits2hex(binary))
    phase2(binary)
    print(bits2hex(binary))
    sbox_ope(binary)
    hash_str = bits2hex(binary)
    return hash_str


plain =  ""
if len(sys.argv) == 1:
    print("Aucun argument donné. Rien à hacher. Bye bye.")
elif len(sys.argv) >= 2 :
    plain += sys.argv[1]
    for i in range(2,len(sys.argv)):
        plain += " " + str(sys.argv[i])
    print(h(plain))
```

Le script est encore un peu étrange: il fait des opérations sur des
octets représentés sous forme de chaînes de 8 bits "0" ou "1".
Remplaçons toutes ces opérations par des opérations "normales":
```
S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

def hash(b):
    b = list(b)
    # padding
    if len(b) % 32 == 31:
        b += [1, 0]
    if len(b) % 32 != 0:
        b.append(1)
        b += (32 - len(b)%32) * [0]
    # phase 1
    if len(b) > 32:
        m = (len(b)-1) // 32
        b = [b[i*m] ^ b[i*m+1] for i in range(32)]
    # phase 2
    print(bytes(b).hex())
    for _ in range(3):
        b = [x^y for x, y in zip(b, [0]+b)]
        print(bytes(b).hex())
    # phase 3
    b = [S[x] for x in b]
    return bytes(b).hex()

def main():
    import sys
    arg = " ".join(sys.argv[1:])
    print(hash(arg.encode()))

if __name__ == "__main__":
    main()
```

## Inversion

On observe que les phases 2 et 3 sont inversibles: l'inverse est assez
simple.

La phase 2 remplace chaque octet par son XOR avec le précédent.

La phase 3 est une S-Box, qu'on peut facilement inverser.

```
Sinv = [S.index(i) for i in range(256)]

import sys
b = list(bytes.fromhex(sys.argv[1]))
b = [Sinv[x] for x in b]
for _ in range(3):
    out = []
    x = 0
    for e in b:
        x ^= e
        out.append(x)
    b = out
print(bytes(b))
```

Et voilà, c'est fini:
```
% python fontehash-solve.py 18f2048f7d4de5caabd2d0a3d23f4015af8033d46736a2e2d747b777a4d4d205
b'404CTF{yJ7dhDm35pLoJcbQkUygIJ}\x01\x00'
```
