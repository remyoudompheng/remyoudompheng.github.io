---
title: HotshotGL
parent: ECW CTF 2022
grand_parent: CTF writeups
---

# HotshotGL

Challenge reverse proposé par Thalès.

Everything is going wrong at the Khronos airport. Please help the air
controller to find the secret flag which will finally makes the plane takeoff !

## Description

Le challenge est un petit binaire Linux x86-64. Comme indiqué dans le titre,
la particularité est qu'une partie de la logique est implémentée en utilisant
des shaders OpenGL.

Les chaînes de caractères qui peuvent être affichées par le binaire sont:
```
You will never fly!
Okay Houston I believe we've had a problem here!
Mon coeur s'entirbouchonne autour de mes chevilles comme un vieux slip moite. C'est pas ca !
Y a-t-il un pilote dans l'avion ?
Taking off
```

L'objectif étant d'atteindre la dernière.

## Aperçu de la fonction main

La fonction main effectue environ ceci (en pseudocode):
```python
if argc < 2:
    print("You will never fly !")
flag = string(argv[1])
if len(flag) != 58:
    print("Okay, Houston, I believe we've had a problem here!")
s = flag[:4] + flag[-1:]
if s != "ECW{}":
    print("Mon coeur s'entirbouchonne ...")
flag = flag[4:57]
# code de vérification
```

## Premier shader

Le premier shader ressemble à:
```
OBFUSCATED = bytes.fromhex("""
153c697a6d6c7670713f2c2c2f3f7c706d7a1515737e66706a6b3773707\
c7e6b7670713f223f2f363f706a6b3f7973707e6b3f70497e736a7a2415\
156970767b3f727e767137361564153f3f3f3f70497e736a7a3f223f797\
3707e6b37376a76716b37787340596d7e785c70706d7b3167363f353f6a\
76716b372f67592e2e28363f343f6a76716b372f675e2c272f36363f3a3\
f2d2a294a363f303f2d2a2a3124156215
"""

SHADER1 = """
#version 330 core
layout(location = 0) out float oValue;
uniform uint AN225;
void main()
{
    oValue = float(AN225 % 256U) / 255.;
}
"""

arg = ???

runShader(&output, OBFUSCATED, SHADER1, GL_XOR, arg)
```

La chaîne de caratères obfusquée est composée de 160 octets
à l'adresse 0xbf30 et 4 octets supplémentaires `"$\x15b\x15"`

The programme va exécuter le shader (qui retourne une constante)
et le combiner avec une "texture" (la chaîne encodée)
avec un opérateur XOR.

En examinant plus attentivement, on voit que la sortie de cette opération
va elle-même être utilisée comme shader, donc on peut trouver la clé de
déchiffrement en cherchant le texte connu `version 330 core`.

On trouve facilement que l'opération à effectuer
est XOR 0x1F et le texte secret est:
```
#version 330 core

layout(location = 0) out float oValue;

void main()
{
    oValue = float((uint(gl_FragCoord.x) * uint(0xF117) + uint(0xA380)) % 256U) / 255.;
}
```
(ce qui permet de découvrir une nouvelle blagounette aéronautique).

Le clé est construite de la manière suivante:
```
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::substr
	(&prefix3,&flag,0,3);
n = strtol(prefix3.str,NULL,10);
key = (int)n + (int)shader_src1.len;
```

La longueur du premier shader est 109 donc le flag doit commencer par `"178"`
puisque `uint8(178 + 109) == 0x1F`

Le flag est donc de la forme:
```
ECW{178 <suffix: 50 caractères> }
```

# Deuxième shader

Le deuxième shader est exécuté par un appel:
```
runShader(&output, suffix, SECRET_SHADER, GL_EQUIV, &arg)
```

L'opération `GL_EQUIV` combine les valeurs par `NOT (a XOR b)`.
Pour une coordonnée `x` (indice dans le tableau) le shader
va produire la valeur `(x * 0xF117 + 0xA380) % 256`.
Cette opération transforme donc le flag comme le code Python:
```
[0xff ^ b ^ (0x17 * i + 0x80) & 0xff for i, b in enumerate(suffix)]
```

Par exemple, si on entre le flag:
```
ECW{178defghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0}
```
La sortie de cette opération est (en hexadécimal)
```
1b0d375d4b659fb5abddf7ed1b254f557b8d97bdcbe5ff0f35234d779d83a5dff5e31d372d43658f95a3cdd7fd03253f5528
```
ce qui se vérifie facilement avec GDB.

# Troisième shader

Le 3e shader est visible en clair dans le programme:
```
#version 330 core
layout(location = 0) out float oValue;
uniform int X15[63];
void main()
{
    int jet = int(gl_FragCoord.x) + 13;
    oValue = float(X15[jet]) / 255.;
}
```

Et il est appliqué par l'appel:
```
runShader(&output, buffer, SHADER3, GL_XOR, &arg)
```

Il s'applique à la sortie du shader précédednt (50 octets) via une opération XOR
et les valeurs proviennent d'une variable `uniform` OpenGL X15, initialisée
par la fonction à l'adresse 0x9ec0 par un tableau statique:
```
0xBD40:
   32 43 58 97 F3 31 87 32
   A4 BE FA 01 AA 28 0D 3D
   59 4C 61 90 81 A8 DE C6
   C0 04 35 4F 42 23 A7 B5
   A2 DA EF DA 07 24 1F 70
   7D 8E 96 92 F5 FE F8 05
   3B 2A 42 4A AD 97 B5 D8
   C9 E2 1A 3A 19 14 31
```

L'opération est donc le XOR avec les 50 dernières valeurs du tableau (ignorer
les 13 premières).

# Dernier shader

La dernière opération est un peu compliquée: on a un fragment shader:
```
#version 330 core
layout(location = 0) out float oValue;
uniform sampler2D Input;
void main() {
    ivec2 p = 2 * ivec2(gl_FragCoord.xy);
    oValue = texelFetch(Input, p, 0).r;
    if((p.x + 1) < textureSize(Input, 0).x) {
        oValue += texelFetch(Input, p + ivec2(1, 0), 0).r;
    }
}
```

Et un vertex shader:
```
#version 330 core
out vec2 texCoord;
void main()
{
    float x = float(((uint(gl_VertexID) + 2u) / 3u) % 2u);
    float y = float(((uint(gl_VertexID) + 1u) / 3u) % 2u);

    gl_Position = vec4(-1.0f + x * 2.0f, -1.0f + y * 2.0f, 0.0f, 1.0f);
}
```

Mais la structure du code permet de deviner l'opération qui est effectuée:
```
length = 50
while length > 1:
    length = (length + 1) // 2
    # Create 2D texture from data
    # Apply shaders
```

Le fragment shader calcule à chaque fois la somme de 2 valeurs,
et la taille du tableau est divisée par 2 à chaque fois.

On comprend que ce qui est calculé est la somme de tous les éléments
et que la vérification est faite est que la somme est nulle (et donc
tous les éléments sont nuls).

# Solution

Il suffit donc de s'arrêter au 3e shader.

En résumé, le flag est de la forme `ECW{178suffix}`
et on doit avoir que:
```
suffix = ...
blob = [0xff ^ b ^ (0x17 * i + 0x80) & 0xff for i, b in enumerate(suffix)]
blob2 = xor(blob, uniform[13:])
assert all(b == 0 for b in blob2)
```

Le flag est donc:
```
mask = bytes((0x17 * i + 0x80) & 0xff for i in range(50))

uniform = bytes.fromhex("""
   32 43 58 97 F3 31 87 32
   A4 BE FA 01 AA 28 0D 3D
   59 4C 61 90 81 A8 DE C6
   C0 04 35 4F 42 23 A7 B5
   A2 DA EF DA 07 24 1F 70
   7D 8E 96 92 F5 FE F8 05
   3B 2A 42 4A AD 97 B5 D8
   C9 E2 1A 3A 19 14 31
""".replace("\n", ""))

print(bytes(a ^ b ^ 0xff for a, b in zip(mask, uniform[13:])))

# Welcome_on_Board,_This_is_Your_Captain_Speaking_;)
# ECW{178Welcome_on_Board,_This_is_Your_Captain_Speaking_;)}
```
