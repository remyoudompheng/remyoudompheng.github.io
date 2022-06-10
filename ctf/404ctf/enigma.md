---
title: Cryptanalyse — Enigma
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

# Enigma

```
« La mission qui suit est d'une confidentialité absolue ! Nous avons
intercepté un message envoyé par un membre de Hallebarde, et nous avons
retrouvé la machine utilisée, une machine Enigma M3. Déchiffrez ce
message, retrouvez le nom de leur contact, et déjouez les plans de nos
ennemis ! »
Au cours de vos recherches vous découvrez le concept « d'indice de coïncidence », qui vous intrigue particulièrement...

    Vous avez à votre disposition deux répliques de machines Enigma M3,
l'une en python, l'autre en C++ Le flag est le nom du contact, n'oubliez
pas d'ajouter 404CTF{} autour de son nom

Auteur : Aug. C#3888
```

Thématique: Cryptanalyse

Difficulté: Difficile

## Description

Un texte chiffré (3132 lettres) est fourni:
```
HBMUBJARKLZIVXEIULIWTAFNKPFDYCWZB...
```
ainsi que deux implémentations d'Enigma (en Python et en C++).

L'énoncé suggère de trouver la bonne configuration de chiffrement
d'Enigma en utilisant la technique de l'indice de coïncidence
(un peu étrange: elle n'est pas censée fonctionner dans le cas général
sur Enigma).

## Position des rotors

Le câblage (plugboard) d'Enigma ne bouge pas au cours du processus
de chiffrement, donc on l'ignore en espérant qu'il n'affecte pas
le calcul de l'indice de coïncidence.

On peut donc se concentrer sur la position des rotors. Comme le troisième
rotor ne peut tourner que tous les 26x26 caractères, la position de son
encoche est peu importante (il ne bougera que de quelques lettres).

On peut donc chercher par force brute parmi les `26x26x26x26x26`
configurations possibles des 3 rotors et des 2 premières encoches,
soit environ 12 millions de combinaisons.

Attention, on a également le choix de 3 rotors parmi 5, et de deux
réflecteurs, on arrive donc à 1.4 milliard de combinaisons.

On utilise l'implémentation C++ pour la performance.

Code de craquage:
```
  Rotor rot[5] = {
      Rotor::create("I", 'H', 'M'),   Rotor::create("II", 'E', 'C'),
      Rotor::create("III", 'T', 'U'), Rotor::create("IV", 'T', 'U'),
      Rotor::create("V", 'T', 'U'),
  };

  Reflector refB = Reflector::create("B");
  Reflector refC = Reflector::create("C");
  Plugboard plugboard{{}};

  // 5*4*3 = 60 combinaisons.
  for (int i = 50; i < 60; i++) {
    int a = i / 12;
    int b = (i % 12) / 3;
    int c = i % 3;
    if (a <= b)
      b++;
    if (a <= c)
      c++;
    if (b <= c)
      c++;
    printf("Rotors %d %d %d\n", a+1, b+1, c+1);
    Rotor r1 = rot[a];
    Rotor r2 = rot[b];
    Rotor r3 = rot[c];
    Enigma eB(r1, r2, r3, refB, plugboard);
    Enigma eC(r1, r2, r3, refC, plugboard);
    for (int i1 = 0; i1 < 26; i1++) {
      for (int i2 = 0; i2 < 26; i2++) {
        for (int i3 = 0; i3 < 26; i3++) {
          for (int j1 = 0; j1 < 26; j1++) {
            for (int j2 = 0; j2 < 26; j2++) {
              eB.left_rotor.position = i1;
              eB.middle_rotor.position = i2;
              eB.right_rotor.position = i3;
              eB.middle_rotor.ring_setting = j1;
              eB.right_rotor.ring_setting = j2;
              eB.left_rotor.complete_rotation = false;
              eB.middle_rotor.complete_rotation = false;
              eB.right_rotor.complete_rotation = false;
              std::string dec = eB.encrypt(enc);
              double coin = coinc(&dec);
              if (coin > .05) {
                printf("B %d %d %d %.5f\n", i1, i2, i3, coin);
                printf("B %d %d %d\n",
                    eB.left_rotor.position, eB.middle_rotor.position, eB.right_rotor.position);
                std::cout << dec << std::endl;
              }

              eC.left_rotor.position = i1;
              eC.middle_rotor.position = i2;
              eC.right_rotor.position = i3;
              eB.middle_rotor.ring_setting = j1;
              eB.right_rotor.ring_setting = j2;
              eC.left_rotor.complete_rotation = false;
              eC.middle_rotor.complete_rotation = false;
              eC.right_rotor.complete_rotation = false;

              dec = eC.encrypt(enc);
              coin = coinc(&dec);
              if (coin > 0.05) {
                printf("C %d %d %d %.5f\n", i1, i2, i3, coin);
                printf("C %d %d %d\n",
                    eC.left_rotor.position, eC.middle_rotor.position, eC.right_rotor.position);
                std::cout << dec << std::endl;
              }
            }
          }
        }
      }
    }
  }
```

## Un problème de performance

En faisant tourner ce programme, on constate un gros problème de
performance: pour itérer 26x26x26 fois, il faut environ 18 secondes,
soit au total 20 heures pour l'ensemble de la boucle.

On voit alors que l'implémentation C++ a d'importants problèmes que l'on
peut patcher.

Éviter la boucle sur la liste d'encoches de taille 1:
```
-	if (std::find(middle_rotor.notches.begin(),
-	              middle_rotor.notches.end(),
-	              alphabet.at(middle_rotor.position)) !=
-	    middle_rotor.notches.end()) {
+	if (alphabet.at(middle_rotor.position) == middle_rotor.notches[0]) {
```

Éviter de mettre le texte en majuscules (il l'est déjà):
```
-	std::transform(plain.begin(), plain.end(), plain.begin(), ::toupper);
+	//std::transform(plain.begin(), plain.end(), plain.begin(), ::toupper);
```

Éviter une boucle pour transformer une lettre de l'alphabet en nombre:
```
- alphabet.find(plain.at(i))
+ plain[i] - 'A'
```

Éviter la hashmap dans la classe Plugboard:
```
 class Plugboard {
   public:
-	std::unordered_map<char, char> permutations;
+	char charmap[26];

```

Cela permet d'aller 2x ou 3x plus vite.

## Performance aggressive

En réalité, on a besoin d'aller vraiment très vite, on fait donc des
hypothèses plus aggressives.

On a choisi d'ignorer le Plugboard, on le débranche donc complètement.

On peut aussi calculer l'indice de coïncidence sur une partie du texte
(300 caractères au lieu de 3000), ce qui accélère fortement le calcul
(les lettres de l'alphaet seront autant représentées sur 300 lettres que
sur 3000).

Après ces changements, il suffit de 8 minutes pour tester une
combinaison de rotors (mais il y a encore 60 combinaisons de rotors
soit 8 heures au total!).

## Performance aggressive, épisode 2

Sur un texte aussi petit (taille 400), les encoches n'ont plus vraiment d'impact
sur l'indice de coïncidence (la deuxième encoche n'a pas d'effet,
et décaler la première ne change que quelques lettres).

On les ignore donc aussi, ce qui permet d'accélérer encore d'un facteur
576.

On a maintenant la solution en une minute:
```
Rotors 5 2 4
C 16 22 14 0.05625
```
avec un indice de coïncidence assez élevé et un texte presque
intelligible:
```
UVGENTNDUSAGBVONSDPSBTVOISJOUVSROTVECONTACTSGWMLOISEAHDECALHEXVVIENAVODNBIISJAIMECETEXTEDUTEMPSDRJVIMOABDAV
```

## Fin du déchiffrement

On peut repasser sur l'implémentation Python pour plus de flexibilité:
```
    r1 = Rotor(R5, "Q", "A")
    r2 = Rotor(R2, "W", "A")
    r3 = Rotor(R4, "O", "A")
```

Il faut encore déterminer le tableau de branchements, et la position des
encoches.
```
enc HBMUBJARKLZIVXEIULIWTAFNKPFDYCWZBGUQWZFDYMALJNYINHMKYVQGVXSWXVFHUQKGRDPVWVTQLHGGNAAWPEPDMLIQNJT
dec UVGENTNDUSAGBVONSDPSBTVOISJOUVSROTVECONTACTSGWMLOISEAHDECALHEXVVIENAVODNBIISJAIMECETEXTEDUTEMPS
```

Si une lettre est correcte, elle ne peut pas faire partie du Plugboard
(qui échange des lettres). Après une élimination rapide, il reste les
candidats JKQRUV.

On teste différentes possibilités et le branchement VR est le plus
prometteur:
```
plug VR
URGENTNOUSAGIRONSDPSBTROISJOURSVOTRECONTACTSGWMLOISEAUDEMALHEUR
HBMUBJARKLZIVXEIULIWTAFNKPFDYCWZBGUQWZFDYMALJNYINHMKYVQGVXSWXVF
```

Alignons le texte partiellement déchiffré en lignes de 26 caractères:
```
URGENTNOUSAGIRONSDPSBTROIS
JOURSVOTRECONTACTSGWMLOISE
AUDEMALHEURRIENAVODEBAISJA
IMECETEXTEDUTEMPSDVJRIMOAB
DARILYAVAITABABYLOQVCNJEUN
EHOMMENOMMEZADIGNEUKRCUNBE
AUNATURELFORTIFIEPKKGBSEET
KBAZVATDVJLJQFZLRFPSDPEILS
AVAITMODERERSESPASKABNSILN
AFFECTAITRIENILNEVRVEAITPO
INTTOUJOURSAVOIRRAGVFNETSA
                  ^^^
```

On voit que 3 colonnes sont fausses (le texte devrait être "nous agirons
dans trois jours"). On peut corriger cela en déplaçant l'encoche de 3
crans.

```
    r1 = Rotor(R5, "Q", "A")
    r2 = Rotor(R2, "W", "A")
    r3 = Rotor(R4, "R", "D")
```

Et voilà:
```
URGENTNOUSAGIRONSDANSTROISJOURSVOTRECONTACTSERALOISEAUDEMALHEUR
RIENAVOIRMAISJAIMECETEXTEDUTEMPSDUROIMOABDARILYAVAITABABYLONEUN
```

Le flag était `404CTF{LOISEAUDEMALHEUR}`
