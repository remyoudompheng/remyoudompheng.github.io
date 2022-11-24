---
title: Wanna more features
parent: DG'h4ck 2022
grand_parent: CTF writeups
---

# Énoncé

Nous utilisons un programme de hachage très avancé dans notre entreprise. Ce programme s'appelle H4SH.

Vous le savez, nos opérations sont confidentielles.

Nous avons réussi à obtenir une licence limitée mais ne pouvons pas obtenir la licence complète.

Nous savons qu'il existe un prototype d'un nouvel algorithme de hachage très avancé dans le programme.

Trouvez cette fonctionnalité. Trouvez un moyen de l'activer. Et essayez-la.

Ce message ne s'auto-détruira pas.

# Solution

On a accès à une VM.

On trouve assez facilement le programme en question:
```
malice@malice:/$ find -name 'h4*' 2>/dev/null
./opt/h4sh

malice@malice:/opt/h4sh$ find
.
./start-H4SH.sh
./lib
./lib/libfeatures.so
./lib/libcrypto.so.1.1
./etc
./etc/features.xml
./bin
./bin/start-H4SH.bin

malice@malice:/opt/h4sh$ cat ./etc/features.xml 
<product>
  <name>H4SH</name>
  <version>1.2.3</version>
  <vendor>Unbreakable Software</vendor>
  <features>
    <sha1>yes</sha1>
    <sha224>no</sha224>
    <sha256>yes</sha256>
    <sha384>no</sha384>
    <sha512>yes</sha512>
    <md4>no</md4>
    <md5>yes</md5>
  </features>
  <seal>gSP7PJk6MFAGK5hXMpKTlB+v0Awpq7P5+pHCNv7gwZ5Lp3WCnop0Z3iv+51mJ5hNfH3DBb/ENrGSHPB5IDlmBmgVQabaxSrDZqLMa5v9/95K0Chr1iSbrSzMZryD1d5DPQvSFY+304ehGkWbrLSjzCIcvvgU7Y1031PoF5mH9yA0S/SNumX+R+WzslkZTV2wDvkRpG94UeXYtofcMi7I8AMDcd6e0LOGxzxWQ7/ZPmvJiA3Y+2R9jKUkSk2bislc9PM1ubmd05xKEd9HXd08n9An6KAgbReFSzG4eNJoMzOWlWrArgdAIp15x3iwqK5YjvCg+LqhDEtovui6LJciHQ==</seal>
</product>

malice@malice:/opt/h4sh$ ls -l ./bin/start-H4SH.bin
---x--x--x 1 root root 18568 21 oct.  16:55 ./bin/start-H4SH.bin
```

Le binaire n'a pas les permissions en lecture!

Après analyse, aucun des autres fichiers ne contient d'information intéressante.
La `libfeatures.so` présente une fonction de signature
`void app_behavior(char *feature,char *input)` qui reçoit un nom de hash
et une chaîne de caractères et renvoie le résultat.

## Exfiltration du binaire

Puisque le binaire est dynamique, en l'exécutant le code doit être chargé
en mémoire. On peut donc exfiltrer son contenu en copiant sur le serveur
une bibliothèque dynamique bien choisie avec `LD_PRELOAD`.

On compile le morceau de code suivant avec `gcc -Os -shared -o libtest.so test.c`
```
void app_behavior(char *feature,char *input) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    size_t p0, p1;
    fread(buf, 1024, 1, f);
    puts(buf);
```

On peut donc voir comment le programme est mappé en mémoire:
```
55a4ee7fc000-55a4ee7fd000 r--p 00000000 08:01 782                        /opt/h4sh/bin/start-H4SH.bin
55a4ee7fd000-55a4ee7ff000 r-xp 00001000 08:01 782                        /opt/h4sh/bin/start-H4SH.bin
55a4ee7ff000-55a4ee800000 r--p 00003000 08:01 782                        /opt/h4sh/bin/start-H4SH.bin
55a4ee800000-55a4ee801000 r--p 00003000 08:01 782                        /opt/h4sh/bin/start-H4SH.bin
55a4ee801000-55a4ee802000 rw-p 00004000 08:01 782                        /opt/h4sh/bin/start-H4SH.bin
```

Attention, une section du binaire est en double.

Avec ce morceau de code, on peut affichier le binaire en hexadécimal:
```
void app_behavior(char *feature,char *input) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    size_t p0, p1;

    fscanf(f, "%llx-%llx", &p0, &p1);
    printf("%p-%p\n", p0, p1);
    for (size_t i = 0; i < 18568; i++) {
            uint8_t *p = i > 0x4000 ? (p0 + i + 4096) : (p0 + i);
            printf("%02x", *(uint8_t*)p);
            if (p % 32 == 31)
                    puts("");
    }
    puts("");
}
```

```
malice@malice:/opt/h4sh$ LD_PRELOAD=/tmp/libtest.so ./start-H4SH.sh md5 toto 
0x56352d37e000-0x56352d37f000
7f454c4602010100000000000000000003003e0001000000801a000000000000
4000000000000000484100000000000000000000400038000d0040001d001c00
0600000004000000400000000000000040000000000000004000000000000000
d802000000000000d80200000000000008000000000000000300000004000000
[etc]
```

## Reverse

Après avoir extrait le binaire, on peut l'ouvrir dans Ghidra:
```
      iVar4 = thunk_strcmp(argv[1],"sha10x256");
      if (iVar4 == 0) {
        lVar5 = 0;
        do {
          bVar14 = s__00103700[lVar5];
          if (bVar14 != 0) {
            bVar14 = bVar14 ^ 0xcb;
          }
          (&DAT_00105260)[lVar5] = bVar14;
          lVar5 = lVar5 + 1;
        } while (lVar5 != 0x3d);
        DAT_0010529d = 0;
        iVar3 = 0;
        thunk_printf_chk(1,
                         "\nYou have cracked our unbreakable software protection.\nThis will be repo rted to the police!\n\nJust kidding ;-). Well done!\n%s\n"
                         ,&DAT_00105260);
      }
```

Le flag est donc à l'adresse 0x3700 et XOR avec 0xcb:
```
>>> bytes(b ^ 0xcb for b in data[0x3700:0x3740])
b'DGHACK{G00DLUCK74R1NG70UND34574ND7H1SFL4G1FY0UD0N75P34KL337}\xcb\xcb\xcb\xcb'
```
