---
title: "Travail de bachelor"
author: [Maxime Chantemargue]
date: \today
subject: ""
subtitle: "Analyse de sécurité des réseaux LoRaWAN"
lang: "fr"
titlepage: true
titlepage-logo: ./figures/HEIG-Logo.png
titlepage-rule-color: "D9291B"
toc: true
toc-own-page: true
number-sections: true
caption-justification: centering
graphics: yes
geometry: "top=2cm, bottom=2cm, left=2cm, right=2cm"
---


# Travail de bachelor - Analyse des réseaux LoRaWAN dans la région Romande
Cette projet de bachelor vise à évaluer la sécurité des protocoles de communication LPWAN, en particulier LoRaWAN, dans le contexte de l'Internet des Objets (IoT).
## Motivation
La vision de l'Internet-of-Things (IoT) promet une multitude d'objets connectés, capables d'échanger des informations sur un réseau universel.
Ces objets sont souvent contraints par leur taille et leur coût, ce qui limite la puissance disponible ainsi que la taille physique des antennes.
Ces contraintes peuvent exclure l'utilisation de technologies existantes, comme les réseaux mobiles ou les réseaux sans fil domestique.

Pour pallier à ces limitations, il existe des protocoles de communication "Low Power Wide Area Network" (LPWAN) tels que LoRaWAN, Sigfox, ou LTE-M, permettant de communiquer à longue distance et à basse puissance, en renonçant à un débit élevé. La communication se fait avec un réseau de stations de base communiquant entre elles par une infrastructure classique. Ce réseau peut être commercial (par exemple, Swisscom exploite un réseau LoRaWAN à l'usage de clients business), mais il existe aussi des réseaux publics formés par des participants volontaires, comme The Things Network.

Ces réseaux posent de nouveaux problèmes de sécurité: d'une part, l'interception des communications radio peut se faire facilement à plus grande échelle, de l'autre, un opérateur malveillant peut choisir de participer à un réseau public. Il est important d'étudier les risques posés par une telle technologie.

## Descriptif

Dans un premier temps, une synthèse des mécanismes de sécurité présents nativement dans le protocole LoRaWAN sera réalisée, avec une identification des risques les plus importants et une analyse des scénarios d'attaque possibles. Ensuite, des mesures expérimentales seront effectuées sur un site en Suisse Romande pour comprendre l'utilisation du réseau LoRaWAN dans la région, tout en évaluant l'impact des métadonnées malgré le chiffrement. Enfin, l'installation et l'exploitation d'un point d'accès au sein d'un réseau volontaire permettront d'évaluer la faisabilité pour un opérateur malveillant de mettre en place les scénarios d'attaque évoqués ci-dessus.

## Cahier des charges
- Produire un état de l'art sur le fonctionnement de LoRaWAN
- Production d'un document décrivant synthétiquement l'utilisation de la cryptographie dans la stack LoRaWAN, y compris les procédures de gestion de clés implémentées par les constructeurs et les opérateurs de réseaux publics.
- Installation d'un point d'accès LoRaWAN, connexion à un réseau public, mise en place d'un mécanisme de collecte de trafic, et production d'une capture d'un mois de données.
- Analyse de ces captures et inventaire des mécanismes de sécurité utilisés pour la communication entre les points d'accès d'un réseau public.
- Etude de la faisabilité et de l'impact de la falsification de la position géographique d'un point d'accès sur les applications de géolocalisation.

# Glossaire et définitions
|Mot technique|Définition|
|---|---|
|End device|Appareil se connectant au réseau LoRaWAN.|
|Gateway|Passerelle d'accès au réseau LoRaWAN.|
|Application server|Serveur d'application en bout de chaîne de communication vers lequel les données du *end device* sont envoyées.|
|Join request|Requête d'activation sur le réseau LoRaWAN envoyée par le *end device* vers le *join server*.|
|Join accept|Requête de validation renvoyée par le *join server* au *end device* si l'activation est un succès.|
|Join server|Serveur vers lequel le *end device* est envoyée une *oin request* et si celui-ci est légitime alors, ce même *join server* renvoie la réponse *join accept* au *end device*.|
|Payload|Charge utile mise dans une requête pour être envoyée au serveur.|

|Acronyme|Définition|
|---|---|
|LoRaWAN|Low power wide area network|
|IoT|Internet of things|
|AES|Advance encryption standard|
|AppKey|Application key|
|AppSKey|Application session key|
|NwkKey|Network key|
|AES-ECB|Advanced Encryption Standard with Electronic Code Book mode|
|AES-CCM|Advanced Encryption Standard with counter with cipher block chaining message authentication code|

# LoRaWAN - Etat de l'art
---
LoRaWAN est une couche applicative qui vient s'ajouter au protocole basse consommation de LoRa. Celle-ci permet notamment d'ajouter une couche sécuritaire avec chiffrement, authentification et vérification d'intégrité. LoRaWAN est maintenue par [LoRa Alliance](https://lora-alliance.org/)
La première version de LoRaWAN est sortie en 2015. Voici-ci contre les différentes versions.

|Version|Date de sortie|
|---|---|
|1.0|Janvier 2015|
|1.0.1|Février 2016|
|1.0.2|Juillet 2016|
|1.1|Octobre 2017|
|1.0.3|Juillet 2018|
|1.0.4|Octobre 2020|

[Source des versions](https://www.thethingsnetwork.org/docs/lorawan/what-is-lorawan/)

## Avantages
Sur le lien vers la documentation de The Things Network, il existe une liste exhaustive de tous les avantages de LoRaWAN. Voici à mon sens les plus pertinents :

- Basse consommation :
- Grande portée : les passerelles LoRaWAN peuvent transmettre et recevoir des signaux sur une distance de plus de 10 kilomètres dans les zones rurales et jusqu'à 3 kilomètres dans les zones urbaines denses.
- Couche sécuritaire : communication chiffrée de bout en bout entre le *End device* et l'*Application Server* avec AES-128.
- Géolocalisation : possibilité de localisation d'appareil IoT par triangulation et donc pas besoin de GPS.
- Ecosystème : soutenu par la communauté, beaucoup de personnes mettent en place des *gateways* pour que les *end devices* puissent se connecter dessus et ainsi avoir une grande couverture sur tout un territoire.

## Classes d'appareils
Sur le réseau LoRaWAN. il existe 3 classes d'appareil comme suit : A B et C. Ces différentes classes définissent la manière dont l'appareil communique avec la passerelle et influent sur la consommation d'énergie ainsi que la réception de données.

### Classe A
- **Fonctionnement** : C'est la classe la plus basique et économe en énergie. Tout appareil de Classe A ouvre deux courtes fenêtres de réception après chaque transmission. Si le réseau doit envoyer des données à l'appareil, il doit attendre que celui-ci initie une transmission.
- **Cas d'utilisation** : idéale pour des appareils connecté sur batteries nécessistant une communication faible et/ou par intermittence.
- **Avantages** : très faible consommation d'énergie.
- **Inconvénients** : capacité de communication descendante limitée, elle dépend des transmissions ascendante de l'appareil. 

### Classe B
- **Fonctionnement** :  Les appareils de Classe B ouvrent des fenêtres de réception supplémentaires à des moments programmés en plus des fenêtres de la Classe A. Pour cela, ils écoutent des balises (beacons) émises par la passerelle pour synchroniser l'ouverture de ces fenêtres.
- **Cas d'utilisation** : Convient aux applications nécessitant des fenêtres de réception programmées pour les communications descendantes sans consommer trop d'énergie.
- **Avantages** : Permet des communications descendantes plus fréquentes tout en conservant une bonne efficacité énergétique.

### Classe C
- **Fonctionnement** : Les appareils de Classe C gardent leur récepteur allumé en permanence, sauf lorsqu'ils transmettent. Cela permet de recevoir des données à tout moment.
- **Cas d'utilisation** : Idéal pour les appareils alimentés sur secteur ou ceux qui nécessitent une grande quantité de données en temps réel.
- **Avantages** : Capacité maximale de réception des communications descendantes.


# [Sécurité](https://www.thethingsnetwork.org/docs/lorawan/security/)
LoRaWAN utilise de la cryptographie symmétrique pour éviter les “handshake” coûteux entre l’appareil et le serveur. La même clé est donc sur le serveur et sur le *end device*. 

Ce choix est dû au fait que l’utilisation de la fréquence LoRa est réglementée et donc limitée dans le temps pour chaque appareil, dans le cas d’un handshake TLS ceci rajouterait un temps considérable à chaque transfère de donnée car la connexion serait forcément initiée par un handshake. De plus, le contexte étant de l’IoT et LoRaWAN designé pour être basse consommation, un handshake serait très gourment pour un petit appareil IoT.

TODO à revoir

Il s’avère néanmois que d’après la documentation de thethingsnetwork, le dernier mode de chiffrement utilisé est ECB, celui-ci étant vivement déconseillé car il n’a pas de nonce.


## Cryptographie

### AES-ECB
C'est un algorithme de chiffrement symétrique par bloc non authentifié. De plus, les blocs ne sont pas chaînés entres eux ce qui rend cet algorithme maléable. Par ailleurs, il n'est pas authentifié, donc un bit de changement dans le texte clair implique un changement dans le texte chiffré de sortie, mais impossible de savoir pour le recepteur du texte chiffré si oui ou non il a été changé en cours de route.

#### Chiffrement
![AES-ECB_Encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/1024px-ECB_encryption.svg.png)

#### Déchiffrement
![AES-ECB_Encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/1024px-ECB_decryption.svg.png)

#### Problèmatique
Une problèmatique d'ECB est qu'il ne possède pas d'IV, ce qui le rend donc déterministe. Ceci veut dire concrètement qu'en chiffrant une fois un texte clair $P_1$, la sortie obtenu est $C_1$. Si $P_1$ est rechiffré dans un autre contexte, il aura toujours la même sortie, soit $C_1$.
Ceci est un problème lors, car l'algorithme est vulnérable aux analyses, car il laisse potentiellement fuiter de la données, vu qu'un texte clair a toujours le même texte chiffré.


La présente problèmatique peut être représentée par le chiffrement d'une image comme suit :


|Texte clair|Texte chiffré avec AES-ECB|
|---|---|
![](./figures/plainTux.svg.png)|![](./figures/encryptedECB.png)|


### AES-CCM
L'algorithme garantissant la confidentialité des données utilisées dans les différentes versions de LoRaWAN jusqu'à présent est AES-CCM. C'est un algorithme de chiffrement de données symmétrique authentifié, ceci garantissant ainsi l'intégrité des données. Plus précisément, cet algorithme utilise AES-CTR (counter mode), qui utilise un compteur et en plus, un AES-CMAC à la fin pour la partie authentification des données.

#### Chiffrement avec AES-CTR :
![AES-CTR_Encryption](./figures/CTR_encryption_2.svg.png)
#### Déchiffrement avec AES-CTR :
![AES-CTR_Decryption](./figures/CTR_decryption_2.svg.png)

#### Réutilisation d'IV

Comme cet algorithme utilise AES-CTR dans son fonctionnement interne, cet algorithme est donc un algorithme de chiffrement par flux. Ceci le rend donc vulnérable à la réutilisation d'IV pour une même clé. 

Dans le cas d'une réutilisation d'IV pour une même clé et deux textes clairs, il est possible d'obtenir l'égalité suivante :

$$
C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) \\
= P_1 \oplus P_2 \oplus (K \oplus K) \\
= P_1 \oplus P_2
$$

Ainsi il est possible faire fuiter le flux de clé permettant ensuite de déchiffrer un texte clair chiffré avec cette même clé car plus précisément :

Dans cette expression, $C_1$ à et $C_2$ représentent des textes chiffrés (ciphertexts), tandis que $P_1$ et $P_2$ sont des textes en clair (plaintexts), et $K$ est la clé de chiffrement utilisée. L'opération $\oplus$ indique un XOR (ou exclusif). La partie $K \oplus K$ s'annule, car toute valeur XOR avec elle-même est nulle, ce qui simplifie l'expression à $P_1 \oplus P_2$.

### Danger potentiel avec AES-CCM
Il est mentionné dans la spécification LoRaWAN que les mode de chiffrement utilisé pour chiffrer le contenu des *payload* est AES-CCM. Pour rappel, CCM est un mode de chiffrement par flot. Par conséquent, il inclu forcément l'utilisation d'un *IV* et qui ne doit jamais être réutilisé pour une même clé. 
Dans LoRaWAN, l'IV utilisé pour chiffrer la *payload* est le *frame counter* plus précisément le *FcntUp*. La terminaison des compteurs varie entre les deux séries de versions 1.0.x et 1.1.x. Ici, le cas de la version 1.1 est traité. *FcntUp* correspond au *frame counter* qui correspond au numéro de séquence de la trame courante envoyée du *end device* au *network server*. Celui-ci est codé sur 4 octets, soient 32 bits, ce qui signifie une possibilité de comptage maximum de $2^{32}=4294967296$. Plus précisément, pour une même clé utilisé, il ne faut pas que le compteur dépasse $2^{32}=4294967296$ ou réutilise une valeur de compteur déjà utilisé, sinon l'exploitation par réutilisation vue plus haut est applicable.

## Clés et dérivations
### V1.0.x
De manière générale, l’algorithme principal de chiffrement symmétrique utilisé est AES avec une longuer de clé 128 bits. Le mode de chiffrement peut varier en fonction des cas d’utilisations. D’après le [papier de sécurité de LoRaWAN Alliance](https://lora-alliance.org/wp-content/uploads/2020/11/lorawan_security_whitepaper.pdf), AES-CTR est utilisé pour le chiffrement des données qui vont transiter de l’appareil au serveur d’application et inversement. AES-CMAC est utilisé pour la protection d’intégrité. Les données entre l’appareil et le serveur d’application sont **chiffrées de bout en bout**. Le lien du whitepaper ci-contre fait référence à la version 1.0.6.
 
Dans la version LoRaWAN 1.0.x, il n’y a qu’une seule clé root key appelée `AppKey`. 

Depuis la version 1.1, il y a deux root keys, l’`AppKey` et la `NwkKey`. Sur la base des deux root keys citées, des clées de sessions sont dérivées pour garantir l’authenticité, l’intégrité ainsi que la confidentialité des données.

* Les *root keys* sont soulignées.

|Type de clé|Description|
|---|---|
|<ins>AppKey</ins> (Application key)|*Root key* utilisée pour dériver l'*AppSKey* et la *NwkSKey* pour la sécurité de la couche d'application.|
|NwkSKey (Network Session Key)|Utilisée pour le chiffrement/déchiffrement des *payloads* MAC et les calculs de MIC. Utilisée par le *end device* et le *network server*, elle est propre au *end device*.|
|AppSKey (Application Session Key)|Utilisée pour le chiffrement et le déchiffrement de la *payload* de l'application. Utilisée par le *end device* et le *network server*, propre au *end device*. Utilisée aussi pour calculer et vérifier un *MIC* au niveau applicatif, car celui-ci peut être inclu dans la *payload*.|

### V 1.1.x
Les deux clés sont hardcodées dans l’appareil par le fournisseur.

L'`AppKey` est une clé AES-128 bits unique partagée entre le *end device* et l'*Application Server*. Il est utilisé pour chiffrer et déchiffrer la charge utile des messages de données d'application et pour dériver l'`AppSKey`, qui est utilisée pour sécuriser la communication entre l'*end device* et l'*Application Server*. La `NwkKey` est une clé unique AES-128 bits partagée entre tous les *end devices* et *Network Server*. Ainsi, plusieurs *Network Server* sont impliqués dans la v1.1 ; par conséquent, `NwkKey` est utilisé pour générer la clé de session pour chaque serveur et des clés à vie spécifiques pour le *Join Server*.

* Les *root keys* sont soulignées.

|Type de clé|Description|
|---|---|
|<ins>NwkKey</ins> (Network Key)|*Root key* utilisée pour dériver plusieurs clés de session pour la sécurité de la couche réseau, notamment lors de l'activation OTAA, les clés dérivées sont FNwkSIntKey, SNwkSIntJey et NwkSEncKey. Assignée au *end device* par le fabricant.|
|<ins>AppKey</ins> (Application Key)|*Root key* utilisée pour dériver l'*AppSKey* pour la sécurité de la couche d'application. Assignée au *end device* par le fabricant.|
|FNwkSIntKey (Forwarding Network Session Integrity Key)	|Utilisée pour la protection de l'intégrité des messages de données de le *end device* vers le serveur réseau (montant).|
|SNwkSIntKey (Serving Network Session Integrity Key)	|Utilisée pour la protection de l'intégrité des messages entre les *end devices* et le *network server*. Aussi utilisée pour le chiffrement de la *payload*.|
|NwkSEncKey (Network Session Encryption Key)|Utilisée pour le chiffrement du champ de données la *payload*.|
|AppSKey (Application Session Key)|Utilisée pour le chiffrement et le déchiffrement de la *payload* de l'application.|


## [Activation de l’appareil](https://www.thethingsnetwork.org/docs/lorawan/end-device-activation/)
Il existe deux mode d’activation pour un appareil : OTAA et ABP. Le modèle préconisé est le OTAA car les clés de sessions sont différentes à chaque fois. En pratique, **ABP ne devrait jamais être utilisé dans un contexte de production.**

### OTAA
OTAA pour **O**ver **T**he **A**ir **A**ctivation : à chaque connexion de l’appareil de nouvelle clés de sessions sont dérivées des root keys et différentes des anciennes précédemment générées.

### ABP
ABP pour **A**ctivation **B**y **P**ersonalization : utilise toujours les mêmes clés de session.

# Architecture
Voici ci-dessous un schéma représentant l’acheminement de données entre le *end device* ainsi que le serveur d’application :

![[https://www.thethingsindustries.com/docs/getting-started/lorawan-basics/architecture.png](https://www.thethingsindustries.com/docs/getting-started/lorawan-basics/architecture.png)](./figures/lorawan_architecture.png)

[https://www.thethingsindustries.com/docs/getting-started/lorawan-basics/architecture.png](https://www.thethingsindustries.com/docs/getting-started/lorawan-basics/architecture.png)

Il est important de rappelé que le type de cryptographie utilisé est symmétrique. Ceci implique que les deux entités communiquante doivent être en mesure de lire les données (de les déchiffrer), c’est pour ceci que lors des dérivations de clés, la clé de chiffrement des données est connu par l’appareil final (**End node**) et le serveur d’application (**Application server**) seulement.

# Identifiant des entités LoRaWAN

**J**oin **E**xtended **U**nique **I**dentifier **JoinEUI** : est un identifiant unique assigné à chaque network server.

**D**evice **E**xtended **U**nique **I**dentifier  **DevEUI** : est un identifiant chaque appareil IoT.

**D**evice **N**once **DevNonce** : est une valeur de 16 bits générée aléatoirement par l’appareil final. Celle-ci est inclue dans la requête envoyée au Network Server pendant l’étape de Join Request. 

# Attaque potentielles
Dans LoRaWAN, les parties critiques en termes de sécurités sont les *root keys*, toutes la sécurité des transmissions sur le réseau se repose sur elles. Ainsi, si elles venaient à fuiter, le réseau ainsi que les communications se retrouveraient compromises.
Il est possible de dénombrer plusieurs scénarios d'attaques possibles en fonction :
- Attaque physique sur le *end device* : 
- Attaque sur le réseau :
- Attaque sur les clés : si la génération des clés n'est pas fait de manière aléatoire, il peut y avoir un risque de retrouver les clés et donc accéder à des données confidentielles.
- Attaque sur l'*application server* : si celui-ci venait à être infecter par un attaquant, il serait en mesure d'accéder à la clé symmétrique permettant de déchiffrer les données qui transitent sur le réseaux envoyées parle *end device*.

# Analyse

## Différences entre 1.0.x et 1.1.x
Il existe plusieurs différences notables entre les deux versions. Notamment au niveau du *frame counter*. 
# Lien intéressants

[https://www.slideshare.net/apnic/lorawan-in-depth](https://www.slideshare.net/apnic/lorawan-in-depth)

[https://www.thethingsnetwork.org/docs/lorawan/](https://www.thethingsnetwork.org/docs/lorawan/)

[https://www.youtube.com/watch?v=ZsVhYiX4_6o](https://www.youtube.com/watch?v=ZsVhYiX4_6o)

[https://www.youtube.com/watch?v=WPiV0YArKQ4](https://www.youtube.com/watch?v=WPiV0YArKQ4)

[https://www.thethingsnetwork.org/docs/lorawan/security/](https://www.thethingsnetwork.org/docs/lorawan/security/)

[https://www.thethingsnetwork.org/docs/lorawan/the-things-certified-security/](https://www.thethingsnetwork.org/docs/lorawan/the-things-certified-security/)

[https://lora-alliance.org/resource_hub/lorawan-security-whitepaper/](https://lora-alliance.org/resource_hub/lorawan-security-whitepaper/)

[https://lora-alliance.org/wp-content/uploads/2020/11/lorawan_security_whitepaper.pdf](https://lora-alliance.org/wp-content/uploads/2020/11/lorawan_security_whitepaper.pdf)

# Sniffing

[https://www.redalyc.org/journal/3442/344261485011/html/](https://www.redalyc.org/journal/3442/344261485011/html/)

[https://www.researchgate.net/publication/373349760_Exploring_LoRaWAN_Traffic_In-Depth_Analysis_of_IoT_Network_Communications](https://www.researchgate.net/publication/373349760_Exploring_LoRaWAN_Traffic_In-Depth_Analysis_of_IoT_Network_Communications)