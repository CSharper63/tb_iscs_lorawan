---
title: "Travail de Bachelor - Cahier des Charges"
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

## Motivation
La vision de l'Internet-of-Things (IoT) promet une multitude d'objets connectés, capables d'échanger des informations sur un réseau universel.
Ces objets sont souvent contraints par leur taille et leur coût, ce qui limite la puissance disponible ainsi que la taille physique des antennes.
Ces contraintes peuvent exclure l'utilisation de technologies existantes, comme les réseaux mobiles ou les réseaux sans fil domestique.

Pour pallier à ces limitations, il existe des protocoles de communication "Low Power Wide Area Network" (LPWAN) tels que LoRaWAN, Sigfox, ou LTE-M, permettant de communiquer à longue distance et à basse puissance, en renonçant à un débit élevé. La communication se fait avec un réseau de stations de base communiquant entre elles par une infrastructure classique. Ce réseau peut être commercial (par exemple, Swisscom exploite un réseau LoRaWAN à l'usage de clients business), mais il existe aussi des réseaux publics formés par des participants volontaires, comme The Things Network.

Ces réseaux posent de nouveaux problèmes de sécurité: d'une part, l'interception des communications radio peut se faire facilement à plus grande échelle, de l'autre, un opérateur malveillant peut choisir de participer à un réseau public. Il est important d'étudier les risques posés par une telle technologie.

## Objectifs

 - Effectuer une synthèse des mécanismes de sécurité présents dans LoRaWAN
 - Evaluer les risques et élaborer des scénarios d'attaques possibles
 - Installer un point d'accès vers un réseau ouvert, et s'en servir pour collecter du trafic LoRaWAN
 - Analyser le trafic collecté pour y détecter la présence de problèmes éventuels

## Objectifs optionnels

 - Elaborer des scénarios d'attaques basés sur la falsification des coordonnées géographiques d'un point d'accès
 - Tester la viabilité des implémentations en radio software (USRP) pour moduler et démoduler le protocole LoRa sous-jacent
 - Elaborer des scénarios d'attaque sur la couche matérielle du protocole (timing, brouillage...)


## Livrables

 - Un rapport contenant:

   - Un état de l'art sur le fonctionnement de LoRaWAN
   - Une description synthétique de l'utilisation de la cryptographie dans la stack LoRaWAN, y compris les procédures de gestion de clés implémentées par les constructeurs et les opérateurs de réseaux publics.
   - Une description de la procédure employée pour mettre en place le point d'accès et le système de collecte de données
   - Les résultats de l'analyse de trafic
   - Les résultats des objectifs optionnels
   - Un journal de travail avec les heures réalisées

 - Les traces collectés, en format PCAP-ng.

