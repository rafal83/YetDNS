# YetDNS sur ESP32

[![CI](https://github.com/rafal83/YetDNS/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/rafal83/YetDNS/actions/workflows/ci.yml)
[![Release](https://github.com/rafal83/YetDNS/actions/workflows/release.yml/badge.svg)](https://github.com/rafal83/YetDNS/actions/workflows/release.yml)
[![Dernière version](https://img.shields.io/github/v/release/rafal83/YetDNS?label=version)](https://github.com/rafal83/YetDNS/releases/latest)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-5.5.1-red)](https://docs.espressif.com/projects/esp-idf/en/v5.5.1/)
[![Carte](https://img.shields.io/badge/carte-ESP32--S3%20N16R8-blue)](#)

Filtre DNS local en C++ / **ESP-IDF 5.5.1**, développé pour un **ESP32-S3 Wi-Fi, flash 16 Mo et PSRAM 8 Mo**. Seule cette carte (**ESP32-S3 N16R8**) est supportée. Administration locale **sans jeton ni connexion**, journal activé par défaut, listes autonomes et découverte MQTT Home Assistant.

## Utilisation

Ouvrir l'adresse IP affichée sur le port série (carte actuellement déployée : `http://192.168.1.168`). Le menu réunit cinq onglets sur une ligne : **Filtrage**, **DNS avancé**, **Journal**, **Diagnostic** et **Home Assistant**. Sur petit écran, il défile horizontalement. Filtrage rassemble les listes automatiques, les applications, les listes blanche/noire et les règles locales dans quatre sections dépliables.

Fonctions disponibles :

- **Listes de blocage** : HaGeZi Light, HaGeZi Normal, StevenBlack, OISD Small, OISD Big, EasyPrivacy et URL HTTPS personnalisées ; jusqu'à six sources, activation individuelle, actualisation manuelle et intervalle automatique de 1 à 720 heures.
- **Applications** : catalogue de 43 services (YouTube, TikTok, Instagram, jeux, messageries, streaming…), recherche et catégories. Sélection globale ou blocages supplémentaires par IPv4, avec 16 profils. Les choix persistent en NVS sans téléchargement au démarrage.
- **Liste blanche / Liste noire** : domaines autorisés ou bloqués, un par ligne, globalement ou pour une IP. Les deux listes partagent les 32 règles locales avec les réécritures et conservent les règles des autres périmètres. Le JSON reste accessible dans Règles locales.
- **Paramètres avancés** : résolveurs IPv4 principal/secondaire, UDP ou DoH, URL HTTPS, timeout de 500 à 10 000 ms, limite de 0 à 1 000 requêtes/s/appareil, restriction au sous-réseau local et journalisation.
- **Règles locales** : 32 exceptions, blocages ou réécritures IPv4, globales ou par IP client. L'appareil a priorité sur les règles globales ; le suffixe le plus précis gagne dans chaque groupe.
- **Journal** : les 32 dernières requêtes, leur appareil, leur résultat et leur durée ; effacement manuel.
- **Diagnostic** : test exécuté dans le navigateur de l'appareil qui ouvre la page, liste personnalisable et rapports HTML/JSON ; aucun changement du DNS utilisé.
- **Home Assistant** : broker MQTT, identifiants, préfixe de découverte, fréquence de publication et état de connexion.

Les réglages sont persistants et s'appliquent sans reflash. Le journal garde uniquement les **32 dernières requêtes en RAM** ; son contenu disparaît au redémarrage et lors de sa désactivation. Il peut être effacé depuis l'interface.

Dans Journal, **Conserver uniquement les blocages** est activé par défaut. Ce choix est enregistré séparément en NVS : seuls les résultats `blocked` entrent alors dans le journal, y compris les blocages sur alias. Les requêtes autorisées, erreurs et limitations ne remplacent pas les 32 derniers blocages. Activer ce mode retire les autres entrées déjà présentes tout en conservant les blocages. Décocher la case reprend l'enregistrement de toutes les requêtes.

La section Règles locales contient un exemple expliqué pour `192.168.1.50` : `client` limite une règle à cet appareil, `deny` bloque, `allow` autorise malgré les listes et `rewrite` renvoie l'IPv4 définie dans `address`. Sans `client`, la règle est globale. Les règles couvrent le domaine et ses sous-domaines. Réserver l'IP par DHCP et faire interroger l'ESP directement : si un routeur relaie toutes les requêtes sous sa propre IP, le filtrage ne peut pas distinguer les appareils.

Dans Applications et dans les listes blanche/noire, laisser l'IP vide pour tous les appareils, ou saisir une IPv4 puis cliquer sur « Charger ce périmètre ». Modifier la sélection ou les domaines puis enregistrer. La recherche d'applications masque les lignes sans effacer les choix. Une sélection par appareil ajoute des blocages à ceux du périmètre global ; pour une exception, utiliser la liste blanche. Les règles locales sont évaluées avant les applications, puis les listes téléchargées. Les alias CNAME/DNAME sont également contrôlés.

Le catalogue embarqué est un instantané de [nextdns/services](https://github.com/nextdns/services), sous [licence MIT](data/nextdns-services-LICENSE.txt) ; sa révision est enregistrée dans `data/applications.json`. Ses 403 suffixes de domaines distincts sont recherchés exactement dans un index trié en flash. Le chemin DNS ne construit aucune règle et n'alloue pas de mémoire pour les applications. Le catalogue est actualisable avant compilation avec `python tools/update_app_catalog.py`, ou régénérable hors ligne avec `--offline`. Ses positions d'identifiants sont stables pour préserver les choix enregistrés. Ce blocage concerne les services entiers, peut affecter des fonctions partagées, et ne garantit pas de bloquer un VPN, un DNS externe ou une connexion déjà ouverte.

L'option **Page de blocage HTTP**, dans DNS avancé, est désactivée par défaut. Une fois activée, les réponses A bloquées renvoient l'IPv4 de l'ESP et celui-ci affiche « Accès bloqué par YetDNS » avec un statut HTTP 403, quel que soit le chemin demandé. Les hôtes redirigés n'accèdent pas à l'administration ; celle-ci reste disponible par l'IP de l'ESP ou `yetdns.local`. Les réponses AAAA restent `::`. HTTPS n'affiche pas cette page : une erreur de connexion ou de certificat apparaît, car le DNS seul ne permet pas d'intercepter une connexion chiffrée. Les réponses DNS locales ont un TTL de 60 secondes ; un appareil peut conserver temporairement l'ancien mode après changement.

Pour utiliser le filtrage sur le LAN, réserver l'IP de l'ESP dans le DHCP du routeur et la distribuer comme DNS (option DHCP 6). Un second DNS public peut contourner le filtre. Le serveur écoute sur IPv4 et traite aussi les enregistrements AAAA ; l'écoute IPv6 n'est pas encore implémentée. Vérifier les DNS IPv6 annoncés par le routeur et les appareils utilisant leur propre DoH/DoT.

## Test de la connexion depuis le navigateur

Ouvrir l'onglet **Diagnostic**, ou directement `http://192.168.1.168/diagnostic`, puis lancer le test. Il utilise la connexion effective du navigateur, y compris son éventuel DNS sécurisé, proxy, VPN et ses extensions. Le DNS de l'ESP n'est pas imposé. L'ESP héberge uniquement les fichiers de l'interface et ne réalise aucune sonde à la place du PC.

Le jeu par défaut contient 26 sondes : trois témoins légitimes, douze domaines publicitaires, dix domaines de traçage/télémétrie et un témoin synthétique de sécurité Cloudflare. Contrôle parental synthétique et réseaux sociaux sont facultatifs. Une liste personnalisée peut être collée ou importée depuis un fichier local ; 500 sondes maximum au total. Le fichier reste dans le navigateur. Le test ne change ni les règles de filtrage ni le DNS système.

Les requêtes sont des HTTPS HEAD `no-cors`, sans cookies ni référent, avec redirections HTTPS suivies par le navigateur. Aucun contenu de page n'est affiché ou exécuté. Les échecs réseau sont classés « filtrage possible », les délais dépassés et restrictions de page restent inconnus. Une panne générale, des témoins inaccessibles ou un arrêt partiel ne donnent pas un pourcentage de protection. Le rapport distingue les catégories et ne produit pas une note globale de sécurité : une extension, une erreur TLS ou un serveur hors ligne peuvent ressembler à un blocage DNS. Les réponses DNS brutes, le résolveur réel, la couverture A/AAAA et SafeSearch ne sont pas identifiables par cette méthode.

Les boutons exportent un **HTML autonome sans script ni requête réseau** et un JSON détaillé. Depuis l'ESP, les résultats restent dans le navigateur jusqu'à leur téléchargement ; ils ne sont envoyés à aucun serveur de test. Les domaines sondés voient nécessairement les connexions et l'IP de sortie. Les caches DNS du navigateur/système peuvent retarder l'effet d'un changement de configuration.

Pour utiliser exactement le même outil sans ESP, avec Python standard sur le PC :

```powershell
python tools/dns_protection_test.py --run --once
```

Le script ouvre le navigateur par défaut sur un serveur **local `127.0.0.1`**, lance les sondes côté navigateur, puis enregistre HTML et JSON dans `build-reports/` et s'arrête. `--output DOSSIER` choisit le dossier, `--no-open` affiche seulement l'URL et l'absence de `--run` laisse choisir les catégories avant le lancement. Ce mode transmet le rapport uniquement au serveur local du PC pour écrire les fichiers ; il ne dépend pas de l'ESP ni d'une API de diagnostic externe.

La méthode de [dnsfiltertest.com](https://www.dnsfiltertest.com/my-connection) a été étudiée ; voir [la note de comparaison](docs/dnsfiltertest-review.md). Les sondes sont une implémentation originale.

## Listes automatiques

**HaGeZi Light est sélectionnée par défaut, avec une mise à jour toutes les 24 heures.** Une première actualisation est déclenchée quand le Wi-Fi et l'heure SNTP sont disponibles. Les URL proviennent des dépôts primaires [HaGeZi](https://github.com/hagezi/dns-blocklists) et [StevenBlack](https://github.com/StevenBlack/hosts). Leurs licences respectives continuent de s'appliquer.

Au redémarrage, la dernière liste validée et la date de sa mise à jour sont relues en flash. Un redémarrage seul ne relance pas le téléchargement : l'échéance restante est recalculée après synchronisation de l'heure. Un téléchargement a lieu si la liste manque, si les sources ont changé, si l'intervalle automatique est écoulé, ou sur demande manuelle. Le bouton « Enregistrer et actualiser » demande explicitement une mise à jour.

L'ESP télécharge et compile les listes lui-même, sans ordinateur ni serveur de compilation. Formats pris en charge : domaines ASCII/Punycode, hosts (`0.0.0.0 domaine`) et règles simples `||domaine^`. Les commentaires, fins CRLF et fichiers sans saut de ligne final sont acceptés. Une liste qui commence par un en-tête `[Adblock Plus…]` est lue en mode tolérant : seules les règles `||domaine^` et `||domaine^$third-party` sont conservées, toutes les autres (exceptions `@@`, motifs d'URL, filtres cosmétiques, règles à options `$script`, `$image`, `domain=`…) sont ignorées, car un DNS ne voit pas l'URL. Cela permet d'utiliser directement `https://small.oisd.nl`, `https://big.oisd.nl` (233 000 domaines) ou `https://easylist.to/easylist/easyprivacy.txt` (47 000 domaines sur 57 000 lignes). Les exceptions d'une telle liste sont perdues : les ajouter dans la liste blanche. Hors en-tête Adblock Plus, les regex, exceptions `@@`, modificateurs et filtres cosmétiques restent refusés, pour ne jamais changer le sens d'une règle.

La fusion utilise un tableau de préparation en RAM avec comparaison exacte : les hachages servent uniquement au dédoublonnage, sans faux positif. Un sous-domaine déjà couvert par un domaine parent de la liste (`a.b.com` si `b.com` est bloqué) est écarté, ce qui ne change aucun résultat. Le résultat reste en flash sous forme de domaines inversés (`com.exemple.pub`), triés et compressés par préfixes communs, par blocs de 16 : environ 12 octets par domaine au lieu de 24, soit 2,9 Mio pour OISD Big (233 000 domaines) et 3,4 Mio pour OISD Big + EasyPrivacy. Une recherche examine les têtes de blocs par dichotomie, puis décode au plus 16 entrées. Sur la carte N16R8, la préparation utilise au maximum environ 7 Mio de PSRAM (un cinquième pour la table de hachage), soit une capacité d'environ 290 000 domaines ; une liste trop grande échoue explicitement, sans troncature silencieuse. Après une mise à jour depuis une version antérieure (liste au format 1, illisible), la liste intégrée filtre le temps que la liste soit retéléchargée au démarrage si l'actualisation automatique est active, sinon à la prochaine actualisation manuelle.

Deux partitions indépendantes conservent la liste active et la nouvelle version. Les téléchargements doivent tous réussir, les fichiers ne doivent pas être vides, et le CRC est vérifié avant publication. Un marqueur final valide la nouvelle copie. En cas d'échec, de coupure ou de capacité dépassée, la dernière copie valide reste disponible au démarrage. Les mises à jour n'effacent pas les règles locales. Un échec automatique est retenté après cinq minutes.

Si aucune source n'est activée, la liste compilée `data/blocked.txt` est utilisée (quatre domaines de démonstration). La capacité réelle dépend de la RAM disponible, de la taille des domaines et des partitions. Les deux partitions de liste font environ 6 Mo chacune ; la PSRAM sert à préparer les grandes listes (OISD Big, 2,9 Mio, y tient).

## DNS et performances

Serveur UDP/TCP avec connexions partielles/persistantes, inspection CNAME/DNAME, blocage A → `0.0.0.0`, AAAA → `::`, autres types → NOERROR sans réponse. Réécriture IPv4 : réponse A configurée, autres types sans réponse. Suspendre le blocage conserve les réécritures.

Le cache vieillit chaque TTL et expire au minimum des TTL (3 600 s au plus). Les réponses négatives (NXDOMAIN, NODATA) sont conservées selon la RFC 2308 : minimum du TTL et du MINIMUM du SOA, 300 s au plus, et seulement si la réponse contient un SOA. Il ne conserve pas les réponses tronquées, SERVFAIL, à TTL nul, ni les requêtes EDNS comportant des options. Une même question n'occupe qu'une entrée, rafraîchie par la dernière réponse. Le résolveur UDP principal n'est attendu que 800 ms au plus avant de basculer sur le secondaire. Les requêtes DO/CD sont distinctes. Paquets : maximum 4096 octets, UDP plafonné à 1232 ou 512 sans EDNS. Une réponse trop grande déclenche TC ; le résolveur amont est repris en TCP si nécessaire.

Le chemin DNS local n'alloue pas de mémoire applicative. Les requêtes amont, les mises à jour HTTPS et MQTT utilisent des tâches séparées. Wi-Fi sans économie d'énergie, CPU 240 MHz, cache de 1 024 entrées en PSRAM, indexé par un tableau de hachages en RAM interne pour que la recherche ne parcoure pas la PSRAM. Les files sont bornées : 4 workers amont (environ 11 Kio de RAM interne chacun) et 64 requêtes en attente (tampons en PSRAM) ; au-delà, une surcharge renvoie SERVFAIL et incrémente le compteur « saturations ». Ces valeurs sont des maxima (`menuconfig` > YetDNS) : si la mémoire manque au démarrage, les pools sont réduits plutôt que d'échouer, et le nombre de workers s'arrête avant d'épuiser la RAM interne. Le tableau de bord affiche la RAM interne libre et son minimum depuis le démarrage, et `/api/stats` ajoute `workers` et `stack_min_free` (marge de pile la plus faible) pour juger la marge avant d'augmenter ces valeurs. Les files de réception UDP (32 datagrammes) et la table de sockets lwIP sont dimensionnées dans `sdkconfig.defaults` ; les tampons TLS vont en PSRAM. Aucune supériorité de débit sur d'autres projets n'est encore démontrée par un banc comparatif.

En DoH, certificats et noms sont vérifiés ; aucun repli en clair des requêtes client. L'heure SNTP et le DNS de bootstrap restent nécessaires. La résolution initiale des noms des serveurs utilise le DNS de bootstrap en clair. Pour NextDNS, renseigner `https://dns.nextdns.io/VOTRE_PROFIL` comme URL DoH. La validation DNSSEC appartient au résolveur amont ; les réponses locales n'affirment jamais AD.

## Statistiques de blocage

L’onglet **Statistiques** affiche le top 10 des domaines bloqués (avec le nombre de blocages), le top 10 des appareils qui déclenchent le plus de blocages, et l’historique des 14 derniers jours (requêtes, blocages, part bloquée). Les compteurs sont enregistrés dans la flash de l’ESP (partition NVS `listscfg`) toutes les 10 minutes et à minuit, heure locale (`YETDNS_TIMEZONE`, Europe/Paris par défaut) : ils survivent aux redémarrages, avec au plus 10 minutes de détail perdues. Seuls les 10 premiers de chaque classement sont conservés après un redémarrage et pour les jours passés.

Le classement des domaines utilise un compteur borné (128 domaines distincts, 7 Kio de RAM) : exact tant que la table n'est pas pleine, puis approximatif pour les domaines peu fréquents (affiché « ≈ »). Les noms d’appareils viennent d’une requête mDNS inverse envoyée aux appareils les plus bloqués ; un appareil qui n’y répond pas (certains Android, objets connectés) reste affiché par son IP. Chaque blocage compte une fois par type de requête (A et AAAA comptent séparément, comme le compteur global).

## Home Assistant via MQTT

Configurer le même broker dans l'ESP et dans l'intégration MQTT de Home Assistant, puis activer l'intégration dans YetDNS. Exemple : `mqtt://192.168.1.10:1883`, ou `mqtts://broker.exemple:8883` avec certificat reconnu. Utilisateur et mot de passe sont séparés de l'URL ; le mot de passe enregistré n'est jamais renvoyé par l'API. Un champ vide conserve le secret existant.

La [découverte MQTT Home Assistant](https://www.home-assistant.io/integrations/mqtt/#mqtt-discovery) crée un appareil à identifiant stable dérivé de la MAC, avec :

- capteurs : requêtes, blocages, réponses du cache, domaines actifs, erreurs, RAM interne et durée de fonctionnement ;
- interrupteurs : protection DNS et journal ;
- boutons : actualiser les listes et vider le cache ;
- réglage numérique : limite de requêtes par seconde et par appareil.

Les annonces de découverte sont retenues et republiées après reconnexion ou redémarrage de Home Assistant. Un Last Will signale l'état hors ligne. Les commandes retenues sont ignorées pour éviter leur réexécution au redémarrage. Les domaines consultés ne sont pas publiés dans MQTT. Le broker n'est pas fourni par le firmware ; son adresse se configure dans l'interface.

## Installation et partitions

Dans un terminal ESP-IDF 5.5.1, pour la carte N16R8 :

```powershell
idf.py -B build-device -D SDKCONFIG=build-device/sdkconfig menuconfig
idf.py -B build-device build
idf.py -B build-device -p COM4 flash monitor
```

Renseigner le Wi-Fi dans `menuconfig` et remplacer le port selon la carte. Les identifiants restent dans le dossier `build-device` ignoré par Git et dans le binaire privé. Ne pas distribuer ce binaire.

Le partitionnement 0.5 prévoit deux emplacements firmware (`ota_0`, `ota_1`, 2 Mo), `otadata`, une partition NVS dédiée aux réglages (`listscfg`) et deux espaces de listes (environ 6 Mo chacun). Il remplace le partitionnement précédent : le passage à 0.5 se fait **une seule fois par USB**, après un effacement complet de la flash (`idf.py -B build-device -p COM4 erase-flash`), ce qui efface réglages, règles et listes. Les identifiants Wi-Fi de la compilation sont recopiés en NVS au démarrage ; les mises à jour suivantes se font sans fil.

## Mises à jour depuis GitHub

L’onglet **Mise à jour** compare la version installée à la dernière publication (« release ») du dépôt `YETDNS_UPDATE_REPO` (`rafal83/YetDNS`) via l’API GitHub, au clic ou une fois par jour (réglable). Si une version plus récente existe, le bouton **Installer la mise à jour** :

1. télécharge le fichier de la release correspondant à la carte (`yetdns-esp32s3-n16r8.bin`) en HTTPS avec vérification du certificat ;
2. refuse un fichier qui n’est pas un firmware YetDNS ou qui n’est pas plus récent que la version installée, avant d’écrire en flash ;
3. compare l’empreinte SHA-256 du fichier reçu à celle publiée par GitHub pour cette pièce jointe (sans empreinte, l’installation est refusée) ;
4. l’écrit dans l’emplacement inactif, active le nouvel emplacement puis redémarre.

Le nouveau firmware doit retrouver le réseau dans la minute qui suit son démarrage ; sinon, au redémarrage suivant, le chargeur de démarrage revient à la version précédente (annulation automatique). Réglages, règles, listes et statistiques sont conservés.

Publier une version : créer un tag `vX.Y.Z` (`git tag v0.5.0 && git push origin v0.5.0`). Un tag ne lance que le workflow de release : l'intégration continue (`ci.yml`) ne tourne que sur les pushes vers `master` et les pull requests, et la release ne rejoue pas les tests, donc attendre que la CI du commit soit verte avant de taguer. Le workflow `.github/workflows/release.yml` compile le firmware sans identifiants Wi-Fi et joint à la release `yetdns-esp32s3-n16r8.bin` (fichier de mise à jour) et sa variante `-first-flash.bin` (image complète à écrire à l’adresse 0x0 pour une première installation). Seules les publications officielles (ni brouillons ni pré-versions) sont proposées. Une carte flashée depuis un poste de développement dont la version n’est pas de la forme `X.Y.Z` se voit proposer n’importe quelle release. La mise à jour n’est pas signée : elle repose sur HTTPS vers GitHub, donc sur le contrôle du dépôt.

## API locale

| Route | Méthodes | Usage |
|---|---|---|
| `/api/stats` | GET | État DNS, mémoire, heure synchronisée |
| `/api/settings` | POST | `{"blocking":true}` |
| `/api/config` | GET / PUT | Réglages avancés, PUT partiel accepté |
| `/api/lists` | GET / PUT | Sources, calendrier, résultat et progression |
| `/api/lists/update` | POST | Déclenchement asynchrone, réponse 202 |
| `/api/mqtt` | GET / PUT | Réglages Home Assistant et état du broker |
| `/api/rules` | GET / PUT | Lecture/remplacement des règles locales |
| `/api/apps` | GET / PUT | Catalogue et profils ; PUT `{"client":"192.168.1.50","blocked":["youtube","tiktok"]}`, client vide/absent pour tous |
| `/api/top?day=N` | GET | Top 10 des domaines bloqués et des appareils avec le plus de blocages ; `day` 0 = aujourd’hui, 1 = hier… jusqu’à 13 |
| `/api/history` | GET | Requêtes et blocages des jours conservés |
| `/api/update` | GET / PUT | État de la mise à jour ; PUT `{"auto_check":true}` |
| `/api/update/check` | POST | Recherche d’une publication plus récente, réponse 202 |
| `/api/update/install` | POST | Installe la version vérifiée, réponse 202 puis redémarrage |
| `/api/logs` | GET | Journal en RAM |
| `/api/logs/clear` | POST | Effacement du journal |
| `/api/logs/config` | PUT | `{"blocked_only":true}` pour ne conserver que les blocages |
| `/api/cache/flush` | POST | Purge du cache |
| `/api/restart` | POST | Redémarre la carte après 1 s (bouton « Redémarrer » du tableau de bord) |

## Tests et mesures

```sh
python3 -m unittest discover -s tests -v
cmake -S tests -B build-host -DCMAKE_BUILD_TYPE=Debug
cmake --build build-host
ctest --test-dir build-host --output-on-failure
python3 tools/check_dashboard.py build-host/dashboard.js
node --check build-host/dashboard.js
```

Les tests GCC/Clang utilisent ASan/UBSan : protocole, TTL, règles par client, 100 000 paquets aléatoires, 20 000 mutations structurées, calendrier, parseur de listes, saturation mémoire, fusion de 20 000 domaines et compatibilité binaire avec le compilateur Python indépendant.

`tools/device_smoke.py`, avec le Python ESP-IDF, vérifie sur la carte HTTP, DNS UDP/TCP, A/AAAA et cache. `tools/benchmark.py --server IP --name pagead2.googlesyndication.com --queries 1000 --concurrency 4` mesure débit, latences et pertes. La limite par défaut de 500 requêtes/s/IP doit être désactivée pour mesurer la saturation ; les réponses REFUSED/SERVFAIL ne sont pas des résolutions réussies.

## Références et suite

Projets étudiés : [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker), [esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock), [ESP32_AdBlocker_Reborn](https://github.com/GlomarGadaffi/ESP32_AdBlocker_Reborn) et [NextDNS CLI](https://github.com/nextdns/nextdns). Implémentation originale, sans reprise de leur code. Leurs chiffres annoncés ne sont pas directement comparables à une mesure Wi-Fi de YetDNS.

L'étude de [NikoMalik/esp32-block](https://github.com/NikoMalik/esp32-block) et la portée de son benchmark sont détaillées dans [cette note](docs/esp32-block-review.md).

Restent à développer : écoute IPv6, OTA signé avec rollback, portail de configuration Wi-Fi, SafeSearch local, catégories/horaires, DoT/DoQ, déduplication des requêtes simultanées et inspection HTTPS/SVCB.
