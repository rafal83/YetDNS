# Lecture de NikoMalik/esp32-block

Source étudiée le 18 octobre 2026 : [dépôt](https://github.com/NikoMalik/esp32-block), [blocklist.cpp](https://github.com/NikoMalik/esp32-block/blob/main/src/blocklist.cpp) et [dns.cpp](https://github.com/NikoMalik/esp32-block/blob/main/src/dns.cpp).

L'index est compact : un hachage de 40 bits est séparé en préfixe de 16 bits et suffixe de 24 bits. Les préfixes désignent 65 536 buckets et seuls les suffixes sont stockés dans chaque bucket. Le fichier est mappé directement depuis une partition flash, ce qui évite les lectures aléatoires d'un système de fichiers.

Le benchmark `Blocklist::bench()` reconstruit des hachages présents dans l'index et chronomètre `inBlob()`. Il exclut le calcul du hachage du domaine, son analyse DNS, les règles, les sockets et le Wi-Fi. Le chiffre annoncé de 8 µs ne prouve donc pas un débit réseau de 123 000 requêtes DNS/s.

YetDNS utilise déjà une partition flash mappée et un répertoire de préfixes. Ses chaînes exactes occupent davantage de place. Un futur accélérateur pourrait ajouter des empreintes ou un filtre préalable, tout en vérifiant le domaine complet avant de décider d'un blocage. Ce changement doit être mesuré sur le traitement DNS complet et rester compatible avec les index persistants.

Les mises à jour ont aussi des contraintes différentes : ce dépôt charge un index compilé sur ordinateur ; YetDNS télécharge, fusionne et compile les sources sur l'ESP, puis valide une seconde partition avant de l'activer. Cette capacité et la conservation de l'ancienne liste doivent rester couvertes par les tests.

Aucun code de ce dépôt n'a été repris dans cette mise à jour.
