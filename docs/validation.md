# Validation de YetDNS 0.2

Contrôles locaux réalisés le 18 octobre 2026 sur ESP32-S3 Wi-Fi, flash 16 Mo, PSRAM 8 Mo, avec ESP-IDF 5.5.1.

- Compilation du firmware N16R8 et du profil générique 8 Mo réussie. Firmware N16R8 final transféré sur la carte et vérifié par esptool.
- Deux suites C++ ASan/UBSan réussies : protocole DNS, cache, règles, paquets malformés, parseur et compilation des listes. Cinq tests Python réussis. Syntaxe JavaScript vérifiée avec Node.
- Sur la carte : réponses de blocage A/AAAA, UDP/TCP, résolution amont et cache vérifiés. Aucun jeton nécessaire pour l'administration ; journal actif.
- HaGeZi Light, HaGeZi Normal et StevenBlack téléchargées, fusionnées et dédoublonnées sur l'ESP : **232 588 domaines**, soit le résultat du compilateur indépendant sur les mêmes téléchargements. Mise à jour automatique réglée à 24 heures.
- Téléchargement volontairement inexistant : la liste active de 232 588 domaines et sa génération sont conservées. Restauration des sources et nouvelle actualisation réussies.
- Après reflash et redémarrage : liste persistante, génération et date de dernière réussite conservées ; aucun téléchargement lancé, échéance quotidienne restante restaurée après synchronisation de l'heure.
- Chromium réel : cinq onglets exclusifs, formulaires avancés, journal activé, exemple JSON par appareil valide, aucune erreur JavaScript. Captures bureau/mobile conservées dans le dossier privé de compilation.
- MQTT : connexion au broker configuré par le propriétaire confirmée par la carte. L'affichage des entités dans l'interface Home Assistant n'a pas été vérifié depuis cette session.

Ces contrôles valident les fonctions décrites, sans constituer une mesure comparative de débit, un test de vieillissement ou une campagne de coupures électriques pendant les écritures flash. Les journaux de navigation, identifiants, binaires configurés et sauvegardes restent exclus de Git.
