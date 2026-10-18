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

## Applications et exceptions dans YetDNS 0.3

- Catalogue NextDNS embarqué : 43 services, 403 suffixes distincts. Les données et leur licence MIT sont incluses, avec la révision source.
- Troisième suite C++ ASan/UBSan : chaque association service/domaine du snapshot est vérifiée, ainsi que les limites de suffixe, les masques globaux, le cumul par IP et la suppression/saturation des profils.
- Builds N16R8 et générique 8 Mo réussis ; syntaxe JavaScript validée.
- Navigateur Chromium : huit onglets, recherche YouTube, formulaires blanche/noire et exemple par appareil ; aucune erreur JavaScript.
- Test réel depuis l'IP du PC : activation de YouTube via l'interface, blocage du site et du CDN vidéo, A/AAAA et UDP/TCP ; autorisation par liste blanche malgré le blocage d'application ; domaine `.invalid` bloqué par liste noire. Les autres règles ont été conservées et les réglages de test restaurés.
- L'API refuse les identifiants d'applications inconnus sans changer les choix enregistrés.
- Les choix d'applications d'un profil de test ont survécu à un reflash/redémarrage ; le profil a ensuite été supprimé. La liste de 232 588 domaines a été rechargée sans téléchargement.

## Sauvegarde NVS et page HTTP

- Les règles sont enregistrées dans `listscfg/policy`, avec uniquement l'en-tête et les entrées utilisées. Aucun code de migration des anciennes règles ou des anciens paramètres n'est conservé.
- Test réel : six domaines de test et une règle de blocage par IP, remplacés douze fois successivement, relus à chaque écriture, puis retirés en conservant les autres règles. Toutes les sauvegardes ont réussi.
- Option HTTP activée temporairement : réponse A bloquée égale à l'IPv4 de l'ESP, réponse AAAA égale à `::`. Message HTTP 403 vérifié sur `/`, un chemin arbitraire et une route API avec le nom d'un domaine bloqué ; l'administration par IP reste accessible.
- La page a été affichée dans Chromium au format mobile. L'option et les règles de test ont été restaurées ensuite. Aucun test ne prétend fournir de page d'interception HTTPS.
- Les builds refusent désormais une frame C++ supérieure à 6 144 octets, pour détecter les gros objets locaux qui pourraient dépasser la pile de démarrage.
- Dernier reflash/redémarrage : les cinq règles sauvegardées par le propriétaire, les paramètres DNS et les choix d'applications ont été conservés. Les 232 588 domaines ont été rechargés sans téléchargement. Un nom redirigé reste isolé de l'administration même après désactivation de l'option HTTP, pendant l'expiration des caches clients.
