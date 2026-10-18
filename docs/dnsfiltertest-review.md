# Lecture de DNS Filter Test

Site trouvé à [dnsfiltertest.com](https://www.dnsfiltertest.com/), étudié le 18 octobre 2026. Le nom saisi « dnsfiltertsts.com » ne répondait pas.

Le [test de résolveurs](https://www.dnsfiltertest.com/test) envoie les domaines et le résolveur choisi à `/api/dns-test`. Les requêtes DNS sont faites par son backend. Ce mode permet une classification des réponses et des vérifications SafeSearch, mais ne mesure pas le DNS effectivement utilisé par le navigateur d'un utilisateur sur son LAN.

La page [Test this connection](https://www.dnsfiltertest.com/my-connection) travaille dans le navigateur : elle tente des connexions HTTPS sans lecture CORS des réponses. Ses scripts publics utilisent `fetch`, un délai d'abandon et un contrôle de disponibilité. Le site indique les ambiguïtés liées aux extensions et aux témoins synthétiques. Le code serveur n'est pas public dans les pages consultées ; son algorithme de classification DNS n'a donc pas été vérifié.

YetDNS suit le second principe, conformément à la demande : sondes issues du navigateur, aucune résolution DNS de test sur l'ESP, aucun appel au backend de ce site. Trois témoins légitimes précèdent les sondes. Les catégories sont séparées ; erreurs réseau, délais et restrictions de page sont distingués. Des témoins défaillants ou une exécution incomplète rendent les pourcentages non concluants. Un échec HTTPS reste un indice de filtrage possible, sans identification de sa cause.

Le navigateur impose `redirect: follow` avec le mode `no-cors`. Les sondes HEAD peuvent donc suivre les redirections HTTPS, tout en omettant cookies et référent et sans exécuter le contenu reçu. Les catégories facultatives expriment une politique choisie et ne dégradent pas artificiellement une note globale.

Le catalogue de départ est volontairement limité et éditable. Le témoin de sécurité et celui du contrôle parental sont documentés par [Cloudflare](https://developers.cloudflare.com/1.1.1.1/setup/). Leur résultat ne certifie pas la couverture des menaces réelles. Aucune liste privée ni aucun code du site n'ont été copiés.
