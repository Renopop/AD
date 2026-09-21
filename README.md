# Analyse des journaux AdGuard Home (surveillance parentale)

Outil Python **sans dépendance** (Python 3.8+, Tkinter inclus dans Python pour Windows) qui lit le
journal des requêtes DNS d'AdGuard Home (installé sur un NAS Synology, par exemple) et fait ressortir,
pour un appareil donné :

- les consultations de **sites pornographiques**, de **sites/applis de rencontres pour adultes**, d'**applis
  de « rencontre d'amis » visant les adolescents** (Yubo, Wizz, Hoop, Litmatch, Coco...) et de **tchats vidéo
  avec des inconnus** (type Omegle) ;
- filtrées par **appareil**, **dates**, **plages horaires** (y compris à cheval sur minuit, ex. 22h-6h)
  et **jours de la semaine** (week-end, semaine) ;
- les **activités récurrentes** : mêmes sites revus sur plusieurs jours, créneaux horaires typiques,
  jours de la semaine, sessions (durée, nombre de requêtes, bloquées ou autorisées par AdGuard) ;
- un rapport **texte**, **HTML** (carte jour × heure, tableaux) et un export **CSV** pour Excel.

Il permet aussi d'**identifier l'iPhone sans connaître son adresse MAC** : la commande `clients` liste
tous les appareils vus par AdGuard avec leur adresse IP, leur type probable (indices iOS / Android /
Windows) et les applis les plus utilisées (Snapchat, TikTok, Discord...).

Le programme est prévu pour tourner sur un PC Windows et être transformé en `.exe` avec PyInstaller.

---

## 1. Prérequis côté AdGuard Home

1. **Journal des requêtes activé** : *Paramètres > Paramètres généraux > Journal des requêtes*, avec une
   durée de conservation suffisante (90 jours conseillés). Sans journal, il n'y a rien à analyser.
2. Pour la lecture par le réseau (recommandée) : l'adresse d'AdGuard Home (ex. `http://192.168.1.10:3000`)
   et l'identifiant / mot de passe de son interface web.
3. Alternative : copier le fichier `querylog.json` (et `querylog.json.1`) depuis le NAS. Sur Synology avec
   Docker, il est dans le dossier partagé monté sur `/opt/adguardhome/work` du conteneur, par exemple
   `\\NAS\docker\adguardhome\work\data\querylog.json`.

### Les limites à connaître

- **iCloud Private Relay** (iPhone, avec un abonnement iCloud+) : quand il est actif, la navigation Safari
  passe par Apple et **n'apparaît pas** dans AdGuard. L'outil le détecte (requêtes vers `mask.icloud.com`)
  et vous prévient. Pour le neutraliser côté réseau, ajoutez dans AdGuard *Filtres > Règles de filtrage
  personnalisées* :
  ```
  ||mask.icloud.com^
  ||mask-h2.icloud.com^
  ```
  L'iPhone affichera alors que Private Relay n'est pas disponible sur ce réseau Wi-Fi.
- **Données mobiles (4G/5G)** : hors Wi-Fi, le téléphone n'utilise pas AdGuard. Seul le trafic Wi-Fi
  de la maison est visible.
- **Rencontres à l'intérieur des grandes applis** : Facebook Dating, les messages privés Instagram, Snapchat
  ou Discord utilisent les mêmes domaines que l'appli elle-même. Le DNS ne permet pas de les distinguer ;
  seuls les sites et applis dédiés sont détectables.

---

## 2. Installation

```
git clone https://github.com/Renopop/AD.git
cd AD
python adguard_analyse.py          # ouvre l'interface graphique
```

**Recommandé** : télécharger les listes publiques qui complètent les listes intégrées (à refaire de temps
en temps, elles évoluent) :

```
python maj_listes.py              # ~150 000 domaines pornographiques + 8 600 sites de rencontres (liste UT1)
python maj_listes.py --complet    # ajoute la liste UT1 complète "adult" (~4 millions de domaines, ~100 Mo,
                                  # analyse plus lente ; utile seulement si un site échappe aux listes standard)
```

Deux listes de sites de rencontres sont déjà livrées dans le dépôt et actives dès l'installation :
**UT1 « dating »** (8 600 domaines, `listes/externes/rencontres_ut1.txt`, licence CC BY-SA 4.0, Université
Toulouse Capitole) et **ShadowWhisperer « Dating »** (1 400 domaines, dont beaucoup de sites français,
seniors, cougars et « casual »). S'y ajoutent les 390 sites et applis de `listes/rencontres.txt` : toutes les marques des grands
groupes (Match Group, Bumble, Spark Networks, ParshipMeet) dans chaque pays, les sites généralistes majeurs
de France, Belgique, Suisse, Québec, Allemagne, Pays-Bas, Espagne, Italie, Royaume-Uni, Russie, Inde, Asie
et monde arabe, les cougars, sugar mommas, libertins, seniors, gay, escorts, les « petites amies IA » (Replika,
Candy.ai, Nomi...). Les applis de « rencontre d'amis » visant les adolescents (Yubo, Wizz, Hoop, Litmatch,
Spotafriend, MyLOL, Coco...) forment une catégorie à part, **Rencontres ados**, dans `listes/rencontres-ados.txt` :
c'est là que des adultes mal intentionnés entrent en contact avec des jeunes. Un site de rencontres dont le
nom contient « ados », « teen », « jeunes »... y est basculé automatiquement et une trentaine de
mots-clés en plusieurs langues (`rencontr`, `dating`, `cougar`, `sugarmomma`, `toyboy`, `incontri`...).
`maj_listes.py` rafraîchit ces listes et ajoute les listes porno (~350 000 domaines).

Sources : liste **UT1** de l'Université Toulouse Capitole (catégories *dating* et *adult*, référence des
contrôles parentaux et des établissements scolaires français), **ShadowWhisperer** (*Dating*, *Adult*),
**HaGeZi NSFW**, **StevenBlack porn**, **Blocklist Project porn**. Les listes intégrées `listes/*.txt` couvrent les principaux sites (et les CDN
des grands sites porno, les API des applis de rencontres) même sans ce téléchargement.

---

## 3. Utilisation avec l'interface graphique

1. Lancez `python adguard_analyse.py` (ou `AdGuardAnalyse.exe`).
2. **Source** : URL d'AdGuard, identifiant, mot de passe (ou choisissez un fichier `querylog.json`).
3. Cliquez **« Tester / lister les appareils »** : la liste des appareils s'affiche, avec le type probable
   (« iPhone/iPad (très probable) ») et les applis vues. Choisissez l'iPhone dans le menu déroulant
   « Appareil ».
4. Réglez les **dates** (boutons 7 / 30 / 90 jours), les **plages horaires** (`22h-6h`), les **jours**,
   les **catégories**.
5. **« Générer le rapport »** : le rapport texte s'affiche, le rapport HTML est écrit dans le dossier
   `rapports\` et s'ouvre dans le navigateur. **« Exporter CSV »** produit un fichier pour Excel.
6. **« Enregistrer les paramètres »** mémorise URL, identifiant, appareil, filtres (le mot de passe
   uniquement si vous cochez la case ; il est alors stocké en clair dans `adguard_analyse.config.json`).

---

## 4. Utilisation en ligne de commande

```
# Lister les appareils (pour trouver l'IP de l'iPhone)
python adguard_analyse.py clients --api http://192.168.1.10:3000 --user admin --password secret

# Rapport sur 30 jours, la nuit (22h-6h), pour l'appareil 192.168.1.42, avec HTML + CSV
python adguard_analyse.py rapport --api http://192.168.1.10:3000 --user admin --password secret ^
    --client 192.168.1.42 --jours 30 --heures 22h-6h --html rapport.html --csv detail.csv --ouvrir

# Même chose depuis un fichier copié du NAS, le week-end seulement, entre deux dates
python adguard_analyse.py rapport --log querylog.json --client 192.168.1.42 ^
    --du 01/09/2026 --au 21/09/2026 --weekend

# Une seule journée, plusieurs plages horaires, seulement la pornographie, chaque requête listée
python adguard_analyse.py rapport --log querylog.json --client 192.168.1.42 --jour 20/09/2026 ^
    --heures "12h-14h, 22h-7h" --categories porno --detail

# Vérifier comment un domaine serait classé
python adguard_analyse.py test-domaine fr.pornhub.com tinder.com essex.ac.uk
```

Options principales (`--help` pour tout voir) :

| Option | Rôle |
|---|---|
| `--api URL --user U --password P` | lecture par l'API d'AdGuard Home |
| `--log FICHIER...` | lecture de `querylog.json` (fichiers ou dossier ; `.gz` accepté) |
| `--client IP\|NOM` | appareil ciblé : IP exacte, `192.168.1.*`, ou partie du nom (`iphone`). Répétable |
| `--du`, `--au`, `--jour`, `--jours N` | période (dates `JJ/MM/AAAA` ou `AAAA-MM-JJ`, incluses) |
| `--heures "22h-6h, 12h-14h"`, `--nuit` | plages horaires (traversent minuit si besoin) |
| `--semaine lun,mar`, `--weekend` | jours de la semaine |
| `--categories porno,rencontres,rencontres-ados,chat-aleatoire` | catégories analysées (défaut : toutes) |
| `--seuil-recurrence N` | « récurrent » = vu au moins N jours différents (défaut 3) |
| `--gap MIN` | silence qui sépare deux sessions (défaut 10 min) |
| `--tz Europe/Paris` ou `+02:00` | fuseau d'affichage (défaut : celui du PC) |
| `--alias 192.168.1.42=iPhone-Ado` | nommer un appareil (ou fichier `listes/clients.txt`) |
| `--tous-sites N` | ajouter les N sites les plus visités par l'appareil, toutes catégories, pour repérer un site de rencontres inconnu des listes |
| `--html`, `--csv`, `--detail`, `--ouvrir` | sorties |

Le rapport indique pour chaque requête si AdGuard l'a **bloquée** (le site a été demandé mais pas
atteint, si le contrôle parental est actif) ou **autorisée** (le site a été atteint).

---

## 5. Identifier l'iPhone sans son adresse MAC

AdGuard journalise les requêtes par **adresse IP**, pas par adresse MAC. La commande `clients` (ou le
bouton du même nom) montre pour chaque IP :

- le **type probable** : un iPhone contacte `time-ios.apple.com`, `gsp-ssl.ls.apple.com`, etc. ;
  un Mac contacte `swscan.apple.com` ; un Android `connectivitycheck.gstatic.com` ;
- les **applis** (Snapchat, TikTok, Discord, Fortnite...) qui permettent de reconnaître le téléphone
  de l'adolescent parmi les autres appareils Apple de la maison ;
- le nom transmis par l'appareil s'il est connu d'AdGuard (`iPhone-de-Prénom`).

Pour que l'IP ne change pas : dans la box internet (Freebox, Livebox...), page DHCP, attribuez un **bail
statique** à cet appareil (la box affiche elle-même son adresse MAC, sans toucher au téléphone). Ou bien
déclarez-le dans AdGuard : *Paramètres > Paramètres des clients > Ajouter un client* avec son IP et un nom,
puis utilisez `--client iPhone-Ado`.

Note : iOS utilise une « adresse Wi-Fi privée » (MAC aléatoire) mais elle est stable pour un même réseau
Wi-Fi, donc le bail statique fonctionne.

---

## 6. Personnaliser la détection (dossier `listes/`)

| Fichier | Contenu |
|---|---|
| `porno.txt`, `rencontres.txt`, `rencontres-ados.txt`, `chat-aleatoire.txt` | domaines (sous-domaines inclus). Formats acceptés : `domaine.com`, `0.0.0.0 domaine.com`, `\|\|domaine.com^` |
| `motscles_*.txt` | mots-clés cherchés dans chaque partie du nom (`porn`, `^sex` = commence par, `sex$` = finit par, `=adult` = exactement) |
| `exclusions.txt` | faux positifs à ignorer : domaines (`adultswim.com`) ou mots (`essex`) |
| `clients.txt` | `IP  nom` pour nommer les appareils |
| `externes/` | listes téléchargées par `maj_listes.py` (préfixe `porno_`, `rencontres_`...) ; les listes intégrées restent prioritaires |

L'outil utilise aussi les décisions d'AdGuard : une requête bloquée par le **contrôle parental** est classée
« pornographie » même si le domaine n'est dans aucune liste, et un **service bloqué** (Tinder...) est classé
selon son nom.

Détection en trois couches, dans cet ordre : listes intégrées, listes externes, mots-clés
(`porn`, `xxx`, `rencontr`, `dating`, `flirt`, `libertin`, `cougar`...), puis décisions d'AdGuard. Un site de
rencontres inconnu des listes est donc quand même repéré si son nom contient un mot-clé, et le
rapport indique pour chaque domaine quelle couche l'a détecté. Quand un nom évoque à la fois le sexe et la
rencontre (`sexe-rencontre.com`, `sexy-cougars.net`), il est classé « rencontres ».

Pour débusquer un site de rencontres qui échapperait à tout cela, l'option `--tous-sites 60` (cochée par
défaut dans l'interface graphique) ajoute au rapport les sites les plus visités par l'appareil, toutes
catégories confondues : un nom inconnu qui revient chaque soir se repère à l'œil, et il suffit alors de
l'ajouter dans `listes/rencontres.txt`.

Astuce AdGuard : *Filtres > Services bloqués* permet de bloquer d'un clic Tinder, OnlyFans et
**iCloud Private Relay** ; *Paramètres > Paramètres généraux > Contrôle parental* bloque les sites pour adultes
connus d'AdGuard. Les tentatives apparaissent alors comme « bloquées » dans le rapport.

Le classement d'un domaine se teste avec `python adguard_analyse.py test-domaine <domaine>`.

---

## 7. Fabriquer le `.exe` (Windows)

```
pip install pyinstaller
build_exe.bat
```

Résultat dans `dist\` : `AdGuardAnalyse.exe` (interface graphique, sans fenêtre console) et
`adguard_analyse_cli.exe` (ligne de commande), plus le dossier `listes\` à garder à côté des `.exe`
(les listes intégrées dans l'exe servent de secours si le dossier est absent). Le fichier de configuration
et le dossier `rapports\` sont créés à côté de l'exe.

---

## 8. Tests et exemple

```
python exemples/generer_exemple.py exemples/querylog.json --jours 14   # journal fictif (iPhone, PC, Android)
python adguard_analyse.py clients --log exemples/querylog.json
python adguard_analyse.py rapport --log exemples/querylog.json --client 192.168.1.42 --nuit --html rapport.html
python -m unittest discover -s tests -v
```

Les tests couvrent l'analyse des dates/heures, la classification (dont les faux positifs), les filtres,
la détection des récurrences et des sessions, et la lecture par l'API grâce à un faux serveur AdGuard.
