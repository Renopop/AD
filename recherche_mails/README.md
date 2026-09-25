# Recherche de courriels sur un disque dur

Outil Python **sans dépendance** (Python 3.8+, Tkinter inclus dans Python pour Windows) pour retrouver et
fouiller des courriels stockés sur un disque : par expéditeur, destinataire, sujet, mots du texte, dates,
pièces jointes. Interface graphique et ligne de commande, transformable en `.exe` (voir `build_exe.bat`).

## Formats

| Format | Support |
|---|---|
| `.eml` (message unitaire) | lu entièrement |
| `.emlx` (Apple Mail) | lu entièrement |
| `.mbox`, `.mbx`, boîtes Thunderbird (dossiers `Mail`, `ImapMail`, `*.sbd`) | lues entièrement |
| `.msg` (Outlook) | recherche dans le texte brut extrait du fichier (sujet et expéditeur approximatifs) |
| `.pst`, `.ost` (Outlook), `.dbx` (Outlook Express) | **inventoriés seulement** : chemin et taille. À ouvrir avec Outlook ou à convertir (ex : `readpst` sous Linux/Mac) |

## Trois commandes

```
# Où sont les courriels sur le disque (types, tailles, dossiers, archives non lisibles)
python recherche_mails.py inventaire --dossier D:\

# Retrouver des messages
python recherche_mails.py chercher --dossier D:\Archives --de dupont --texte facture --du 01/01/2020 ^
    --html resultats.html --csv resultats.csv --extraire trouves

# Lister les adresses rencontrées (qui écrit à qui, combien de fois, sur quelle période)
python recherche_mails.py adresses --dossier D:\ --csv adresses.csv
```

Sans argument : l'interface graphique s'ouvre.

## Critères de recherche (tous cumulatifs, insensibles aux accents et à la casse)

| Option | Rôle |
|---|---|
| `--de TEXTE` | expéditeur (nom ou adresse) contient |
| `--a TEXTE` | destinataire (À ou Cc) contient |
| `--sujet TEXTE` | sujet contient |
| `--texte MOT` | corps ou sujet contient ; répétable = tous les mots doivent apparaître |
| `--partout MOT` | n'importe où (en-têtes, corps, noms de pièces jointes) |
| `--piece-jointe TEXTE` | nom d'une pièce jointe contient, ex : `.pdf` ou `facture` |
| `--avec-pj` | seulement les messages ayant au moins une pièce jointe |
| `--du`, `--au` | plage de dates (`JJ/MM/AAAA` ou `AAAA-MM-JJ`) |
| `--regex EXPR` | expression régulière dans le corps ou le sujet |
| `--types eml,mbox,...` | limiter aux formats indiqués |
| `--max N` | s'arrêter après N résultats |

## Sorties

- **HTML** (`--html`) : tableau avec un lien vers chaque fichier de message.
- **CSV** (`--csv`) : pour Excel.
- **Extraction** (`--extraire DOSSIER`) : copie chaque message trouvé en `.eml` (un fichier par message,
  y compris les messages tirés d'une boîte mbox), nommé `date_sujet.eml`.

## Fabriquer le `.exe` (Windows)

```
pip install pyinstaller
build_exe.bat
```

Produit `dist\RechercheMails.exe` (interface graphique) et `dist\recherche_mails_cli.exe` (ligne de commande).

## Tests

```
python -m unittest discover -s tests -v
```
