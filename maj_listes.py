#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Télécharge des listes publiques de domaines dans listes/externes/ pour compléter les listes
intégrées (à relancer de temps en temps : les listes évoluent).

    python maj_listes.py              # listes standard (GitHub) : ~350 000 domaines porno, ~10 000 rencontres
    python maj_listes.py --complet    # ajoute la liste UT1 complète (Université Toulouse Capitole,
                                      # référence des contrôles parentaux français) : adult (~4 millions
                                      # de domaines, ~100 Mo, analyse plus lente et gourmande en mémoire)
                                      # et dating, téléchargées directement sur dsi.ut-capitole.fr

Le préfixe du nom de fichier donne la catégorie : porno_*.txt, rencontres_*.txt, chat-aleatoire_*.txt.
Les listes intégrées (listes/porno.txt, listes/rencontres.txt...) restent prioritaires en cas de
désaccord, et listes/exclusions.txt permet de neutraliser un faux positif.
"""
import argparse
import io
import os
import sys
import tarfile
import urllib.request

# (fichier de sortie, URL, membre à extraire si archive tar.gz)
SOURCES = [
    ("rencontres_ut1.txt", "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/dating/domains", None),
    ("rencontres_shadowwhisperer.txt", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Dating", None),
    ("porno_shadowwhisperer.txt", "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Adult", None),
    ("porno_hagezi.txt", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt", None),
    ("porno_stevenblack.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts", None),
    ("porno_blocklistproject.txt", "https://blocklistproject.github.io/Lists/porn.txt", None),
]
SOURCES_COMPLET = [
    ("rencontres_ut1_direct.txt", "https://dsi.ut-capitole.fr/blacklists/download/dating.tar.gz", "dating/domains"),
    ("porno_ut1_adult.txt", "https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz", "adult/domains"),
]


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "adguard-analyse"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return resp.read()


def extract_member(data, member):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.name.endswith(member):
                return tar.extractfile(m).read()
    raise ValueError("membre %s introuvable dans l'archive" % member)


def main():
    ap = argparse.ArgumentParser(description="Mise à jour des listes externes de domaines.")
    ap.add_argument("--complet", action="store_true", help="ajouter les listes UT1 complètes (volumineuses)")
    args = ap.parse_args()
    base = os.path.dirname(os.path.abspath(sys.argv[0]))
    out_dir = os.path.join(base, "listes", "externes")
    os.makedirs(out_dir, exist_ok=True)
    sources = SOURCES + (SOURCES_COMPLET if args.complet else [])
    ok = 0
    for name, url, member in sources:
        dest = os.path.join(out_dir, name)
        print("Téléchargement de %s ..." % url)
        try:
            data = download(url)
            if member:
                data = extract_member(data, member)
            with open(dest, "wb") as fh:
                fh.write(data)
            n = sum(1 for l in data.decode("utf-8", "replace").splitlines() if l.strip() and not l.startswith("#"))
            print("  -> %s (%d domaines)" % (dest, n))
            ok += 1
        except Exception as e:  # noqa: BLE001
            print("  ECHEC : %s" % e)
            if os.path.isfile(dest):
                print("  (l'ancienne version de %s est conservée)" % name)
    print("%d/%d liste(s) mise(s) à jour dans %s" % (ok, len(sources), out_dir))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
