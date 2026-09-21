#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Télécharge des listes publiques de domaines pornographiques (plusieurs dizaines de milliers de
domaines) dans listes/externes/ pour compléter les listes intégrées.

    python maj_listes.py

Les fichiers sont nommés porno_*.txt : le préfixe "porno" indique la catégorie.
Aucune liste publique fiable n'existe pour les sites de rencontres : la liste intégrée
listes/rencontres.txt et les mots-clés font ce travail.
"""
import os
import sys
import urllib.request

SOURCES = [
    ("porno_stevenblack.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"),
    ("porno_blocklistproject.txt", "https://blocklistproject.github.io/Lists/porn.txt"),
]


def main():
    base = os.path.dirname(os.path.abspath(sys.argv[0]))
    out_dir = os.path.join(base, "listes", "externes")
    os.makedirs(out_dir, exist_ok=True)
    ok = 0
    for name, url in SOURCES:
        dest = os.path.join(out_dir, name)
        print("Téléchargement de %s ..." % url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "adguard-analyse"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            with open(dest, "wb") as fh:
                fh.write(data)
            n = sum(1 for l in data.decode("utf-8", "replace").splitlines() if l.strip() and not l.startswith("#"))
            print("  -> %s (%d lignes)" % (dest, n))
            ok += 1
        except Exception as e:  # noqa: BLE001
            print("  ECHEC : %s" % e)
    print("%d/%d liste(s) mise(s) à jour." % (ok, len(SOURCES)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
