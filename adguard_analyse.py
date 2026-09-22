#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
adguard_analyse.py - Analyse des journaux de requêtes DNS d'AdGuard Home.

Objectif : repérer, pour un appareil donné (ex : l'iPhone d'un adolescent), les
consultations de sites sensibles (pornographie, rencontres, tchat avec des inconnus),
sur des dates et des plages horaires précises, et faire ressortir les activités
récurrentes (mêmes sites, mêmes créneaux, mêmes jours).

Fonctionne avec Python 3.8+ sans aucune bibliothèque externe (compatible PyInstaller).

Sources possibles :
  - l'API d'AdGuard Home sur le réseau  (--api http://IP_DU_NAS:3000 --user admin --password ...)
  - un ou plusieurs fichiers querylog.json copiés depuis le NAS (--log chemin/querylog.json)

Lancé sans argument, le script ouvre une interface graphique (Tkinter).
Lancé avec "--help", il affiche l'aide de la ligne de commande.
"""

import argparse
import base64
import collections
import csv
import datetime as dt
import gzip
import html
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0"

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

CATEGORIES = ["porno", "rencontres", "rencontres-ados", "chat-aleatoire"]
# Ordre d'examen des mots-clés : un site à la fois "sexe" et "rencontre" est classé rencontres
KEYWORD_ORDER = ["rencontres-ados", "rencontres", "chat-aleatoire", "porno"]
# Un site de rencontres / tchat dont le nom contient l'un de ces mots vise les mineurs
TEEN_MARKERS = {"ado", "ados", "teen", "teens", "teenager", "teenagers", "jeunes", "mineur", "mineurs", "lyceen", "lyceens"}
CATEGORY_LABELS = {
    "porno": "Pornographie",
    "rencontres": "Rencontres adultes",
    "rencontres-ados": "Rencontres ados",
    "chat-aleatoire": "Tchat vidéo avec inconnus",
}

# Codes "Reason" du fichier querylog.json d'AdGuard Home (filtering.Reason)
REASON_CODES = {
    0: "NotFilteredNotFound",
    1: "NotFilteredAllowList",
    2: "NotFilteredError",
    3: "FilteredBlockList",
    4: "FilteredSafeBrowsing",
    5: "FilteredParental",
    6: "FilteredInvalid",
    7: "FilteredSafeSearch",
    8: "FilteredBlockedService",
    9: "Rewritten",
    10: "RewrittenAutoHosts",
    11: "RewrittenRule",
}
REASON_LABELS = {
    "NotFilteredNotFound": "autorisé",
    "NotFilteredAllowList": "autorisé (liste blanche)",
    "NotFilteredError": "autorisé (erreur)",
    "FilteredBlockList": "bloqué (liste de filtres)",
    "FilteredSafeBrowsing": "bloqué (navigation sécurisée)",
    "FilteredParental": "bloqué (contrôle parental)",
    "FilteredInvalid": "bloqué (invalide)",
    "FilteredSafeSearch": "recherche sécurisée forcée",
    "FilteredBlockedService": "bloqué (service bloqué)",
    "Rewritten": "réécrit",
    "RewrittenAutoHosts": "réécrit (hosts)",
    "RewrittenRule": "réécrit (règle)",
}
BLOCKED_REASONS = {"FilteredBlockList", "FilteredSafeBrowsing", "FilteredParental",
                   "FilteredInvalid", "FilteredBlockedService"}

WEEKDAYS_FR = ["lun", "mar", "mer", "jeu", "ven", "sam", "dim"]
WEEKDAYS_FR_LONG = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]

# Suffixes publics à deux niveaux les plus courants (pour retrouver le "domaine de base")
SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "co.nz", "com.br", "com.mx", "com.ar", "co.za",
    "co.kr", "com.tr", "com.cn", "com.tw", "com.hk", "com.sg", "co.in", "co.il",
    "com.es", "com.pt", "com.ua", "com.ru", "com.pl", "asso.fr", "gouv.fr", "com.fr",
}

# Signatures permettant de reconnaître un appareil sans connaître son adresse MAC
DEVICE_SIGNATURES = {
    "apple": ["apple.com", "icloud.com", "icloud-content.com", "apple-dns.net", "mzstatic.com",
              "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com", "apple.news", "itunes.com"],
    "ios": ["time-ios.apple.com", "gsp-ssl.ls.apple.com", "gspe1-ssl.ls.apple.com",
            "gsp64-ssl.ls.apple.com", "iphone-ld.apple.com", "gateway.icloud.com",
            "init.itunes.apple.com", "smoot.apple.com", "guzzoni.apple.com"],
    "macos": ["time-macos.apple.com", "swscan.apple.com", "swdist.apple.com", "swcdn.apple.com"],
    "android": ["android.googleapis.com", "connectivitycheck.gstatic.com", "android.clients.google.com",
                "play.googleapis.com", "mtalk.google.com", "samsungcloud.com", "smartthings.com",
                "xiaomi.com", "miui.com", "huawei.com", "hicloud.com", "oppomobile.com"],
    "windows": ["msftconnecttest.com", "windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com"],
    "private_relay": ["mask.icloud.com", "mask-h2.icloud.com", "mask-api.icloud.com", "mask-canary.icloud.com"],
    "dns_chiffre": ["dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.adguard.com",
                    "dns.adguard-dns.com", "nextdns.io", "dns.quad9.net", "doh.opendns.com",
                    "dns.nextdns.io", "doh.cleanbrowsing.org", "dns.controld.com"],
}
APP_SIGNATURES = {
    "Snapchat": ["snapchat.com", "sc-cdn.net", "sc-jpl.com", "snapkit.com", "feelinsonice.com", "feelinsonice-hrd.appspot.com"],
    "TikTok": ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokv.eu", "tiktokcdn-eu.com", "byteoversea.com", "ibytedtos.com", "musical.ly", "tiktokrow-cdn.com"],
    "Instagram": ["instagram.com", "cdninstagram.com"],
    "Discord": ["discord.com", "discordapp.com", "discord.gg", "discord.media", "discordapp.net"],
    "WhatsApp": ["whatsapp.net", "whatsapp.com"],
    "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com"],
    "Twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
    "Spotify": ["spotify.com", "scdn.co", "spotifycdn.com"],
    "Deezer": ["deezer.com", "dzcdn.net"],
    "Netflix": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    "Fortnite/Epic": ["epicgames.com", "fortnite.com", "unrealengine.com"],
    "Roblox": ["roblox.com", "rbxcdn.com"],
    "Minecraft": ["minecraft.net", "mojang.com"],
    "BeReal": ["bereal.com", "bere.al"],
    "Telegram": ["telegram.org", "t.me", "telegram.me"],
    "Facebook/Messenger": ["facebook.com", "fbcdn.net", "messenger.com", "facebook.net"],
    "X/Twitter": ["twitter.com", "twimg.com", "x.com"],
    "Pinterest": ["pinterest.com", "pinimg.com", "pinterest.fr"],
    "Steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    "PlayStation": ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"],
    "Xbox": ["xboxlive.com", "xbox.com"],
    "Nintendo": ["nintendo.net", "nintendo.com"],
    "Reddit": ["reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"],
    "Amazon": ["amazon.fr", "amazon.com", "amazon.de", "primevideo.com", "media-amazon.com"],
    "Google": ["google.com", "googleapis.com", "gstatic.com", "google.fr"],
    "Apple / iCloud (système)": ["apple.com", "icloud.com", "icloud-content.com", "apple-dns.net", "mzstatic.com",
                                 "aaplimg.com", "cdn-apple.com", "apple-cloudkit.com"],
    "Microsoft (système)": ["microsoft.com", "msftconnecttest.com", "windowsupdate.com", "live.com", "office.com"],
    "Jeux mobiles divers": ["supercell.com", "supercellgames.com", "clashroyaleapp.com", "brawlstarsgame.com",
                            "kingapps.io", "king.com", "miniclip.com", "gameloft.com", "ea.com", "activision.com",
                            "callofduty.com", "mihoyo.com", "hoyoverse.com", "playrix.com", "rovio.com", "zynga.com"],
    "Twitter/X": ["twitter.com", "twimg.com", "x.com"],
    "Wattpad": ["wattpad.com", "wattpad.io"],
    "Crunchyroll / animes": ["crunchyroll.com", "vrv.co", "animedigitalnetwork.fr", "adn.fr"],
    "Publicité / mesure d'audience (bruit des applis)": [
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com", "app-measurement.com",
        "crashlytics.com", "firebase.io", "firebaseio.com", "firebaseinstallations.googleapis.com", "appsflyer.com",
        "adjust.com", "adjust.io", "branch.io", "amplitude.com", "mixpanel.com", "segment.io", "sentry.io", "onesignal.com",
        "unityads.unity3d.com", "applovin.com", "applvn.com", "ironsrc.com", "supersonicads.com", "chartboost.com",
        "vungle.com", "inmobi.com", "moatads.com", "adcolony.com", "adnxs.com", "criteo.com", "criteo.net", "rubiconproject.com",
        "pubmatic.com", "openx.net", "taboola.com", "outbrain.com", "scorecardresearch.com", "demdex.net", "omtrdc.net",
        "adsrvr.org", "casalemedia.com", "smartadserver.com", "bidswitch.net", "liftoff.io", "tapjoy.com", "fyber.com",
        "singular.net", "kochava.com", "braze.com", "appboy.com", "appboycdn.com", "hotjar.com", "datadoghq.com",
        "bugsnag.com", "newrelic.com", "nr-data.net", "flurry.com", "adform.net", "yieldmo.com", "sharethrough.com"],
    "Infrastructure / CDN (bruit technique)": [
        "akamai.net", "akamaiedge.net", "akamaized.net", "akamaihd.net", "edgekey.net", "edgesuite.net", "cloudfront.net",
        "amazonaws.com", "cloudflare.com", "cloudflare.net", "fastly.net", "fastlylb.net", "azureedge.net", "azure.com",
        "windows.net", "llnwd.net", "cdn77.org", "jsdelivr.net", "unpkg.com", "gvt1.com", "gvt2.com", "1e100.net",
        "ntp.org", "pool.ntp.org", "digicert.com", "letsencrypt.org", "globalsign.com", "sectigo.com", "pki.goog",
        "apple-dns.net", "captive.apple.com", "msftncsi.com", "connectivitycheck.gstatic.com", "in-addr.arpa", "ip6.arpa"],
}
NOISE_APPS = {"Publicité / mesure d'audience (bruit des applis)", "Infrastructure / CDN (bruit technique)"}


# Indices (indicatifs) sur la nature de l'activité d'après le sous-domaine demandé
HOST_HINTS = [
    (re.compile(r"^mmg(-fna)?\.whatsapp\.net$"), "WhatsApp", "média envoyé ou reçu (photo, vidéo, vocal, document)"),
    (re.compile(r"^media-.*\.cdn\.whatsapp\.net$"), "WhatsApp", "média téléchargé"),
    (re.compile(r"^pps\.whatsapp\.net$"), "WhatsApp", "photos de profil consultées"),
    (re.compile(r"^(e\d+|g)\.whatsapp\.net$"), "WhatsApp", "connexion à la messagerie"),
    (re.compile(r"^static\.whatsapp\.net$"), "WhatsApp", "ouverture de l'appli"),
    (re.compile(r"^(app|gcp\.api|api)\.snapchat\.com$"), "Snapchat", "appli active (messages, stories)"),
    (re.compile(r".*\.sc-cdn\.net$"), "Snapchat", "snaps / stories chargés"),
    (re.compile(r"^i\.instagram\.com$"), "Instagram", "appli active (fil, messages)"),
    (re.compile(r"^scontent.*\.cdninstagram\.com$"), "Instagram", "photos / vidéos chargées"),
    (re.compile(r"^v\d+.*\.tiktokcdn.*$|^v\d+-.*\.tiktokv.*$"), "TikTok", "vidéos regardées"),
    (re.compile(r"^api\d+.*\.tiktokv.*$"), "TikTok", "appli active"),
    (re.compile(r"^gateway\.discord\.gg$"), "Discord", "connexion au tchat"),
    (re.compile(r"^(cdn\.discordapp\.com|media\.discordapp\.net)$"), "Discord", "images / fichiers échangés"),
    (re.compile(r".*\.discord\.media$"), "Discord", "appel vocal / vidéo"),
    (re.compile(r".*\.googlevideo\.com$"), "YouTube", "vidéos regardées"),
]


def host_hint(host):
    for rx, app, text in HOST_HINTS:
        if rx.match(host):
            return app, text
    return None, None


def app_of_host(host):
    suffixes = set(host_suffixes(host))
    for app, sigs in APP_SIGNATURES.items():
        for sg in sigs:
            if sg in suffixes:
                return app
    return None


# ---------------------------------------------------------------------------
# Utilitaires temps
# ---------------------------------------------------------------------------

_TIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_time(value):
    """Convertit une date RFC3339 (avec nanosecondes éventuelles) en datetime avec fuseau."""
    if not value:
        return None
    m = _TIME_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    if tz is None or tz == "Z":
        tzinfo = dt.timezone.utc
    else:
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        tzinfo = dt.timezone(sign * dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        return dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo)
    except ValueError:
        return None


def get_timezone(name):
    """Retourne un objet fuseau horaire pour --tz, ou None pour le fuseau local du PC."""
    if not name or name.lower() in ("local", "locale"):
        return None
    try:
        import zoneinfo  # Python 3.9+
        return zoneinfo.ZoneInfo(name)
    except Exception:
        m = re.match(r"^(?:UTC)?([+-])(\d{1,2})(?::?(\d{2}))?$", name.strip(), re.I)
        if m:
            sign = 1 if m.group(1) == "+" else -1
            return dt.timezone(sign * dt.timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0)))
        raise ValueError("Fuseau horaire inconnu : %s (sous Windows, installez le paquet 'tzdata' "
                         "ou utilisez un décalage comme +02:00)" % name)


def to_local(t, tz):
    return t.astimezone(tz) if tz is not None else t.astimezone()


def day_bounds(date, tz):
    """Début (00:00:00) et fin (23:59:59.999999) d'une date, dans le fuseau demandé."""
    start = dt.datetime.combine(date, dt.time.min)
    end = dt.datetime.combine(date, dt.time.max)
    if tz is not None:
        return start.replace(tzinfo=tz), end.replace(tzinfo=tz)
    return start.astimezone(), end.astimezone()


def parse_date(value):
    """Accepte AAAA-MM-JJ, JJ/MM/AAAA, JJ-MM-AAAA, 'aujourdhui', 'hier'."""
    v = value.strip().lower()
    today = dt.date.today()
    if v in ("aujourdhui", "aujourd'hui", "today"):
        return today
    if v in ("hier", "yesterday"):
        return today - dt.timedelta(days=1)
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d/%m/%y", "%Y%m%d"):
        try:
            return dt.datetime.strptime(v, fmt).date()
        except ValueError:
            pass
    raise ValueError("Date invalide : %s (attendu AAAA-MM-JJ ou JJ/MM/AAAA)" % value)


_HOUR_RE = re.compile(r"^\s*(\d{1,2})(?:[:hH](\d{2})?)?\s*$")


def parse_hour(value):
    m = _HOUR_RE.match(value)
    if not m:
        raise ValueError("Heure invalide : %s (attendu 22h, 22:30, 6h30...)" % value)
    h, mi = int(m.group(1)), int(m.group(2) or 0)
    if h > 24 or mi > 59 or (h == 24 and mi > 0):
        raise ValueError("Heure invalide : %s" % value)
    return h * 60 + mi


def parse_hour_ranges(value):
    """'22h-6h, 12:00-14:00' -> [(1320, 360), (720, 840)] en minutes depuis minuit."""
    ranges = []
    if not value:
        return ranges
    for part in re.split(r"[,;]", value):
        part = part.strip()
        if not part:
            continue
        pieces = re.split(r"\s*(?:-|à|a|>)\s*", part, maxsplit=1)
        if len(pieces) != 2:
            raise ValueError("Plage horaire invalide : %s (attendu 22h-6h)" % part)
        start, end = parse_hour(pieces[0]), parse_hour(pieces[1])
        ranges.append((start % 1440, end if end == 1440 else end % 1440))
    return ranges


def minute_in_ranges(minute, ranges):
    if not ranges:
        return True
    for start, end in ranges:
        if start == end:
            return True  # plage de 24 h
        if start < end:
            if start <= minute < end:
                return True
        else:  # traverse minuit
            if minute >= start or minute < end:
                return True
    return False


def parse_weekdays(value):
    """'lun,mar' ou 'weekend' ou 'semaine' -> ensemble de numéros de jour (0 = lundi)."""
    if not value:
        return None
    v = value.strip().lower()
    if v in ("weekend", "week-end", "we"):
        return {5, 6}
    if v in ("semaine", "ecole", "école"):
        return {0, 1, 2, 3, 4}
    days = set()
    for part in re.split(r"[,; ]+", v):
        if not part:
            continue
        found = False
        for i, name in enumerate(WEEKDAYS_FR):
            if part.startswith(name) or part.startswith(WEEKDAYS_FR_LONG[i]):
                days.add(i)
                found = True
                break
        if not found:
            raise ValueError("Jour inconnu : %s (attendu lun, mar, mer, jeu, ven, sam, dim, weekend, semaine)" % part)
    return days or None


def fmt_dt(t):
    return t.strftime("%d/%m/%Y %H:%M:%S")


def fmt_date(d):
    return d.strftime("%d/%m/%Y")


def fmt_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return "%d s" % seconds
    if seconds < 3600:
        return "%d min" % (seconds // 60)
    return "%dh%02d" % (seconds // 3600, (seconds % 3600) // 60)


# ---------------------------------------------------------------------------
# Domaines
# ---------------------------------------------------------------------------

def ip_sort_key(ip):
    """Clé de tri sûre pour IPv4, IPv6 et identifiants clients (jamais de comparaison int/str)."""
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a), "")
    except ValueError:
        return (9, 0, str(ip))


def normalize_host(host):
    return (host or "").strip().strip(".").lower()


def base_domain(host):
    """Domaine 'de base' : pornhub.com pour fr.pornhub.com, bbc.co.uk pour www.bbc.co.uk."""
    labels = normalize_host(host).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_suffixes(host):
    labels = normalize_host(host).split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def host_matches_any(host, suffixes):
    for s in host_suffixes(host):
        if s in suffixes:
            return True
    return False


# ---------------------------------------------------------------------------
# Listes et classification
# ---------------------------------------------------------------------------

class Keyword(object):
    __slots__ = ("text", "mode")

    def __init__(self, raw):
        raw = raw.strip().lower()
        if raw.startswith("="):
            self.mode, self.text = "exact", raw[1:]
        elif raw.startswith("^"):
            self.mode, self.text = "prefix", raw[1:]
        elif raw.endswith("$"):
            self.mode, self.text = "suffix", raw[:-1]
        else:
            self.mode, self.text = "contains", raw

    def matches(self, label):
        if self.mode == "exact":
            return label == self.text
        if self.mode == "prefix":
            return label.startswith(self.text)
        if self.mode == "suffix":
            return label.endswith(self.text)
        return self.text in label

    def __str__(self):
        return {"exact": "=%s", "prefix": "^%s", "suffix": "%s$", "contains": "%s"}[self.mode] % self.text


def _read_list_lines(path):
    lines = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            # format hosts : "0.0.0.0 domaine" ou "127.0.0.1 domaine"
            if len(parts) >= 2 and re.match(r"^(0\.0\.0\.0|127\.0\.0\.1|::1?|::)$", parts[0]):
                line = parts[1]
            # format AdGuard : ||domaine^
            m = re.match(r"^\|\|([^\^/|$]+)\^?", line)
            if m:
                line = m.group(1)
            lines.append(line)
    return lines


class Classifier(object):
    """Classe un nom de domaine dans une catégorie (ou aucune)."""

    def __init__(self):
        self.domains = {}          # domaine -> (catégorie, source)
        self.keywords = {c: [] for c in CATEGORIES}
        self.excluded_domains = set()
        self.excluded_labels = set()
        self.sources = []

    def add_domains(self, category, domains, source, priority=0):
        """priority : 0 = listes intégrées (prioritaires), 1 = listes externes téléchargées."""
        n = 0
        for d in domains:
            d = normalize_host(d)
            if d and d not in self.domains:
                self.domains[d] = (category, source, priority)
                n += 1
        return n

    def add_keywords(self, category, keywords):
        for k in keywords:
            if k.strip():
                self.keywords.setdefault(category, []).append(Keyword(k))

    def add_exclusions(self, lines):
        for line in lines:
            line = line.strip().lower()
            if not line:
                continue
            if "." in line:
                self.excluded_domains.add(normalize_host(line))
            else:
                self.excluded_labels.add(line)

    def load_directory(self, directory):
        """Charge listes/<categorie>.txt, motscles_<categorie>.txt, exclusions.txt, externes/*."""
        if not directory or not os.path.isdir(directory):
            return False
        excl = os.path.join(directory, "exclusions.txt")
        if os.path.isfile(excl):
            self.add_exclusions(_read_list_lines(excl))
        for cat in CATEGORIES:
            p = os.path.join(directory, cat + ".txt")
            if os.path.isfile(p):
                n = self.add_domains(cat, _read_list_lines(p), os.path.basename(p))
                self.sources.append("%s (%d domaines)" % (os.path.basename(p), n))
            p = os.path.join(directory, "motscles_" + cat + ".txt")
            if os.path.isfile(p):
                kws = _read_list_lines(p)
                self.add_keywords(cat, kws)
                self.sources.append("%s (%d mots-clés)" % (os.path.basename(p), len(kws)))
        ext = os.path.join(directory, "externes")
        if os.path.isdir(ext):
            for name in sorted(os.listdir(ext)):
                cat = None
                for c in sorted(CATEGORIES, key=len):
                    if name.lower().startswith(c):
                        cat = c
                if cat is None:
                    continue
                p = os.path.join(ext, name)
                n = self.add_domains(cat, _read_list_lines(p), "externes/" + name, priority=1)
                self.sources.append("externes/%s (%d domaines)" % (name, n))
        return True

    def is_excluded(self, host):
        return host_matches_any(host, self.excluded_domains)

    def classify(self, host, reason=None, service_name=None):
        """Retourne (catégorie, source, détail) ou (None, None, None)."""
        host = normalize_host(host)
        if not host or self.is_excluded(host):
            return None, None, None
        best = None
        for suffix in host_suffixes(host):
            hit = self.domains.get(suffix)
            if hit and (best is None or hit[2] < best[0][2]):
                best = (hit, suffix)   # liste intégrée prioritaire sur liste externe, sinon suffixe le plus long
        if best:
            return best[0][0], "liste " + best[0][1], best[1]
        # chaque partie du nom, plus ses morceaux séparés par des tirets (hot-matures -> hot, matures)
        # (texte, entier) : un nom à tirets n'est testé en entier que par les mots-clés "contenu"
        labels = []
        for l in host.split("."):
            if l in self.excluded_labels:
                continue
            if "-" in l:
                labels.append((l, False))
                labels.extend((p, True) for p in l.split("-") if p and p not in self.excluded_labels)
            else:
                labels.append((l, True))
        for cat in KEYWORD_ORDER:
            for kw in self.keywords.get(cat, []):
                for label, whole in labels:
                    if (whole or kw.mode == "contains") and kw.matches(label):
                        if cat in ("rencontres", "chat-aleatoire") and any(
                                w and l in TEEN_MARKERS for l, w in labels):
                            return "rencontres-ados", "mot-clé", "%s + ados" % kw
                        return cat, "mot-clé", str(kw)
        if service_name:
            svc = service_name.lower()
            for cat in KEYWORD_ORDER:
                for kw in self.keywords.get(cat, []):
                    if kw.matches(svc):
                        return cat, "service bloqué AdGuard", service_name
        if reason == "FilteredParental":
            return "porno", "AdGuard contrôle parental", "FilteredParental"
        return None, None, None


def find_lists_directory(explicit=None):
    """Cherche le dossier 'listes' : argument, à côté du script/.exe, dossier courant, ressources PyInstaller."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidates.append(os.path.join(exe_dir, "listes"))
    if getattr(sys, "frozen", False):
        candidates.append(os.path.join(os.path.dirname(sys.executable), "listes"))
    candidates.append(os.path.join(os.getcwd(), "listes"))
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(os.path.join(meipass, "listes"))
    for c in candidates:
        if c and os.path.isdir(c):
            return os.path.abspath(c)
    return None


def load_mac_vendors(directory):
    """listes/fabricants_mac.txt : 'XXXXXX Fabricant' (préfixes OUI de l'IEEE, format nmap)."""
    table = {}
    if not directory:
        return table
    p = os.path.join(directory, "fabricants_mac.txt")
    if not os.path.isfile(p):
        return table
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line or line[0] == "#":
                continue
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and len(parts[0]) == 6:
                table[parts[0].upper()] = parts[1].strip()
    return table


def normalize_mac(mac):
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()


def mac_vendor(mac, table):
    """Fabricant d'après les 6 premiers caractères, ou 'adresse aléatoire' (bit local des téléphones récents)."""
    m = normalize_mac(mac)
    if len(m) < 6:
        return ""
    try:
        first = int(m[:2], 16)
    except ValueError:
        return ""
    if first & 0x02:
        return "adresse aléatoire (téléphone/tablette récent)"
    return table.get(m[:6], "fabricant inconnu")


def load_leases_file(path):
    """leases.json d'AdGuard Home (dossier data/) -> {ip: {mac, hostname, static}}."""
    leases = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    for l in data.get("leases") or []:
        ip = l.get("ip")
        if ip:
            leases[ip] = {"mac": l.get("mac") or "", "hostname": l.get("hostname") or "",
                          "static": bool(l.get("static")) or not l.get("expires"), "expires": l.get("expires") or ""}
    return leases


def load_client_aliases(directory, extra=None):
    aliases = {}
    if directory:
        p = os.path.join(directory, "clients.txt")
        if os.path.isfile(p):
            for line in _read_list_lines(p):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    aliases[parts[0].strip().lower()] = parts[1].strip()
    for item in extra or []:
        if "=" in item:
            k, v = item.split("=", 1)
            aliases[k.strip().lower()] = v.strip()
    return aliases


# ---------------------------------------------------------------------------
# Lecture des journaux
# ---------------------------------------------------------------------------

class Entry(object):
    """Une requête DNS normalisée (quel que soit le format source)."""
    __slots__ = ("time", "host", "client", "client_name", "reason", "blocked", "rule", "service", "qtype")

    def __init__(self, time, host, client, client_name, reason, blocked, rule, service, qtype):
        self.time = time
        self.host = host
        self.client = client
        self.client_name = client_name
        self.reason = reason
        self.blocked = blocked
        self.rule = rule
        self.service = service
        self.qtype = qtype


def entry_from_file(d):
    t = parse_time(d.get("T"))
    if t is None:
        return None
    result = d.get("Result") or {}
    reason_code = result.get("Reason", 0)
    reason = REASON_CODES.get(reason_code, str(reason_code)) if isinstance(reason_code, int) else str(reason_code)
    blocked = bool(result.get("IsFiltered")) and reason in BLOCKED_REASONS
    rule = result.get("Rule") or ""
    if not rule:
        rules = result.get("Rules") or []
        if rules and isinstance(rules[0], dict):
            rule = rules[0].get("Text") or ""
    client = d.get("IP") or d.get("CID") or ""
    return Entry(t, normalize_host(d.get("QH")), str(client), "", reason, blocked, rule,
                 result.get("ServiceName") or "", d.get("QT") or "")


def entry_from_api(d):
    t = parse_time(d.get("time"))
    if t is None:
        return None
    q = d.get("question") or {}
    reason = d.get("reason") or "NotFilteredNotFound"
    blocked = reason in BLOCKED_REASONS
    rule = d.get("rule") or ""
    if not rule:
        rules = d.get("rules") or []
        if rules and isinstance(rules[0], dict):
            rule = rules[0].get("text") or ""
    info = d.get("client_info") or {}
    return Entry(t, normalize_host(q.get("name")), str(d.get("client") or ""), info.get("name") or "",
                 reason, blocked, rule, d.get("service_name") or "", q.get("type") or "")


def iter_file_entries(paths, progress=None):
    """Lit les fichiers querylog.json (une entrée JSON par ligne, .gz accepté)."""
    for path in paths:
        opener = gzip.open if path.lower().endswith(".gz") else open
        n = 0
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line[0] != "{":
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                e = entry_from_file(d)
                if e is not None:
                    yield e
                n += 1
                if progress and n % 20000 == 0:
                    progress("%s : %d lignes lues" % (os.path.basename(path), n))
        if progress:
            progress("%s : %d lignes lues" % (os.path.basename(path), n))


def expand_log_paths(paths):
    """Accepte des fichiers, des dossiers (querylog.json*), ou rien (recherche dans le dossier courant)."""
    out = []
    for p in paths or ["."]:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.startswith("querylog.json"):
                    out.append(os.path.join(p, name))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise FileNotFoundError("Fichier introuvable : %s" % p)
    # le fichier le plus récent (querylog.json) en premier, puis .1, .2...
    return sorted(set(out), key=lambda x: (len(os.path.basename(x)), os.path.basename(x)))


class AdGuardAPI(object):
    def __init__(self, url, user=None, password=None, insecure=False, timeout=30):
        self.base = url.rstrip("/")
        if not re.match(r"^https?://", self.base, re.I):
            self.base = "http://" + self.base
        self.timeout = timeout
        self.headers = {"User-Agent": "adguard-analyse/" + VERSION}
        if user is not None:
            token = base64.b64encode(("%s:%s" % (user, password or "")).encode("utf-8")).decode("ascii")
            self.headers["Authorization"] = "Basic " + token
        self.ctx = None
        if insecure:
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def get_json(self, path, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise RuntimeError("Identifiants AdGuard refusés (HTTP %d). Vérifiez --user / --password." % e.code)
            raise RuntimeError("Erreur HTTP %d sur %s" % (e.code, url))
        except urllib.error.URLError as e:
            raise RuntimeError("Impossible de joindre AdGuard Home à %s : %s" % (self.base, e.reason))

    def status(self):
        return self.get_json("/control/status")

    def clients(self):
        """Clients connus d'AdGuard (nom -> identifiants) pour nommer les appareils."""
        aliases = {}
        try:
            data = self.get_json("/control/clients")
        except Exception:
            return aliases
        for c in (data.get("clients") or []):
            for ident in c.get("ids") or []:
                aliases[str(ident).lower()] = c.get("name") or ""
        for c in (data.get("auto_clients") or []):
            ip = c.get("ip")
            name = c.get("name")
            if ip and name and ip.lower() not in aliases:
                aliases[ip.lower()] = name
        return aliases

    def dhcp_leases(self):
        """Baux DHCP d'AdGuard Home (si son serveur DHCP est actif) -> {ip: {mac, hostname, static}}."""
        leases = {}
        try:
            data = self.get_json("/control/dhcp/status")
        except Exception:
            return leases
        for key, static in (("leases", False), ("static_leases", True)):
            for l in data.get(key) or []:
                ip = l.get("ip")
                if ip:
                    leases[ip] = {"mac": l.get("mac") or "", "hostname": l.get("hostname") or "",
                                  "static": static, "expires": l.get("expires") or ""}
        return leases

    def iter_querylog(self, since=None, search=None, limit=500, progress=None):
        """Parcourt le journal du plus récent au plus ancien jusqu'à la date 'since'."""
        older_than = None
        total = 0
        while True:
            params = {"limit": limit}
            if older_than:
                params["older_than"] = older_than
            if search:
                params["search"] = search
            data = self.get_json("/control/querylog", params)
            entries = data.get("data") or []
            if not entries:
                break
            for d in entries:
                e = entry_from_api(d)
                if e is not None:
                    yield e
            total += len(entries)
            oldest = data.get("oldest") or entries[-1].get("time")
            if progress:
                progress("API : %d requêtes lues (jusqu'au %s)" % (total, (oldest or "")[:19].replace("T", " ")))
            if not oldest or oldest == older_than:
                break
            older_than = oldest
            t = parse_time(oldest)
            if since is not None and t is not None and t < since:
                break


# ---------------------------------------------------------------------------
# Analyse
# ---------------------------------------------------------------------------

class Filters(object):
    def __init__(self, since=None, until=None, hour_ranges=None, weekdays=None, clients=None,
                 categories=None, tz=None):
        self.since = since              # datetime aware ou None
        self.until = until
        self.hour_ranges = hour_ranges or []
        self.weekdays = weekdays        # set ou None
        self.clients = [c.strip().lower() for c in (clients or []) if c.strip()]
        self.categories = list(categories or CATEGORIES)
        self.tz = tz

    def client_matches(self, ip, names):
        if not self.clients:
            return True
        ip_l = (ip or "").lower()
        names_l = [n.lower() for n in names if n]
        for c in self.clients:
            if c == ip_l:
                return True
            if c.endswith("*") and ip_l.startswith(c[:-1]):
                return True
            for n in names_l:
                if c == n or c in n:
                    return True
        return False


class Record(object):
    """Requête retenue par les filtres et classée dans une catégorie."""
    __slots__ = ("time", "host", "base", "client", "client_name", "category", "source", "detail",
                 "blocked", "reason", "rule", "service")

    def __init__(self, e, local_time, client_name, category, source, detail):
        self.time = local_time
        self.host = e.host
        self.base = base_domain(e.host)
        self.client = e.client
        self.client_name = client_name
        self.category = category
        self.source = source
        self.detail = detail
        self.blocked = e.blocked
        self.reason = e.reason
        self.rule = e.rule
        self.service = e.service


class ClientStats(object):
    def __init__(self, ip):
        self.ip = ip
        self.names = set()
        self.count = 0
        self.first = None
        self.last = None
        self.signals = collections.Counter()
        self.apps = collections.Counter()
        self.categories = collections.Counter()
        self.hours = [0] * 24
        self.days = set()

    def add(self, e, local_time, category):
        self.count += 1
        if e.client_name:
            self.names.add(e.client_name)
        if self.first is None or local_time < self.first:
            self.first = local_time
        if self.last is None or local_time > self.last:
            self.last = local_time
        self.hours[local_time.hour] += 1
        self.days.add(local_time.date())
        if category:
            self.categories[category] += 1
        suffixes = set(host_suffixes(e.host))
        for key, sigs in DEVICE_SIGNATURES.items():
            for s in sigs:
                if s in suffixes:
                    self.signals[key] += 1
                    break
        for app, sigs in APP_SIGNATURES.items():
            for s in sigs:
                if s in suffixes:
                    self.apps[app] += 1
                    break

    def guess(self):
        s = self.signals
        if s["ios"] > 0 and s["macos"] == 0:
            return "iPhone/iPad (très probable)"
        if s["apple"] > 0 and s["macos"] > 0:
            return "Mac"
        if s["apple"] > 0 and s["android"] == 0:
            return "Apple (iPhone/iPad probable)"
        if s["android"] > 0:
            return "Android"
        if s["windows"] > 0:
            return "Windows"
        return "?"


class Analysis(object):
    def __init__(self, filters, classifier, aliases=None, keep_all_hosts=False, keep_all_records=False):
        self.filters = filters
        self.all_records = [] if keep_all_records else None   # (heure locale, hôte) du client sélectionné
        self.classifier = classifier
        self.aliases = aliases or {}
        self.leases = {}            # ip -> {mac, hostname, static}
        self.mac_vendors = {}
        self.records = []
        self.clients = {}
        self.total_scanned = 0
        self.total_in_period = 0
        self.total_selected = 0        # requêtes du/des client(s) choisi(s) dans la période + horaires
        self.selected_per_day = collections.Counter()
        self.selected_per_hour = [0] * 24
        self.selected_heatmap = [[0] * 24 for _ in range(7)]
        self.selected_hosts = collections.Counter() if keep_all_hosts else None
        self.period_first = None
        self.period_last = None

    def client_names(self, e):
        names = []
        if e.client_name:
            names.append(e.client_name)
        alias = self.aliases.get((e.client or "").lower())
        if alias:
            names.append(alias)
        lease = self.leases.get(e.client)
        if lease and lease.get("hostname"):
            names.append(lease["hostname"])
        return names

    def lease_info(self, ip):
        """(mac, fabricant, nom DHCP, statique) pour une IP, ou ('', '', '', False)."""
        lease = self.leases.get(ip)
        if not lease:
            return "", "", "", False
        return lease.get("mac", ""), mac_vendor(lease.get("mac", ""), self.mac_vendors), lease.get("hostname", ""), lease.get("static", False)

    def display_name(self, ip, names):
        names = [n for n in names if n]
        return names[0] if names else ip

    def feed(self, entries):
        f = self.filters
        for e in entries:
            self.total_scanned += 1
            if f.until is not None and e.time > f.until:
                continue
            if f.since is not None and e.time < f.since:
                continue
            self.total_in_period += 1
            local = to_local(e.time, f.tz)
            if self.period_first is None or local < self.period_first:
                self.period_first = local
            if self.period_last is None or local > self.period_last:
                self.period_last = local
            category, source, detail = self.classifier.classify(e.host, e.reason, e.service)
            if category not in f.categories:
                category = None
            cs = self.clients.get(e.client)
            if cs is None:
                cs = self.clients[e.client] = ClientStats(e.client)
            cs.add(e, local, category)
            names = self.client_names(e)
            if not f.client_matches(e.client, names):
                continue
            if not minute_in_ranges(local.hour * 60 + local.minute, f.hour_ranges):
                continue
            if f.weekdays is not None and local.weekday() not in f.weekdays:
                continue
            self.total_selected += 1
            self.selected_per_day[local.date()] += 1
            self.selected_per_hour[local.hour] += 1
            self.selected_heatmap[local.weekday()][local.hour] += 1
            if self.selected_hosts is not None:
                self.selected_hosts[base_domain(e.host)] += 1
            if self.all_records is not None:
                self.all_records.append((local, e.host))
            if category is None:
                continue
            self.records.append(Record(e, local, self.display_name(e.client, names), category, source, detail))
        self.records.sort(key=lambda r: r.time)


def build_sessions(records, gap_minutes):
    """Regroupe les requêtes sensibles en 'sessions' (silence > gap => nouvelle session)."""
    sessions = []
    gap = dt.timedelta(minutes=gap_minutes)
    by_client = collections.defaultdict(list)
    for r in records:
        by_client[r.client].append(r)
    for client, recs in by_client.items():
        current = None
        for r in recs:
            if current is None or r.time - current["end"] > gap:
                current = {"client": client, "client_name": r.client_name, "start": r.time, "end": r.time,
                           "count": 0, "blocked": 0, "domains": collections.Counter(),
                           "categories": collections.Counter()}
                sessions.append(current)
            current["end"] = r.time
            current["count"] += 1
            current["blocked"] += 1 if r.blocked else 0
            current["domains"][r.base] += 1
            current["categories"][r.category] += 1
    sessions.sort(key=lambda s: s["start"])
    return sessions


def build_domain_stats(records):
    stats = {}
    for r in records:
        key = (r.client, r.category, r.base)
        s = stats.get(key)
        if s is None:
            s = stats[key] = {"client": r.client, "client_name": r.client_name, "category": r.category,
                              "domain": r.base, "count": 0, "blocked": 0, "days": set(),
                              "hours": collections.Counter(), "weekdays": collections.Counter(),
                              "first": r.time, "last": r.time, "hosts": collections.Counter(),
                              "source": r.source, "detail": r.detail}
        s["count"] += 1
        s["blocked"] += 1 if r.blocked else 0
        s["days"].add(r.time.date())
        s["hours"][r.time.hour] += 1
        s["weekdays"][r.time.weekday()] += 1
        s["hosts"][r.host] += 1
        if r.time < s["first"]:
            s["first"] = r.time
        if r.time > s["last"]:
            s["last"] = r.time
    return sorted(stats.values(), key=lambda s: (-len(s["days"]), -s["count"]))


def typical_slots(hours_counter, min_share=0.15):
    """Renvoie les créneaux horaires typiques : heures contiguës concentrant l'activité."""
    total = sum(hours_counter.values())
    if not total:
        return []
    keep = {h for h, c in hours_counter.items() if c >= max(1, min_share * total) or c == max(hours_counter.values())}
    slots = []
    for h in range(24):
        if h in keep:
            if slots and slots[-1][1] == h:
                slots[-1][1] = h + 1
            else:
                slots.append([h, h + 1])
    # fusion 23h-0h
    if len(slots) > 1 and slots[0][0] == 0 and slots[-1][1] == 24:
        slots[-1][1] = slots[0][1]
        slots.pop(0)
    return ["%02dh-%02dh" % (a, b % 24) for a, b in slots]


def build_report(analysis, threshold_days=3, gap_minutes=10, top=25, top_sites=0):
    f = analysis.filters
    recs = analysis.records
    days_in_period = sorted(analysis.selected_per_day.keys())
    if f.since is not None and f.until is not None:
        d0, d1 = to_local(f.since, f.tz).date(), to_local(f.until, f.tz).date()
        n_days = (d1 - d0).days + 1
    else:
        n_days = len(days_in_period) or 1

    by_cat = collections.Counter(r.category for r in recs)
    blocked_by_cat = collections.Counter(r.category for r in recs if r.blocked)
    domain_stats = build_domain_stats(recs)
    recurrent = [s for s in domain_stats if len(s["days"]) >= threshold_days]
    sessions = build_sessions(recs, gap_minutes)

    heat = [[0] * 24 for _ in range(7)]
    hours = collections.Counter()
    per_day = {}
    for r in recs:
        heat[r.time.weekday()][r.time.hour] += 1
        hours[r.time.hour] += 1
        d = per_day.setdefault(r.time.date(), {"total": 0, "blocked": 0, "cats": collections.Counter()})
        d["total"] += 1
        d["blocked"] += 1 if r.blocked else 0
        d["cats"][r.category] += 1
    session_days = collections.Counter(s["start"].date() for s in sessions)

    # créneaux et jours récurrents toutes catégories confondues
    weekday_counts = collections.Counter(r.time.weekday() for r in recs)
    active_days = sorted({r.time.date() for r in recs})

    # clients sélectionnés
    selected_clients = {}
    for r in recs:
        selected_clients.setdefault(r.client, r.client_name)
    if not selected_clients and f.clients:
        for ip, cs in analysis.clients.items():
            names = list(cs.names) + ([analysis.aliases.get(ip.lower())] if analysis.aliases.get(ip.lower()) else [])
            if f.client_matches(ip, names):
                selected_clients[ip] = analysis.display_name(ip, names)

    warnings = []
    if analysis.total_scanned == 0:
        warnings.append("Aucune requête lue : vérifiez la source (fichier vide ou API sans journal).")
    elif analysis.total_in_period == 0:
        warnings.append("Aucune requête dans la période demandée : vérifiez les dates et la durée de "
                        "conservation du journal dans AdGuard (Paramètres > Journal des requêtes).")
    elif f.clients and not selected_clients and analysis.total_selected == 0:
        warnings.append("Aucune requête pour le client demandé (%s). Utilisez la commande 'clients' pour "
                        "voir les appareils connus." % ", ".join(f.clients))
    for ip, cs in analysis.clients.items():
        names = list(cs.names)
        if f.clients and not f.client_matches(ip, names + [analysis.aliases.get(ip.lower(), "")]):
            continue
        if cs.signals["private_relay"]:
            warnings.append("%s : iCloud Private Relay (mask.icloud.com) détecté %d fois. Quand il est actif, "
                            "la navigation Safari contourne AdGuard et n'apparaît PAS dans ce journal. "
                            "Pour le désactiver côté réseau : bloquez mask.icloud.com et mask-h2.icloud.com "
                            "dans AdGuard (Filtres > Règles personnalisées : ||mask.icloud.com^ et ||mask-h2.icloud.com^)."
                            % (analysis.display_name(ip, names), cs.signals["private_relay"]))
        if cs.signals["dns_chiffre"]:
            warnings.append("%s : contact avec un serveur DNS chiffré public détecté %d fois (dns.google, "
                            "cloudflare-dns.com...). Une appli ou un profil peut contourner AdGuard."
                            % (analysis.display_name(ip, names), cs.signals["dns_chiffre"]))

    top_sites_rows = []
    if top_sites and analysis.selected_hosts:
        for dom, n in analysis.selected_hosts.most_common(top_sites):
            cat = analysis.classifier.classify(dom)[0]
            top_sites_rows.append((dom, n, cat))

    return {
        "top_sites": top_sites_rows,
        "generated": dt.datetime.now(),
        "filters": f,
        "n_days": n_days,
        "period_first": analysis.period_first,
        "period_last": analysis.period_last,
        "total_scanned": analysis.total_scanned,
        "total_in_period": analysis.total_in_period,
        "total_selected": analysis.total_selected,
        "selected_per_hour": analysis.selected_per_hour,
        "selected_per_day": analysis.selected_per_day,
        "selected_heatmap": analysis.selected_heatmap,
        "selected_hosts": analysis.selected_hosts,
        "selected_clients": selected_clients,
        "records": recs,
        "by_cat": by_cat,
        "blocked_by_cat": blocked_by_cat,
        "domain_stats": domain_stats,
        "recurrent": recurrent,
        "threshold_days": threshold_days,
        "gap_minutes": gap_minutes,
        "sessions": sessions,
        "session_days": session_days,
        "heat": heat,
        "hours": hours,
        "per_day": per_day,
        "weekday_counts": weekday_counts,
        "active_days": active_days,
        "warnings": warnings,
        "clients": analysis.clients,
        "aliases": analysis.aliases,
        "top": top,
        "lists": analysis.classifier.sources,
    }


def build_activity(analysis, gap_minutes=10, top_other=30):
    """Chronologie d'usage par application pour le client sélectionné (toutes requêtes DNS)."""
    recs = sorted(analysis.all_records or [], key=lambda r: r[0])
    gap = dt.timedelta(minutes=gap_minutes)
    apps = {}
    other = collections.Counter()
    day_app = collections.defaultdict(collections.Counter)
    for t, host in recs:
        app = app_of_host(host)
        if app is None:
            other[base_domain(host)] += 1
            app = "(autres sites)"
        a = apps.get(app)
        if a is None:
            a = apps[app] = {"app": app, "count": 0, "days": set(), "hours": collections.Counter(),
                             "hosts": collections.Counter(), "hints": collections.Counter(), "sessions": [],
                             "first": t, "last": t}
        a["count"] += 1
        a["days"].add(t.date())
        a["hours"][t.hour] += 1
        a["hosts"][host] += 1
        hint_app, hint = host_hint(host)
        if hint:
            a["hints"][hint] += 1
        a["last"] = t
        if not a["sessions"] or t - a["sessions"][-1]["end"] > gap:
            a["sessions"].append({"start": t, "end": t, "count": 0, "hints": collections.Counter()})
        sess = a["sessions"][-1]
        sess["end"] = t
        sess["count"] += 1
        if hint:
            sess["hints"][hint] += 1
        day_app[t.date()][app] += 1
    for a in apps.values():
        a["active_seconds"] = sum(max(60, (x["end"] - x["start"]).total_seconds()) for x in a["sessions"])
    ordered = sorted(apps.values(), key=lambda a: (a["app"] in NOISE_APPS, a["app"] == "(autres sites)", -a["count"]))
    timeline = []
    for a in ordered:
        if a["app"] in NOISE_APPS:
            continue   # pas de sessions pour le bruit publicitaire / technique
        for x in a["sessions"]:
            timeline.append((x["start"], x["end"], a["app"], x["count"], x["hints"]))
    timeline.sort(key=lambda x: x[0])
    return {"apps": ordered, "other": other.most_common(top_other), "day_app": day_app, "timeline": timeline,
            "total": len(recs), "gap_minutes": gap_minutes,
            "client": (analysis.filters.clients[0] if analysis.filters.clients else "?"),
            "first": recs[0][0] if recs else None, "last": recs[-1][0] if recs else None}


def render_activity_text(act, filters):
    out = []
    out.append("DÉTAIL D'ACTIVITÉ PAR APPLICATION - appareil %s" % act["client"])
    out.append("=" * 78)
    for p in describe_filters(filters)[:-1]:
        out.append("  - " + p)
    out.append("  - %d requêtes DNS ; sessions séparées par %d min de silence" % (act["total"], act["gap_minutes"]))
    out.append("")
    out.append("Rappel : le DNS montre QUAND une appli est utilisée, jamais le contenu, le correspondant ni le sens")
    out.append("(envoyé/reçu). Les indices entre parenthèses sont déduits des sous-domaines et restent indicatifs.")
    out.append("'(autres sites)' = requêtes qui ne correspondent à aucune appli connue de l'outil : sites visités dans le")
    out.append("navigateur ou applis non répertoriées (liste en fin de rapport). Le bruit publicitaire et technique")
    out.append("généré par les applis est compté à part et n'apparaît pas dans la chronologie.")
    if not act["apps"]:
        out.append("")
        out.append("Aucune requête pour cet appareil sur la période.")
        return "\n".join(out)
    out.append("")
    out.append("APPLICATIONS UTILISÉES")
    out.append("-" * 78)
    out.append("  %-22s %6s %5s %8s %10s  %s" % ("application", "req.", "jours", "sessions", "temps actif", "heures typiques"))
    for a in act["apps"]:
        out.append("  %-22s %6d %5d %8d %10s  %s" % (a["app"][:22], a["count"], len(a["days"]), len(a["sessions"]),
                                                    fmt_duration(a["active_seconds"]), ", ".join(typical_slots(a["hours"])) or "-"))
    for a in act["apps"]:
        if a["app"] == "(autres sites)" or not a["hints"]:
            continue
        out.append("  %s : %s" % (a["app"], ", ".join("%s x%d" % (h, n) for h, n in a["hints"].most_common(4))))
    out.append("")
    out.append("ACTIVITÉ PAR JOUR (requêtes par application)")
    out.append("-" * 78)
    for day in sorted(act["day_app"]):
        c = act["day_app"][day]
        out.append("  %s %s  %s" % (fmt_date(day), WEEKDAYS_FR[day.weekday()],
                                     ", ".join("%s=%d" % (a, n) for a, n in c.most_common(8))))
    out.append("")
    out.append("CHRONOLOGIE DES SESSIONS")
    out.append("-" * 78)
    for start, end, app, n, hints in act["timeline"][-300:]:
        dur = fmt_duration(max(60, (end - start).total_seconds()))
        h = ("  (%s)" % ", ".join("%s x%d" % (k, v) for k, v in hints.most_common(2))) if hints else ""
        out.append("  %s %s -> %s  %-18s %4d req. %6s%s" % (WEEKDAYS_FR[start.weekday()], fmt_dt(start),
                                                             end.strftime("%H:%M"), app[:18], n, dur, h))
    if len(act["timeline"]) > 300:
        out.append("  ... (%d sessions au total, voir le rapport HTML)" % len(act["timeline"]))
    if act["other"]:
        out.append("")
        out.append("AUTRES SITES LES PLUS DEMANDÉS (hors applis reconnues)")
        out.append("-" * 78)
        for dom, n in act["other"]:
            out.append("  %-50s %6d" % (dom[:50], n))
    return "\n".join(out)


def render_activity_html(act, filters):
    h = []
    h.append("<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'><title>Détail d'activité - %s</title>" % _esc(act["client"]))
    h.append("<style>%s</style></head><body><div class='wrap'>" % _CSS)
    h.append("<h1>Détail d'activité par application &ndash; %s</h1>" % _esc(act["client"]))
    h.append("<div class='card'><ul>" + "".join("<li>%s</li>" % _esc(p) for p in describe_filters(filters)[:-1])
             + "<li>%d requêtes DNS ; sessions séparées par %d min de silence</li></ul></div>" % (act["total"], act["gap_minutes"]))
    h.append("<div class='warn'>Le DNS montre <b>quand</b> une appli est utilisée, jamais le contenu des échanges, le "
             "correspondant ni le sens (envoyé / reçu). Les indices sont déduits des sous-domaines et restent indicatifs. "
             "<b>(autres sites)</b> = requêtes sans appli connue : sites visités dans le navigateur ou applis non répertoriées, "
             "listés en fin de rapport. Le bruit publicitaire et technique des applis est compté à part.</div>")
    if not act["apps"]:
        h.append("<div class='card'>Aucune requête pour cet appareil sur la période.</div></div></body></html>")
        return "\n".join(h)
    h.append("<h2>Applications utilisées</h2><table><tr><th>Application</th><th class='num'>Requêtes</th><th class='num'>Jours</th>"
             "<th class='num'>Sessions</th><th>Temps actif</th><th>Heures typiques</th><th>Indices</th><th>Sous-domaines les plus vus</th></tr>")
    for a in act["apps"]:
        h.append("<tr><td><b>%s</b></td><td class='num'>%d</td><td class='num'>%d</td><td class='num'>%d</td><td>%s</td><td>%s</td>"
                 "<td><small>%s</small></td><td><small>%s</small></td></tr>"
                 % (_esc(a["app"]), a["count"], len(a["days"]), len(a["sessions"]), _esc(fmt_duration(a["active_seconds"])),
                    _esc(", ".join(typical_slots(a["hours"])) or "-"),
                    _esc(", ".join("%s ×%d" % (k, v) for k, v in a["hints"].most_common(4))),
                    _esc(", ".join("%s (%d)" % (k, v) for k, v in a["hosts"].most_common(3)))))
    h.append("</table>")
    apps = [a["app"] for a in act["apps"] if a["app"] != "(autres sites)"][:10]
    h.append("<h2>Activité par jour</h2><table><tr><th>Date</th>" + "".join("<th class='num'>%s</th>" % _esc(x) for x in apps) + "</tr>")
    for day in sorted(act["day_app"]):
        c = act["day_app"][day]
        h.append("<tr><td>%s %s</td>%s</tr>" % (_esc(fmt_date(day)), WEEKDAYS_FR[day.weekday()],
                                              "".join("<td class='num'>%s</td>" % (c.get(x) or "") for x in apps)))
    h.append("</table>")
    h.append("<h2>Chronologie des sessions</h2><table><tr><th>Jour</th><th>Début</th><th>Fin</th><th>Durée</th><th>Application</th>"
             "<th class='num'>Requêtes</th><th>Indices</th></tr>")
    for start, end, app, n, hints in act["timeline"]:
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='num'>%d</td><td><small>%s</small></td></tr>"
                 % (WEEKDAYS_FR_LONG[start.weekday()], _esc(fmt_dt(start)), _esc(end.strftime("%H:%M:%S")),
                    _esc(fmt_duration(max(60, (end - start).total_seconds()))), _esc(app), n,
                    _esc(", ".join("%s ×%d" % (k, v) for k, v in hints.most_common(3)))))
    h.append("</table>")
    if act["other"]:
        h.append("<h2>Autres sites les plus demandés</h2><table><tr><th>Domaine</th><th class='num'>Requêtes</th></tr>")
        for dom, n in act["other"]:
            h.append("<tr><td>%s</td><td class='num'>%d</td></tr>" % (_esc(dom), n))
        h.append("</table>")
    h.append("</div></body></html>")
    return "\n".join(h)


def write_activity_csv(analysis, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["date", "heure", "jour", "application", "domaine", "indice"])
        for t, host in sorted(analysis.all_records or [], key=lambda r: r[0]):
            w.writerow([t.strftime("%Y-%m-%d"), t.strftime("%H:%M:%S"), WEEKDAYS_FR[t.weekday()],
                        app_of_host(host) or "", host, host_hint(host)[1] or ""])


# ---------------------------------------------------------------------------
# Rendu texte
# ---------------------------------------------------------------------------

def describe_filters(f):
    parts = []
    if f.since is not None and f.until is not None:
        parts.append("du %s au %s" % (fmt_date(to_local(f.since, f.tz)), fmt_date(to_local(f.until, f.tz))))
    elif f.since is not None:
        parts.append("depuis le %s" % fmt_date(to_local(f.since, f.tz)))
    else:
        parts.append("toute la période disponible")
    if f.hour_ranges:
        parts.append("plages horaires : " + ", ".join("%02dh%02d-%02dh%02d" % (a // 60, a % 60, (b // 60) % 24, b % 60)
                                                        for a, b in f.hour_ranges))
    if f.weekdays is not None:
        parts.append("jours : " + ", ".join(WEEKDAYS_FR[d] for d in sorted(f.weekdays)))
    if f.clients:
        parts.append("client(s) : " + ", ".join(f.clients))
    parts.append("catégories : " + ", ".join(CATEGORY_LABELS.get(c, c) for c in f.categories))
    return parts


def _bar(value, maximum, width=20):
    if maximum <= 0:
        return ""
    n = int(round(width * value / float(maximum)))
    return "#" * n


def render_clients_text(analysis, top_apps=6):
    out = []
    out.append("APPAREILS VUS DANS LE JOURNAL (%d requêtes dans la période)" % analysis.total_in_period)
    out.append("=" * 78)
    clients = sorted(analysis.clients.values(), key=lambda c: -c.count)
    if not clients:
        out.append("Aucun client.")
        return "\n".join(out)
    n_random = 0
    for cs in clients:
        names = list(cs.names)
        alias = analysis.aliases.get(cs.ip.lower())
        if alias:
            names.insert(0, alias)
        mac, vendor, dhcp_name, static = analysis.lease_info(cs.ip)
        if dhcp_name:
            names.append(dhcp_name)
        label = cs.ip
        if names:
            label += "  (" + ", ".join(sorted(set(names))) + ")"
        out.append("")
        out.append(label)
        if mac:
            out.append("  MAC : %s  |  fabricant : %s  |  bail %s" % (mac, vendor or "?", "statique" if static else "dynamique"))
            if vendor.startswith("adresse aléatoire"):
                n_random += 1
        out.append("  Type probable : %s" % cs.guess())
        out.append("  Requêtes : %d   |  jours actifs : %d   |  du %s au %s"
                   % (cs.count, len(cs.days), fmt_dt(cs.first) if cs.first else "-", fmt_dt(cs.last) if cs.last else "-"))
        sig = ["%s=%d" % (k, v) for k, v in cs.signals.most_common() if v]
        if sig:
            out.append("  Indices : " + ", ".join(sig))
        apps = cs.apps.most_common(top_apps)
        if apps:
            out.append("  Applis les plus vues : " + ", ".join("%s (%d)" % (a, n) for a, n in apps))
        if cs.categories:
            out.append("  !! Activité sensible : " + ", ".join("%s=%d" % (CATEGORY_LABELS.get(c, c), n)
                                                             for c, n in cs.categories.most_common()))
        if cs.signals["private_relay"]:
            out.append("  !! iCloud Private Relay actif : une partie du trafic Safari échappe à AdGuard.")
        peak = max(range(24), key=lambda h: cs.hours[h])
        out.append("  Heure la plus active : %02dh" % peak)
    silent = [(ip, l) for ip, l in analysis.leases.items() if ip not in analysis.clients]
    if silent:
        out.append("")
        out.append("APPAREILS AVEC UN BAIL DHCP MAIS AUCUNE REQUÊTE DNS DANS LA PÉRIODE (%d)" % len(silent))
        out.append("  (éteints, ou qui utilisent un autre serveur DNS : à vérifier)")
        for ip, l in sorted(silent, key=lambda x: ip_sort_key(x[0])):
            out.append("  %-16s %-18s %-40s %s%s" % (ip, l.get("mac", ""), mac_vendor(l.get("mac", ""), analysis.mac_vendors)[:40],
                                                      l.get("hostname") or "-", "  [statique]" if l.get("static") else ""))
    out.append("")
    if analysis.leases:
        out.append("MAC : %d appareil(s) avec adresse aléatoire (téléphones/tablettes récents : le fabricant est masqué,"
                   " c'est normal)." % n_random)
        out.append("Un intrus se repère à un nom d'hôte inconnu, un fabricant inattendu, ou des horaires d'activité qui")
        out.append("ne correspondent à personne dans la maison. Seul un nouveau mot de passe Wi-Fi l'exclut durablement.")
    else:
        out.append("MAC et fabricants indisponibles : le serveur DHCP d'AdGuard n'est pas actif, ou indiquez --baux leases.json.")
    out.append("Astuce : un iPhone se reconnaît aux indices 'ios' (time-ios.apple.com...) et aux applis")
    out.append("(Snapchat, TikTok...). Notez son adresse IP puis utilisez : --client <IP>")
    return "\n".join(out)


def render_text(rep, detail=False):
    f = rep["filters"]
    out = []
    out.append("RAPPORT D'ACTIVITÉ SENSIBLE - AdGuard Home")
    out.append("=" * 78)
    out.append("Généré le %s" % fmt_dt(rep["generated"]))
    for p in describe_filters(f):
        out.append("  - " + p)
    if rep["selected_clients"]:
        out.append("  - appareil(s) analysé(s) : " + ", ".join(
            "%s (%s)" % (n, ip) if n != ip else ip for ip, n in rep["selected_clients"].items()))
    if rep["period_first"]:
        out.append("  - journal couvert : du %s au %s" % (fmt_dt(rep["period_first"]), fmt_dt(rep["period_last"])))
    out.append("")
    for w in rep["warnings"]:
        out.append("ATTENTION : " + w)
    if rep["warnings"]:
        out.append("")

    out.append("RÉSUMÉ")
    out.append("-" * 78)
    out.append("Requêtes lues : %d   dans la période : %d   retenues (client + horaires) : %d"
               % (rep["total_scanned"], rep["total_in_period"], rep["total_selected"]))
    total_sensitive = sum(rep["by_cat"].values())
    out.append("Requêtes sensibles : %d  (sur %d jours ; %d jour(s) avec activité sensible ; %d session(s))"
               % (total_sensitive, rep["n_days"], len(rep["active_days"]), len(rep["sessions"])))
    for cat in f.categories:
        n = rep["by_cat"].get(cat, 0)
        if n:
            out.append("  %-28s %6d requêtes, dont %d bloquées par AdGuard, %d autorisées"
                       % (CATEGORY_LABELS.get(cat, cat) + " :", n, rep["blocked_by_cat"].get(cat, 0),
                          n - rep["blocked_by_cat"].get(cat, 0)))
    if total_sensitive == 0:
        out.append("")
        out.append("Aucune activité sensible détectée avec les filtres choisis.")
        return "\n".join(out)

    out.append("")
    out.append("ACTIVITÉS RÉCURRENTES (vues au moins %d jours différents)" % rep["threshold_days"])
    out.append("-" * 78)
    if not rep["recurrent"]:
        out.append("Aucune (essayez --seuil-recurrence 2 ou une période plus longue).")
    for s in rep["recurrent"][:rep["top"]]:
        out.append("%s  [%s]" % (s["domain"], CATEGORY_LABELS.get(s["category"], s["category"])))
        out.append("    %d jours sur %d, %d requêtes (%d bloquées), créneaux : %s, jours : %s"
                   % (len(s["days"]), rep["n_days"], s["count"], s["blocked"],
                      ", ".join(typical_slots(s["hours"])) or "-",
                      ", ".join("%s(%d)" % (WEEKDAYS_FR[d], n) for d, n in sorted(s["weekdays"].items()))))
        out.append("    première fois : %s   dernière fois : %s" % (fmt_dt(s["first"]), fmt_dt(s["last"])))

    out.append("")
    out.append("CRÉNEAUX HORAIRES DE L'ACTIVITÉ SENSIBLE (toutes catégories)")
    out.append("-" * 78)
    mx = max(rep["hours"].values()) if rep["hours"] else 0
    for h in range(24):
        n = rep["hours"].get(h, 0)
        if n:
            out.append("  %02dh-%02dh  %5d  %s" % (h, (h + 1) % 24, n, _bar(n, mx)))
    out.append("  Créneaux typiques : " + (", ".join(typical_slots(rep["hours"])) or "-"))
    out.append("  Jours de la semaine : " + ", ".join("%s=%d" % (WEEKDAYS_FR[d], n)
                                                       for d, n in sorted(rep["weekday_counts"].items())))

    out.append("")
    out.append("CARTE JOUR x HEURE (nombre de requêtes sensibles)")
    out.append("-" * 78)
    out.append("      " + " ".join("%2d" % h for h in range(24)))
    hmax = max(max(row) for row in rep["heat"]) or 1
    scale = " .:-=+*#%@"
    for d in range(7):
        row = rep["heat"][d]
        cells = []
        for v in row:
            idx = 0 if v == 0 else max(1, int(round((len(scale) - 1) * v / float(hmax))))
            cells.append(" " + scale[idx] + " ")
        out.append("  %s " % WEEKDAYS_FR[d] + "".join(cells).rstrip())
    out.append("  (' '=0  '.'=faible ... '@'=maximum %d)" % hmax)

    out.append("")
    out.append("SITES LES PLUS CONSULTÉS")
    out.append("-" * 78)
    out.append("  %-34s %-14s %5s %5s %6s  %s" % ("domaine", "catégorie", "jours", "req.", "bloq.", "dernière fois"))
    for s in sorted(rep["domain_stats"], key=lambda x: -x["count"])[:rep["top"]]:
        out.append("  %-34s %-14s %5d %5d %6d  %s" % (s["domain"][:34], s["category"], len(s["days"]),
                                                     s["count"], s["blocked"], fmt_dt(s["last"])))

    out.append("")
    out.append("ACTIVITÉ PAR JOUR")
    out.append("-" * 78)
    for day in sorted(rep["per_day"]):
        d = rep["per_day"][day]
        cats = ", ".join("%s=%d" % (c, n) for c, n in d["cats"].most_common())
        out.append("  %s %s  %4d requêtes (%d bloquées), %d session(s)  %s"
                   % (fmt_date(day), WEEKDAYS_FR[day.weekday()], d["total"], d["blocked"],
                      rep["session_days"].get(day, 0), cats))

    out.append("")
    out.append("SESSIONS (requêtes sensibles espacées de moins de %d min ; une session peut déborder sur le jour suivant)" % rep["gap_minutes"])
    out.append("-" * 78)
    for s in rep["sessions"][-100:]:
        dur = (s["end"] - s["start"]).total_seconds()
        doms = ", ".join("%s(%d)" % (d, n) for d, n in s["domains"].most_common(4))
        out.append("  %s %s -> %s  (%s, %d req., %d bloquées) [%s] %s"
                   % (WEEKDAYS_FR[s["start"].weekday()], fmt_dt(s["start"]), s["end"].strftime("%H:%M:%S"),
                      fmt_duration(dur), s["count"], s["blocked"], ",".join(sorted(s["categories"])), doms))
    if len(rep["sessions"]) > 100:
        out.append("  ... (%d sessions au total, voir le rapport HTML ou le CSV)" % len(rep["sessions"]))

    if rep["top_sites"]:
        out.append("")
        out.append("SITES LES PLUS VISITÉS PAR L'APPAREIL, TOUTES CATÉGORIES (pour repérer un site inconnu des listes)")
        out.append("-" * 78)
        for dom, n, cat in rep["top_sites"]:
            out.append("  %-45s %6d  %s" % (dom[:45], n, CATEGORY_LABELS.get(cat, "") if cat else ""))

    if detail:
        out.append("")
        out.append("DÉTAIL DES REQUÊTES")
        out.append("-" * 78)
        for r in rep["records"]:
            out.append("  %s  %-14s %-45s %s  %s" % (fmt_dt(r.time), r.category, r.host[:45],
                                                      "BLOQUÉ  " if r.blocked else "autorisé",
                                                      "(%s %s)" % (r.source, r.detail)))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Rendu HTML
# ---------------------------------------------------------------------------

_CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f7;color:#222}
.wrap{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:8px 0} h2{font-size:17px;margin:26px 0 8px;border-bottom:2px solid #d0d4da;padding-bottom:4px}
.card{background:#fff;border-radius:8px;padding:12px 16px;margin:10px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.warn{background:#fff4e5;border-left:5px solid #f0a020;padding:8px 12px;margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:13px} th,td{border:1px solid #e0e3e8;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#eef1f5} tr:nth-child(even) td{background:#fafbfc}
.num{text-align:right;white-space:nowrap} .heat td{text-align:center;width:3.4%;padding:3px 0}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:12px;color:#fff}
.porno{background:#c0392b} .rencontres{background:#8e44ad} .rencontres-ados{background:#1f77b4} .chat-aleatoire{background:#d35400}
.blk{color:#c0392b;font-weight:bold} .ok{color:#27ae60}
.kpi{display:inline-block;min-width:150px;margin:6px 14px 6px 0} .kpi b{display:block;font-size:22px}
.bar{background:#3b7ddd;height:12px;display:inline-block;vertical-align:middle}
small{color:#666} details summary{cursor:pointer;font-weight:bold;margin:10px 0}
"""


def _esc(x):
    return html.escape(str(x))


def _cat_tag(cat):
    return '<span class="tag %s">%s</span>' % (_esc(cat), _esc(CATEGORY_LABELS.get(cat, cat)))


def render_html(rep, detail=True):
    f = rep["filters"]
    h = []
    h.append("<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'><title>Rapport AdGuard - activité sensible</title>")
    h.append("<style>%s</style></head><body><div class='wrap'>" % _CSS)
    h.append("<h1>Rapport d'activité sensible &ndash; AdGuard Home</h1>")
    h.append("<div class='card'><b>Généré le %s</b><ul>" % _esc(fmt_dt(rep["generated"])))
    for p in describe_filters(f):
        h.append("<li>%s</li>" % _esc(p))
    if rep["selected_clients"]:
        h.append("<li>appareil(s) analysé(s) : %s</li>" % _esc(", ".join(
            "%s (%s)" % (n, ip) if n != ip else ip for ip, n in rep["selected_clients"].items())))
    if rep["period_first"]:
        h.append("<li>journal couvert : du %s au %s</li>" % (_esc(fmt_dt(rep["period_first"])), _esc(fmt_dt(rep["period_last"]))))
    h.append("</ul></div>")
    for w in rep["warnings"]:
        h.append("<div class='warn'>%s</div>" % _esc(w))

    total_sensitive = sum(rep["by_cat"].values())
    h.append("<div class='card'>")
    h.append("<span class='kpi'><b>%d</b>requêtes retenues</span>" % rep["total_selected"])
    h.append("<span class='kpi'><b>%d</b>requêtes sensibles</span>" % total_sensitive)
    h.append("<span class='kpi'><b>%d / %d</b>jours avec activité sensible</span>" % (len(rep["active_days"]), rep["n_days"]))
    h.append("<span class='kpi'><b>%d</b>sessions</span>" % len(rep["sessions"]))
    for cat in f.categories:
        n = rep["by_cat"].get(cat, 0)
        h.append("<span class='kpi'><b>%d</b>%s <small>(%d bloquées)</small></span>"
                 % (n, _cat_tag(cat), rep["blocked_by_cat"].get(cat, 0)))
    h.append("</div>")

    if total_sensitive == 0:
        h.append("<div class='card'>Aucune activité sensible détectée avec les filtres choisis.</div>")
        h.append("</div></body></html>")
        return "\n".join(h)

    h.append("<h2>Activités récurrentes <small>(vues au moins %d jours différents)</small></h2>" % rep["threshold_days"])
    if rep["recurrent"]:
        h.append("<table><tr><th>Domaine</th><th>Catégorie</th><th class='num'>Jours</th><th class='num'>Requêtes</th>"
                 "<th class='num'>Bloquées</th><th>Créneaux typiques</th><th>Jours de la semaine</th><th>Première</th><th>Dernière</th></tr>")
        for s in rep["recurrent"][:rep["top"]]:
            h.append("<tr><td>%s</td><td>%s</td><td class='num'>%d / %d</td><td class='num'>%d</td><td class='num'>%d</td>"
                     "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                     % (_esc(s["domain"]), _cat_tag(s["category"]), len(s["days"]), rep["n_days"], s["count"], s["blocked"],
                        _esc(", ".join(typical_slots(s["hours"])) or "-"),
                        _esc(", ".join("%s (%d)" % (WEEKDAYS_FR[d], n) for d, n in sorted(s["weekdays"].items()))),
                        _esc(fmt_dt(s["first"])), _esc(fmt_dt(s["last"]))))
        h.append("</table>")
    else:
        h.append("<div class='card'>Aucune activité récurrente (seuil : %d jours).</div>" % rep["threshold_days"])

    h.append("<h2>Créneaux horaires</h2><div class='card'>")
    h.append("<p>Créneaux typiques de l'activité sensible : <b>%s</b> &nbsp; Jours : %s</p>"
             % (_esc(", ".join(typical_slots(rep["hours"])) or "-"),
                _esc(", ".join("%s=%d" % (WEEKDAYS_FR[d], n) for d, n in sorted(rep["weekday_counts"].items())))))
    mx = max(rep["hours"].values()) if rep["hours"] else 1
    mx_all = max(rep["selected_per_hour"]) or 1
    h.append("<table><tr><th>Heure</th><th>Sensible</th><th></th><th>Tout le trafic de l'appareil</th><th></th></tr>")
    for hr in range(24):
        n = rep["hours"].get(hr, 0)
        a = rep["selected_per_hour"][hr]
        h.append("<tr><td>%02dh-%02dh</td><td class='num'>%d</td><td><span class='bar' style='width:%dpx;background:#c0392b'></span></td>"
                 "<td class='num'>%d</td><td><span class='bar' style='width:%dpx'></span></td></tr>"
                 % (hr, (hr + 1) % 24, n, int(300 * n / mx), a, int(300 * a / mx_all)))
    h.append("</table></div>")

    h.append("<h2>Carte jour &times; heure <small>(requêtes sensibles)</small></h2>")
    hmax = max(max(r) for r in rep["heat"]) or 1
    h.append("<table class='heat'><tr><th></th>" + "".join("<th>%d</th>" % x for x in range(24)) + "</tr>")
    for d in range(7):
        cells = []
        for v in rep["heat"][d]:
            alpha = 0 if v == 0 else 0.15 + 0.85 * v / float(hmax)
            cells.append("<td style='background:rgba(192,57,43,%.2f);color:%s'>%s</td>"
                         % (alpha, "#fff" if alpha > 0.55 else "#222", v or ""))
        h.append("<tr><th>%s</th>%s</tr>" % (WEEKDAYS_FR[d], "".join(cells)))
    h.append("</table>")

    h.append("<h2>Sites consultés</h2>")
    h.append("<table><tr><th>Domaine</th><th>Catégorie</th><th class='num'>Jours</th><th class='num'>Requêtes</th>"
             "<th class='num'>Bloquées</th><th>Détection</th><th>Sous-domaines vus</th><th>Dernière fois</th></tr>")
    for s in sorted(rep["domain_stats"], key=lambda x: -x["count"])[:rep["top"] * 2]:
        hosts = ", ".join("%s (%d)" % (hh, n) for hh, n in s["hosts"].most_common(3))
        h.append("<tr><td>%s</td><td>%s</td><td class='num'>%d</td><td class='num'>%d</td><td class='num'>%d</td>"
                 "<td><small>%s : %s</small></td><td><small>%s</small></td><td>%s</td></tr>"
                 % (_esc(s["domain"]), _cat_tag(s["category"]), len(s["days"]), s["count"], s["blocked"],
                    _esc(s["source"]), _esc(s["detail"]), _esc(hosts), _esc(fmt_dt(s["last"]))))
    h.append("</table>")

    h.append("<h2>Activité par jour</h2>")
    h.append("<table><tr><th>Date</th><th>Jour</th><th class='num'>Requêtes sensibles</th><th class='num'>Bloquées</th>"
             "<th class='num'>Sessions</th><th>Catégories</th><th class='num'>Tout le trafic</th></tr>")
    for day in sorted(rep["per_day"]):
        d = rep["per_day"][day]
        h.append("<tr><td>%s</td><td>%s</td><td class='num'>%d</td><td class='num'>%d</td><td class='num'>%d</td><td>%s</td><td class='num'>%d</td></tr>"
                 % (_esc(fmt_date(day)), WEEKDAYS_FR_LONG[day.weekday()], d["total"], d["blocked"],
                    rep["session_days"].get(day, 0),
                    " ".join("%s %d" % (_cat_tag(c), n) for c, n in d["cats"].most_common()),
                    rep["selected_per_day"].get(day, 0)))
    h.append("</table>")

    h.append("<h2>Sessions <small>(requêtes sensibles espacées de moins de %d min)</small></h2>" % rep["gap_minutes"])
    h.append("<table><tr><th>Jour</th><th>Début</th><th>Fin</th><th>Durée</th><th class='num'>Requêtes</th>"
             "<th class='num'>Bloquées</th><th>Catégories</th><th>Domaines</th></tr>")
    for s in rep["sessions"]:
        dur = (s["end"] - s["start"]).total_seconds()
        doms = ", ".join("%s (%d)" % (d, n) for d, n in s["domains"].most_common(5))
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class='num'>%d</td><td class='num'>%d</td><td>%s</td><td>%s</td></tr>"
                 % (WEEKDAYS_FR_LONG[s["start"].weekday()], _esc(fmt_dt(s["start"])), _esc(s["end"].strftime("%H:%M:%S")),
                    _esc(fmt_duration(dur)), s["count"], s["blocked"],
                    " ".join(_cat_tag(c) for c in sorted(s["categories"])), _esc(doms)))
    h.append("</table>")

    if rep["top_sites"]:
        h.append("<h2>Sites les plus visités par l'appareil <small>(toutes catégories, pour repérer un site inconnu des listes)</small></h2>")
        h.append("<table><tr><th>Domaine</th><th class='num'>Requêtes</th><th>Catégorie</th></tr>")
        for dom, n, cat in rep["top_sites"]:
            h.append("<tr><td>%s</td><td class='num'>%d</td><td>%s</td></tr>" % (_esc(dom), n, _cat_tag(cat) if cat else ""))
        h.append("</table>")

    if detail:
        h.append("<h2>Détail des requêtes</h2><details><summary>Afficher les %d requêtes</summary>" % len(rep["records"]))
        h.append("<table><tr><th>Date/heure</th><th>Catégorie</th><th>Domaine demandé</th><th>Résultat AdGuard</th><th>Détection</th></tr>")
        for r in rep["records"]:
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class='%s'>%s</td><td><small>%s : %s</small></td></tr>"
                     % (_esc(fmt_dt(r.time)), _cat_tag(r.category), _esc(r.host), "blk" if r.blocked else "ok",
                        _esc(REASON_LABELS.get(r.reason, r.reason)), _esc(r.source), _esc(r.detail)))
        h.append("</table></details>")

    h.append("<p><small>Listes utilisées : %s</small></p>" % _esc("; ".join(rep["lists"]) or "listes intégrées"))
    h.append("</div></body></html>")
    return "\n".join(h)


def write_csv(rep, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["date", "heure", "jour", "client", "nom_client", "categorie", "domaine", "domaine_base",
                    "bloque", "resultat_adguard", "regle", "detection", "detail"])
        for r in rep["records"]:
            w.writerow([r.time.strftime("%Y-%m-%d"), r.time.strftime("%H:%M:%S"), WEEKDAYS_FR[r.time.weekday()],
                        r.client, r.client_name, r.category, r.host, r.base, "oui" if r.blocked else "non",
                        REASON_LABELS.get(r.reason, r.reason), r.rule, r.source, r.detail])


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class Job(object):
    """Paramètres d'une analyse (partagés par la ligne de commande et l'interface graphique)."""

    def __init__(self):
        self.api_url = None
        self.api_user = None
        self.api_password = None
        self.api_insecure = False
        self.log_paths = []
        self.leases_path = None     # leases.json copié depuis le NAS (mode fichier)
        self.lists_dir = None
        self.aliases = []
        self.clients = []
        self.date_from = None       # date
        self.date_to = None
        self.hour_ranges = []
        self.weekdays = None
        self.categories = list(CATEGORIES)
        self.tz = None
        self.threshold_days = 3
        self.gap_minutes = 10
        self.top = 25
        self.top_sites = 0          # >0 : lister les N sites les plus visités, toutes catégories
        self.keep_all_hosts = False
        self.activity = False       # commande "activite" : conserver toutes les requêtes du client


def build_filters(job):
    tz = get_timezone(job.tz)
    since = until = None
    if job.date_from:
        since = day_bounds(job.date_from, tz)[0]
    if job.date_to:
        until = day_bounds(job.date_to, tz)[1]
    return Filters(since, until, job.hour_ranges, job.weekdays, job.clients, job.categories, tz)


def run_analysis(job, progress=None, for_clients=False):
    """Lit la source, applique les filtres et renvoie un objet Analysis."""
    progress = progress or (lambda msg: None)
    lists_dir = find_lists_directory(job.lists_dir)
    classifier = Classifier()
    if lists_dir:
        classifier.load_directory(lists_dir)
        progress("Listes chargées depuis %s (%d domaines)" % (lists_dir, len(classifier.domains)))
    else:
        progress("ATTENTION : dossier 'listes' introuvable, aucune détection possible !")
    filters = build_filters(job)
    aliases = load_client_aliases(lists_dir, job.aliases)
    analysis = Analysis(filters, classifier, aliases, keep_all_hosts=job.keep_all_hosts or job.top_sites > 0,
                        keep_all_records=job.activity)
    analysis.mac_vendors = load_mac_vendors(lists_dir)
    if job.leases_path:
        analysis.leases = load_leases_file(job.leases_path)
        progress("%d baux DHCP lus dans %s" % (len(analysis.leases), job.leases_path))

    if job.api_url:
        api = AdGuardAPI(job.api_url, job.api_user, job.api_password, job.api_insecure)
        st = api.status()
        progress("Connecté à AdGuard Home %s" % st.get("version", ""))
        aliases.update({k: v for k, v in api.clients().items() if k not in aliases})
        if not analysis.leases:
            analysis.leases = api.dhcp_leases()
            progress("%d baux DHCP récupérés (serveur DHCP d'AdGuard)" % len(analysis.leases)
                     if analysis.leases else "Pas de baux DHCP : le serveur DHCP d'AdGuard n'est pas actif (MAC indisponibles)")
        search = None
        if not for_clients and len(job.clients) == 1 and re.match(r"^[0-9a-f.:]+$", job.clients[0], re.I):
            search = job.clients[0]
        analysis.feed(api.iter_querylog(since=filters.since, search=search, progress=progress))
    else:
        paths = expand_log_paths(job.log_paths)
        if not paths:
            raise FileNotFoundError("Aucun fichier querylog.json trouvé. Indiquez --log <fichier>.")
        progress("Fichiers : " + ", ".join(paths))
        analysis.feed(iter_file_entries(paths, progress))
    progress("%d requêtes lues, %d dans la période, %d retenues, %d sensibles"
             % (analysis.total_scanned, analysis.total_in_period, analysis.total_selected, len(analysis.records)))
    return analysis


# ---------------------------------------------------------------------------
# Ligne de commande
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="adguard_analyse",
        description="Analyse des journaux AdGuard Home : sites pornographiques, de rencontres (adultes / ados) et tchats "
                    "avec inconnus, par appareil, dates et plages horaires. Sans argument : interface graphique.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exemples :
  adguard_analyse.py clients --api http://192.168.1.10:3000 --user admin --password secret
  adguard_analyse.py rapport --api http://192.168.1.10:3000 --user admin --password secret \\
        --client 192.168.1.42 --jours 30 --heures 22h-6h --html rapport.html
  adguard_analyse.py rapport --log querylog.json --client iphone --du 01/09/2026 --au 21/09/2026 --weekend
  adguard_analyse.py activite --api http://192.168.1.10:3000 --user admin --password secret \\
        --client 192.168.1.42 --jours 7 --html activite.html     (quand chaque appli est utilisée)
  adguard_analyse.py test-domaine fr.pornhub.com tinder.com essex.ac.uk
""")
    src = p.add_argument_group("Source des journaux")
    src.add_argument("--api", metavar="URL", help="URL d'AdGuard Home, ex : http://192.168.1.10:3000")
    src.add_argument("--user", help="identifiant AdGuard Home")
    src.add_argument("--password", help="mot de passe AdGuard Home")
    src.add_argument("--insecure", action="store_true", help="ne pas vérifier le certificat HTTPS")
    src.add_argument("--log", nargs="+", metavar="FICHIER", help="fichier(s) querylog.json (ou dossier les contenant)")
    src.add_argument("--baux", metavar="FICHIER", help="leases.json d'AdGuard (dossier data/) pour les adresses MAC en mode fichier")
    src.add_argument("--listes", metavar="DOSSIER", help="dossier des listes de domaines (défaut : ./listes)")
    src.add_argument("--alias", action="append", metavar="IP=NOM", help="nommer un appareil, ex : 192.168.1.42=iPhone-Ado")

    flt = p.add_argument_group("Filtres")
    flt.add_argument("--client", action="append", metavar="IP|NOM", help="appareil à analyser (IP exacte, IP avec * ou partie du nom). Répétable.")
    flt.add_argument("--du", metavar="DATE", help="date de début (AAAA-MM-JJ ou JJ/MM/AAAA), incluse")
    flt.add_argument("--au", metavar="DATE", help="date de fin, incluse")
    flt.add_argument("--jour", metavar="DATE", help="une seule journée")
    flt.add_argument("--jours", type=int, metavar="N", help="les N derniers jours (aujourd'hui inclus)")
    flt.add_argument("--heures", action="append", metavar="PLAGES", help="plages horaires, ex : 22h-6h ou '12:00-14:00, 22h-7h'. Répétable.")
    flt.add_argument("--semaine", metavar="JOURS", help="jours de la semaine : lun,mar,... ou 'weekend' ou 'semaine'")
    flt.add_argument("--weekend", action="store_true", help="samedi et dimanche uniquement")
    flt.add_argument("--nuit", action="store_true", help="raccourci pour --heures 22h-6h")
    flt.add_argument("--categories", metavar="LISTE", help="catégories : porno,rencontres,rencontres-ados,chat-aleatoire (défaut : toutes)")
    flt.add_argument("--tz", metavar="FUSEAU", help="fuseau horaire d'affichage (défaut : celui du PC), ex : Europe/Paris ou +02:00")

    outp = p.add_argument_group("Sortie")
    outp.add_argument("--html", metavar="FICHIER", help="écrire un rapport HTML")
    outp.add_argument("--csv", metavar="FICHIER", help="exporter le détail des requêtes sensibles en CSV (Excel)")
    outp.add_argument("--detail", action="store_true", help="afficher chaque requête sensible dans le rapport texte")
    outp.add_argument("--seuil-recurrence", type=int, default=3, metavar="N", help="nb de jours distincts pour 'récurrent' (défaut 3)")
    outp.add_argument("--gap", type=int, default=10, metavar="MIN", help="silence (minutes) séparant deux sessions (défaut 10)")
    outp.add_argument("--top", type=int, default=25, metavar="N", help="nombre de lignes dans les classements (défaut 25)")
    outp.add_argument("--tous-sites", type=int, default=0, metavar="N",
                      help="ajouter les N sites les plus visités par l'appareil, toutes catégories (pour repérer un site inconnu des listes)")
    outp.add_argument("--ouvrir", action="store_true", help="ouvrir le rapport HTML dans le navigateur")

    p.add_argument("commande", nargs="?", default="rapport", choices=["rapport", "clients", "activite", "test-domaine", "gui"],
                   help="rapport (défaut) | clients : lister les appareils | activite : chronologie d'usage par appli "
                        "d'un appareil (--client obligatoire) | test-domaine : tester la classification | gui")
    p.add_argument("domaines", nargs="*", help="domaines à tester avec la commande test-domaine")
    return p


def job_from_args(args):
    job = Job()
    job.api_url = args.api
    job.api_user = args.user
    job.api_password = args.password
    job.api_insecure = args.insecure
    job.log_paths = args.log or []
    job.leases_path = args.baux
    job.lists_dir = args.listes
    job.aliases = args.alias or []
    job.clients = args.client or []
    today = dt.date.today()
    if args.jour:
        job.date_from = job.date_to = parse_date(args.jour)
    if args.jours:
        job.date_from = today - dt.timedelta(days=args.jours - 1)
        job.date_to = today
    if args.du:
        job.date_from = parse_date(args.du)
    if args.au:
        job.date_to = parse_date(args.au)
    if job.date_from and not job.date_to:
        job.date_to = today
    ranges = []
    for h in args.heures or []:
        ranges.extend(parse_hour_ranges(h))
    if args.nuit:
        ranges.append((22 * 60, 6 * 60))
    job.hour_ranges = ranges
    if args.weekend:
        job.weekdays = {5, 6}
    if args.semaine:
        job.weekdays = parse_weekdays(args.semaine)
    if args.categories:
        cats = [c.strip().lower() for c in args.categories.split(",") if c.strip()]
        unknown = [c for c in cats if c not in CATEGORIES]
        if unknown:
            raise ValueError("Catégorie(s) inconnue(s) : %s. Choix : %s" % (", ".join(unknown), ", ".join(CATEGORIES)))
        job.categories = cats
    job.tz = args.tz
    job.threshold_days = args.seuil_recurrence
    job.gap_minutes = args.gap
    job.top = args.top
    job.top_sites = max(0, args.tous_sites)
    return job


def _setup_console():
    """Force l'UTF-8 dans la console Windows ; sans console (.exe --noconsole), redirige vers /dev/null."""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    _setup_console()
    if not argv or argv == ["gui"]:
        try:
            from adguard_gui import run_gui
        except ImportError:
            run_gui = None
        if run_gui is None:
            build_parser().print_help()
            return 0
        return run_gui()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.commande == "gui":
        from adguard_gui import run_gui
        return run_gui()

    if args.commande == "test-domaine":
        lists_dir = find_lists_directory(args.listes)
        c = Classifier()
        if lists_dir:
            c.load_directory(lists_dir)
            print("Listes : %s" % lists_dir)
        else:
            print("ATTENTION : dossier 'listes' introuvable")
        for d in args.domaines:
            cat, src, det = c.classify(d)
            print("%-45s -> %s" % (d, ("%s (%s : %s)" % (CATEGORY_LABELS[cat], src, det)) if cat else "non classé"))
        return 0

    try:
        job = job_from_args(args)
        if not job.api_url and not job.log_paths:
            parser.error("indiquez une source : --api URL --user U --password P  ou  --log querylog.json")
        if args.commande == "activite":
            if not job.clients:
                parser.error("la commande activite demande un appareil : --client IP")
            job.activity = True
        progress = lambda m: print("  [..] " + m, file=sys.stderr)
        analysis = run_analysis(job, progress, for_clients=(args.commande == "clients"))
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print("ERREUR : %s" % e, file=sys.stderr)
        return 2

    if args.commande == "clients":
        print(render_clients_text(analysis))
        return 0

    if args.commande == "activite":
        act = build_activity(analysis, job.gap_minutes)
        print(render_activity_text(act, analysis.filters))
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_activity_html(act, analysis.filters))
            print("\nRapport HTML écrit : %s" % os.path.abspath(args.html), file=sys.stderr)
            if args.ouvrir:
                import webbrowser
                webbrowser.open("file://" + os.path.abspath(args.html))
        if args.csv:
            write_activity_csv(analysis, args.csv)
            print("CSV écrit : %s" % os.path.abspath(args.csv), file=sys.stderr)
        return 0

    rep = build_report(analysis, job.threshold_days, job.gap_minutes, job.top, job.top_sites)
    print(render_text(rep, detail=args.detail))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(rep))
        print("\nRapport HTML écrit : %s" % os.path.abspath(args.html), file=sys.stderr)
        if args.ouvrir:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(args.html))
    if args.csv:
        write_csv(rep, args.csv)
        print("CSV écrit : %s" % os.path.abspath(args.csv), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
