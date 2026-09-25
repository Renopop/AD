#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recherche_mails.py - Retrouver et fouiller des courriels stockés sur un disque dur.

Formats lus : .eml (message unitaire), .emlx (Apple Mail), .mbox / .mbx et boîtes Thunderbird
sans extension (dossiers Mail, ImapMail, *.sbd), .msg (Outlook : recherche dans le texte brut).
Formats seulement inventoriés : .pst / .ost (Outlook) et .dbx (Outlook Express) : ils ne se lisent
qu'avec Outlook ou un convertisseur (ex : readpst) ; l'outil indique où ils sont et leur taille.

Python 3.8+ sans dépendance. Sans argument : interface graphique.

Exemples :
  recherche_mails.py inventaire --dossier D:\\
  recherche_mails.py chercher --dossier D:\\Archives --de "dupont" --texte facture --du 01/01/2020
  recherche_mails.py chercher --dossier D:\\ --sujet "contrat" --piece-jointe .pdf --html resultats.html --extraire trouves
  recherche_mails.py adresses --dossier D:\\Archives --csv adresses.csv
"""
import argparse
import collections
import csv
import datetime as dt
import email
import email.policy
import email.utils
import html
import mailbox
import os
import re
import shutil
import sys
import unicodedata

VERSION = "1.0"

MAIL_EXTENSIONS = {".eml": "eml", ".emlx": "emlx", ".mbox": "mbox", ".mbx": "mbox", ".msg": "msg"}
LISTED_ONLY = {".pst": "Outlook PST", ".ost": "Outlook OST", ".dbx": "Outlook Express DBX", ".nsf": "Lotus Notes"}
THUNDERBIRD_DIRS = {"mail", "imapmail", "local folders"}
SKIP_DIRS = {"$recycle.bin", "system volume information", "windows", "program files", "program files (x86)",
             "programdata", "$windows.~bt", "node_modules", ".git", "__pycache__", "winsxs"}
MAX_EML_SIZE = 50 * 1024 * 1024
POLICY = email.policy.default.clone(raise_on_defect=False)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def strip_accents(text):
    return "".join(c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn")


def norm(text):
    """Minuscules, sans accents, espaces réduits : pour comparer sans se soucier de la casse ni des accents."""
    return re.sub(r"\s+", " ", strip_accents(text or "").lower()).strip()


def parse_date(value):
    v = value.strip().lower()
    today = dt.date.today()
    if v in ("aujourdhui", "aujourd'hui"):
        return today
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d/%m/%y", "%Y%m%d", "%m/%Y", "%Y"):
        try:
            return dt.datetime.strptime(v, fmt).date()
        except ValueError:
            pass
    raise ValueError("Date invalide : %s (attendu JJ/MM/AAAA ou AAAA-MM-JJ)" % value)


def fmt_size(n):
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or unit == "To":
            return "%.0f %s" % (n, unit) if unit == "o" else "%.1f %s" % (n, unit)
        n /= 1024.0


def html_to_text(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", s)
    s = re.sub(r"<[^>]+>", " ", s)
    return html.unescape(re.sub(r"[ \t]+", " ", s))


def looks_like_mbox(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(5)
        return head == b"From "
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Modèle
# ---------------------------------------------------------------------------

class Mail(object):
    __slots__ = ("path", "container", "index", "date", "sender", "to", "cc", "subject", "body", "attachments", "size", "kind")

    def __init__(self, path, kind, index=None):
        self.path = path
        self.kind = kind
        self.container = kind in ("mbox",)
        self.index = index
        self.date = None
        self.sender = ""
        self.to = ""
        self.cc = ""
        self.subject = ""
        self.body = ""
        self.attachments = []
        self.size = 0

    def location(self):
        return "%s [message %d]" % (self.path, self.index + 1) if self.index is not None else self.path

    def snippet(self, terms, width=160):
        body = re.sub(r"\s+", " ", self.body)
        low = norm(body)
        for t in terms:
            i = low.find(t)
            if i >= 0:
                start = max(0, i - width // 3)
                return ("..." if start else "") + body[start:start + width] + ("..." if start + width < len(body) else "")
        return body[:width] + ("..." if len(body) > width else "")


# ---------------------------------------------------------------------------
# Lecture des messages
# ---------------------------------------------------------------------------

def _header(msg, name):
    try:
        v = msg.get(name, "")
        return str(v) if v is not None else ""
    except Exception:  # en-tête mal encodé
        raw = msg.get(name, "")
        return raw if isinstance(raw, str) else ""


def _decode_part(part):
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    for cs in (charset, "utf-8", "cp1252", "latin-1"):
        try:
            return payload.decode(cs)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("latin-1", "replace")


def mail_from_message(msg, path, kind, index=None):
    m = Mail(path, kind, index)
    m.sender = _header(msg, "From")
    m.to = _header(msg, "To")
    m.cc = _header(msg, "Cc")
    m.subject = _header(msg, "Subject")
    try:
        d = email.utils.parsedate_to_datetime(_header(msg, "Date"))
        if d is not None:
            m.date = d.astimezone().replace(tzinfo=None) if d.tzinfo else d
    except Exception:
        m.date = None
    texts, htmls = [], []
    try:
        parts = msg.walk() if msg.is_multipart() else [msg]
        for part in parts:
            ctype = part.get_content_type()
            fname = None
            try:
                fname = part.get_filename()
            except Exception:
                fname = None
            disp = str(part.get("Content-Disposition", "")).lower()
            if fname or "attachment" in disp:
                if fname:
                    m.attachments.append(fname)
                continue
            if ctype == "text/plain":
                texts.append(_decode_part(part))
            elif ctype == "text/html":
                htmls.append(_decode_part(part))
    except Exception:
        pass
    m.body = "\n".join(texts) if texts else html_to_text("\n".join(htmls))
    return m


def read_eml(path, kind="eml"):
    size = os.path.getsize(path)
    if size > MAX_EML_SIZE:
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    if kind == "emlx":
        # .emlx : première ligne = longueur, puis le message, puis un plist
        nl = data.find(b"\n")
        if nl > 0 and data[:nl].strip().isdigit():
            length = int(data[:nl].strip())
            data = data[nl + 1:nl + 1 + length]
    msg = email.message_from_bytes(data, policy=POLICY)
    m = mail_from_message(msg, path, kind)
    m.size = size
    return m


def iter_mbox(path):
    try:
        box = mailbox.mbox(path, factory=lambda f: email.message_from_binary_file(f, policy=POLICY), create=False)
    except Exception:
        return
    try:
        for i, msg in enumerate(box):
            try:
                m = mail_from_message(msg, path, "mbox", i)
                m.size = len(msg.as_bytes()) if i < 0 else 0
                yield m
            except Exception:
                continue
    finally:
        try:
            box.close()
        except Exception:
            pass


def read_msg_raw(path):
    """Outlook .msg sans bibliothèque : on extrait les chaînes de caractères du fichier (UTF-16 et ASCII)."""
    size = os.path.getsize(path)
    if size > MAX_EML_SIZE:
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    m = Mail(path, "msg")
    m.size = size
    strings = []
    for s in re.findall(rb"(?:[\x20-\x7e\xa0-\xff]\x00){4,}", data):
        try:
            strings.append(s.decode("utf-16-le"))
        except UnicodeDecodeError:
            pass
    for s in re.findall(rb"[\x20-\x7e]{6,}", data):
        strings.append(s.decode("ascii", "replace"))
    text = "\n".join(strings)
    m.body = text
    # heuristiques : sujet et expéditeur apparaissent souvent en clair
    mm = re.search(r"(?im)^(?:subject|objet)\s*:\s*(.+)$", text)
    if mm:
        m.subject = mm.group(1).strip()
    addrs = EMAIL_RE.findall(text)
    if addrs:
        m.sender = addrs[0]
    if not m.subject:
        m.subject = "(fichier .msg : recherche dans le texte brut)"
    try:
        m.date = dt.datetime.fromtimestamp(os.path.getmtime(path))
    except OSError:
        pass
    return m


# ---------------------------------------------------------------------------
# Parcours du disque
# ---------------------------------------------------------------------------

def iter_mail_files(root, exclude=None, progress=None):
    """Renvoie (chemin, type) pour chaque fichier de courriel, et (chemin, 'listed:<type>') pour PST/OST/DBX."""
    exclude = {e.lower() for e in (exclude or [])} | SKIP_DIRS
    n_dirs = 0
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        dirnames[:] = [d for d in dirnames if d.lower() not in exclude and not d.lower().endswith(".tmp")]
        n_dirs += 1
        if progress and n_dirs % 500 == 0:
            progress("%d dossiers parcourus... %s" % (n_dirs, dirpath[:60]))
        parent = os.path.basename(dirpath).lower()
        in_thunderbird = parent in THUNDERBIRD_DIRS or parent.endswith(".sbd") or "thunderbird" in dirpath.lower()
        for name in filenames:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext in MAIL_EXTENSIONS:
                yield path, MAIL_EXTENSIONS[ext]
            elif ext in LISTED_ONLY:
                yield path, "listed:" + LISTED_ONLY[ext]
            elif in_thunderbird and ext in ("", ".msf") and ext == "" and looks_like_mbox(path):
                yield path, "mbox"
            elif ext == "" and not in_thunderbird:
                try:
                    if os.path.getsize(path) > 1024 and looks_like_mbox(path):
                        yield path, "mbox"
                except OSError:
                    pass


def iter_mails(root, exclude=None, progress=None, kinds=None):
    n = 0
    for path, kind in iter_mail_files(root, exclude, progress):
        if kind.startswith("listed:"):
            continue
        if kinds and kind not in kinds:
            continue
        try:
            if kind == "mbox":
                for m in iter_mbox(path):
                    n += 1
                    if progress and n % 2000 == 0:
                        progress("%d messages lus..." % n)
                    yield m
            elif kind == "msg":
                m = read_msg_raw(path)
                if m:
                    n += 1
                    yield m
            else:
                m = read_eml(path, kind)
                if m:
                    n += 1
                    if progress and n % 2000 == 0:
                        progress("%d messages lus..." % n)
                    yield m
        except (OSError, ValueError):
            continue


# ---------------------------------------------------------------------------
# Inventaire
# ---------------------------------------------------------------------------

def inventory(root, exclude=None, progress=None):
    counts = collections.Counter()
    sizes = collections.Counter()
    listed = []
    folders = collections.Counter()
    for path, kind in iter_mail_files(root, exclude, progress):
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        if kind.startswith("listed:"):
            listed.append((path, kind[7:], size))
            continue
        counts[kind] += 1
        sizes[kind] += size
        folders[os.path.dirname(path)] += 1
    return {"root": root, "counts": counts, "sizes": sizes, "listed": listed, "folders": folders}


def render_inventory(inv):
    out = ["INVENTAIRE DES COURRIELS SOUS %s" % inv["root"], "=" * 78]
    labels = {"eml": "messages .eml", "emlx": "messages .emlx (Apple Mail)", "mbox": "boîtes mbox / Thunderbird",
              "msg": "messages .msg (Outlook)"}
    if not inv["counts"] and not inv["listed"]:
        out.append("Aucun fichier de courriel trouvé.")
        return "\n".join(out)
    for kind, n in inv["counts"].most_common():
        out.append("  %-34s %6d fichier(s)  %s" % (labels.get(kind, kind), n, fmt_size(inv["sizes"][kind])))
    if inv["listed"]:
        out.append("")
        out.append("ARCHIVES NON LISIBLES DIRECTEMENT (à ouvrir avec Outlook / Outlook Express, ou à convertir avec readpst) :")
        for path, kind, size in inv["listed"]:
            out.append("  %-22s %10s  %s" % (kind, fmt_size(size), path))
    out.append("")
    out.append("DOSSIERS CONTENANT LE PLUS DE FICHIERS DE COURRIEL :")
    for folder, n in inv["folders"].most_common(30):
        out.append("  %5d  %s" % (n, folder))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Recherche
# ---------------------------------------------------------------------------

class Criteria(object):
    def __init__(self):
        self.sender = []        # chacun doit apparaître (ET)
        self.to = []
        self.subject = []
        self.text = []          # dans sujet + corps
        self.any = []           # n'importe où (en-têtes + corps)
        self.attachment = []    # nom de pièce jointe contenant
        self.has_attachment = None
        self.date_from = None
        self.date_to = None
        self.regex = None
        self.kinds = None

    def describe(self):
        parts = []
        if self.sender: parts.append("de : " + ", ".join(self.sender))
        if self.to: parts.append("à : " + ", ".join(self.to))
        if self.subject: parts.append("sujet : " + ", ".join(self.subject))
        if self.text: parts.append("texte : " + ", ".join(self.text))
        if self.any: parts.append("partout : " + ", ".join(self.any))
        if self.attachment: parts.append("pièce jointe : " + ", ".join(self.attachment))
        if self.has_attachment: parts.append("avec pièce jointe")
        if self.date_from: parts.append("du " + self.date_from.strftime("%d/%m/%Y"))
        if self.date_to: parts.append("au " + self.date_to.strftime("%d/%m/%Y"))
        if self.regex: parts.append("expression : " + self.regex.pattern)
        return "; ".join(parts) or "aucun critère (tous les messages)"

    def all_terms(self):
        return [norm(t) for t in self.text + self.any + self.subject]


def matches(m, c):
    if c.date_from and (m.date is None or m.date.date() < c.date_from):
        return False
    if c.date_to and (m.date is None or m.date.date() > c.date_to):
        return False
    if c.has_attachment and not m.attachments:
        return False
    sender = norm(m.sender)
    for t in c.sender:
        if norm(t) not in sender:
            return False
    rcpt = norm(m.to + " " + m.cc)
    for t in c.to:
        if norm(t) not in rcpt:
            return False
    subject = norm(m.subject)
    for t in c.subject:
        if norm(t) not in subject:
            return False
    att = norm(" ".join(m.attachments))
    for t in c.attachment:
        if norm(t) not in att:
            return False
    if c.text or c.any or c.regex:
        body = norm(m.body)
        for t in c.text:
            nt = norm(t)
            if nt not in body and nt not in subject:
                return False
        if c.any:
            everything = " ".join((sender, rcpt, subject, body, att))
            for t in c.any:
                if norm(t) not in everything:
                    return False
        if c.regex and not (c.regex.search(m.body) or c.regex.search(m.subject)):
            return False
    return True


def search(root, criteria, exclude=None, progress=None, limit=0):
    results = []
    scanned = 0
    for m in iter_mails(root, exclude, progress, criteria.kinds):
        scanned += 1
        if matches(m, criteria):
            results.append(m)
            if limit and len(results) >= limit:
                break
    results.sort(key=lambda x: x.date or dt.datetime.min, reverse=True)
    return results, scanned


def render_results(results, scanned, criteria, terms=None, detail=True):
    out = ["RÉSULTATS : %d message(s) trouvé(s) sur %d lu(s)" % (len(results), scanned),
           "Critères : " + criteria.describe(), "=" * 78]
    terms = terms or criteria.all_terms()
    for m in results:
        out.append("")
        out.append("%s  %s" % (m.date.strftime("%d/%m/%Y %H:%M") if m.date else "date ?      ", m.subject[:90] or "(sans sujet)"))
        out.append("  De : %s" % m.sender[:100])
        if m.to:
            out.append("  À  : %s" % m.to[:100])
        if m.attachments:
            out.append("  Pièces jointes : %s" % ", ".join(m.attachments[:6]))
        out.append("  Fichier : %s" % m.location())
        if detail:
            out.append("  > " + m.snippet(terms))
    return "\n".join(out)


_CSS = """body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f5f7;color:#222}.wrap{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:20px}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #e0e3e8;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#eef1f5}tr:nth-child(even) td{background:#fafbfc}small{color:#666}.card{background:#fff;border-radius:8px;padding:10px 14px;margin:10px 0}"""


def render_results_html(results, scanned, criteria, terms=None):
    terms = terms or criteria.all_terms()
    h = ["<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'><title>Recherche de courriels</title><style>%s</style></head><body><div class='wrap'>" % _CSS,
         "<h1>Recherche de courriels</h1><div class='card'>%d message(s) trouvé(s) sur %d lu(s)<br><small>Critères : %s</small></div>"
         % (len(results), scanned, html.escape(criteria.describe())),
         "<table><tr><th>Date</th><th>De</th><th>À</th><th>Sujet</th><th>Pièces jointes</th><th>Extrait</th><th>Fichier</th></tr>"]
    for m in results:
        link = "file:///" + m.path.replace("\\", "/")
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td><small>%s</small></td><td><small>%s</small></td><td><a href='%s'>%s</a></td></tr>"
                 % (m.date.strftime("%d/%m/%Y %H:%M") if m.date else "?", html.escape(m.sender), html.escape(m.to[:80]),
                    html.escape(m.subject or "(sans sujet)"), html.escape(", ".join(m.attachments[:6])),
                    html.escape(m.snippet(terms)), html.escape(link), html.escape(m.location())))
    h.append("</table></div></body></html>")
    return "\n".join(h)


def write_results_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["date", "heure", "de", "a", "cc", "sujet", "pieces_jointes", "fichier", "extrait"])
        for m in results:
            w.writerow([m.date.strftime("%Y-%m-%d") if m.date else "", m.date.strftime("%H:%M") if m.date else "",
                        m.sender, m.to, m.cc, m.subject, ", ".join(m.attachments), m.location(), m.snippet([], 200)])


def extract_results(results, dest, progress=None):
    """Copie chaque message trouvé en .eml dans le dossier dest (nom = date_sujet)."""
    os.makedirs(dest, exist_ok=True)
    n = 0
    for i, m in enumerate(results):
        stamp = m.date.strftime("%Y-%m-%d_%H%M") if m.date else "sans-date"
        subj = re.sub(r"[^\w\-]+", "_", strip_accents(m.subject or "sans_sujet"))[:60]
        name = "%s_%s_%04d.eml" % (stamp, subj, i)
        target = os.path.join(dest, name)
        try:
            if m.kind == "mbox":
                box = mailbox.mbox(m.path, create=False)
                try:
                    msg = box[m.index] if m.index in box else None
                    if msg is None:
                        keys = list(box.keys())
                        msg = box[keys[m.index]]
                    with open(target, "wb") as fh:
                        fh.write(msg.as_bytes())
                finally:
                    box.close()
            elif m.kind == "emlx":
                with open(m.path, "rb") as fh:
                    data = fh.read()
                nl = data.find(b"\n")
                if nl > 0 and data[:nl].strip().isdigit():
                    data = data[nl + 1:nl + 1 + int(data[:nl].strip())]
                with open(target, "wb") as fh:
                    fh.write(data)
            else:
                shutil.copy2(m.path, os.path.join(dest, name if m.kind == "eml" else name[:-4] + os.path.splitext(m.path)[1]))
            n += 1
        except Exception as e:  # noqa: BLE001
            if progress:
                progress("impossible d'extraire %s : %s" % (m.location(), e))
    return n


# ---------------------------------------------------------------------------
# Adresses
# ---------------------------------------------------------------------------

def collect_addresses(root, exclude=None, progress=None, kinds=None):
    """Adresses rencontrées dans les en-têtes : {adresse: {"de": n, "a": n, "noms": set, "premier": date, "dernier": date}}."""
    table = {}
    scanned = 0
    for m in iter_mails(root, exclude, progress, kinds):
        scanned += 1
        for fields, key in (([m.sender], "de"), ([m.to, m.cc], "a")):
            for name, addr in email.utils.getaddresses([f for f in fields if f]):
                addr = addr.lower().strip()
                if not addr or "@" not in addr:
                    continue
                e = table.get(addr)
                if e is None:
                    e = table[addr] = {"de": 0, "a": 0, "noms": set(), "premier": m.date, "dernier": m.date}
                e[key] += 1
                if name:
                    e["noms"].add(name.strip())
                if m.date:
                    if e["premier"] is None or m.date < e["premier"]:
                        e["premier"] = m.date
                    if e["dernier"] is None or m.date > e["dernier"]:
                        e["dernier"] = m.date
    return table, scanned


def render_addresses(table, scanned, limit=200):
    out = ["ADRESSES RENCONTRÉES : %d distinctes dans %d message(s)" % (len(table), scanned), "=" * 78,
           "  %-45s %6s %6s  %-10s %-10s %s" % ("adresse", "envoy.", "reçus", "premier", "dernier", "noms")]
    rows = sorted(table.items(), key=lambda kv: -(kv[1]["de"] + kv[1]["a"]))
    for addr, e in rows[:limit]:
        out.append("  %-45s %6d %6d  %-10s %-10s %s" % (addr[:45], e["de"], e["a"],
                                                        e["premier"].strftime("%d/%m/%Y") if e["premier"] else "?",
                                                        e["dernier"].strftime("%d/%m/%Y") if e["dernier"] else "?",
                                                        ", ".join(sorted(e["noms"])[:3])))
    if len(rows) > limit:
        out.append("  ... (%d adresses, voir le CSV)" % len(rows))
    return "\n".join(out)


def write_addresses_csv(table, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["adresse", "messages_envoyes", "messages_recus", "premier", "dernier", "noms"])
        for addr, e in sorted(table.items(), key=lambda kv: -(kv[1]["de"] + kv[1]["a"])):
            w.writerow([addr, e["de"], e["a"], e["premier"].strftime("%Y-%m-%d") if e["premier"] else "",
                        e["dernier"].strftime("%Y-%m-%d") if e["dernier"] else "", ", ".join(sorted(e["noms"]))])


# ---------------------------------------------------------------------------
# Ligne de commande
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="recherche_mails", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("commande", nargs="?", default="gui", choices=["inventaire", "chercher", "adresses", "gui"],
                   help="inventaire : où sont les courriels | chercher : retrouver des messages | adresses : adresses rencontrées | gui")
    p.add_argument("--dossier", "-d", action="append", metavar="DOSSIER", help="dossier ou disque à parcourir (répétable), ex : D:\\")
    p.add_argument("--exclure", action="append", metavar="NOM", help="nom de dossier à ignorer (répétable)")
    p.add_argument("--types", metavar="LISTE", help="limiter aux formats : eml,emlx,mbox,msg")
    c = p.add_argument_group("Critères (tous cumulatifs ; sans accents ni majuscules)")
    c.add_argument("--de", action="append", metavar="TEXTE", help="expéditeur contient (nom ou adresse)")
    c.add_argument("--a", action="append", metavar="TEXTE", help="destinataire (À ou Cc) contient")
    c.add_argument("--sujet", action="append", metavar="TEXTE", help="sujet contient")
    c.add_argument("--texte", action="append", metavar="MOT", help="corps (ou sujet) contient ; répétable = tous les mots")
    c.add_argument("--partout", action="append", metavar="MOT", help="n'importe où (en-têtes, corps, pièces jointes)")
    c.add_argument("--piece-jointe", action="append", metavar="TEXTE", help="nom d'une pièce jointe contient, ex : .pdf ou facture")
    c.add_argument("--avec-pj", action="store_true", help="seulement les messages avec pièce jointe")
    c.add_argument("--du", metavar="DATE", help="à partir de cette date (JJ/MM/AAAA)")
    c.add_argument("--au", metavar="DATE", help="jusqu'à cette date incluse")
    c.add_argument("--regex", metavar="EXPR", help="expression régulière (sensible aux accents) dans le corps ou le sujet")
    c.add_argument("--max", type=int, default=0, metavar="N", help="arrêter après N résultats")
    o = p.add_argument_group("Sortie")
    o.add_argument("--html", metavar="FICHIER", help="écrire les résultats en HTML (liens vers les fichiers)")
    o.add_argument("--csv", metavar="FICHIER", help="écrire les résultats (ou les adresses) en CSV")
    o.add_argument("--extraire", metavar="DOSSIER", help="copier les messages trouvés en .eml dans ce dossier")
    o.add_argument("--sans-extrait", action="store_true", help="ne pas afficher l'extrait du texte")
    return p


def criteria_from_args(args):
    c = Criteria()
    c.sender = args.de or []
    c.to = args.a or []
    c.subject = args.sujet or []
    c.text = args.texte or []
    c.any = args.partout or []
    c.attachment = args.piece_jointe or []
    c.has_attachment = args.avec_pj
    if args.du:
        c.date_from = parse_date(args.du)
    if args.au:
        c.date_to = parse_date(args.au)
    if args.regex:
        c.regex = re.compile(args.regex, re.I | re.M)
    if args.types:
        c.kinds = {t.strip().lower() for t in args.types.split(",") if t.strip()}
    return c


def _setup_console():
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
            from recherche_mails_gui import run_gui
        except ImportError:
            build_parser().print_help()
            return 0
        return run_gui()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.dossier:
        parser.error("indiquez au moins un dossier ou disque : --dossier D:\\")
    for d in args.dossier:
        if not os.path.isdir(d):
            print("ERREUR : dossier introuvable : %s" % d, file=sys.stderr)
            return 2
    progress = lambda m: print("  [..] " + m, file=sys.stderr)
    try:
        if args.commande == "inventaire":
            for d in args.dossier:
                print(render_inventory(inventory(d, args.exclure, progress)))
            return 0
        if args.commande == "adresses":
            table, scanned = {}, 0
            kinds = {t.strip() for t in args.types.split(",")} if args.types else None
            for d in args.dossier:
                t, n = collect_addresses(d, args.exclure, progress, kinds)
                scanned += n
                for k, v in t.items():
                    if k in table:
                        table[k]["de"] += v["de"]; table[k]["a"] += v["a"]; table[k]["noms"] |= v["noms"]
                    else:
                        table[k] = v
            print(render_addresses(table, scanned))
            if args.csv:
                write_addresses_csv(table, args.csv)
                print("CSV écrit : %s" % os.path.abspath(args.csv), file=sys.stderr)
            return 0
        crit = criteria_from_args(args)
        results, scanned = [], 0
        for d in args.dossier:
            r, n = search(d, crit, args.exclure, progress, args.max)
            results.extend(r)
            scanned += n
        results.sort(key=lambda x: x.date or dt.datetime.min, reverse=True)
        print(render_results(results, scanned, crit, detail=not args.sans_extrait))
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(render_results_html(results, scanned, crit))
            print("HTML écrit : %s" % os.path.abspath(args.html), file=sys.stderr)
        if args.csv:
            write_results_csv(results, args.csv)
            print("CSV écrit : %s" % os.path.abspath(args.csv), file=sys.stderr)
        if args.extraire:
            n = extract_results(results, args.extraire, progress)
            print("%d message(s) copié(s) dans %s" % (n, os.path.abspath(args.extraire)), file=sys.stderr)
        return 0
    except (ValueError, re.error) as e:
        print("ERREUR : %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
