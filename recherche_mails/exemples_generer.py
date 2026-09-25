#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crée une arborescence d'exemple (.eml, .emlx, .mbox) pour tester recherche_mails.py."""
import email.utils, os, sys

def eml(sender, to, subject, date, body, attach=None):
    h = ["From: %s" % sender, "To: %s" % to, "Subject: %s" % subject, "Date: %s" % date]
    if attach:
        h += ["MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="B"']
        return "\r\n".join(h) + "\r\n\r\n--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body + \
            "\r\n--B\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"%s\"\r\n\r\nJVBERi0x\r\n--B--\r\n" % attach
    return "\r\n".join(h) + "\r\n\r\n" + body

def main(root):
    os.makedirs(os.path.join(root, "Archives"), exist_ok=True)
    os.makedirs(os.path.join(root, "Mail", "Local Folders"), exist_ok=True)
    data = [
        ("Jean Dupont <jean.dupont@example.com>", "moi@maison.fr", "Facture de mars", "Mon, 03 Mar 2025 09:12:00 +0100",
         "Bonjour, veuillez trouver la facture de mars en pièce jointe. Cordialement.", "facture_mars.pdf"),
        ("Marie Martin <marie@societe.fr>", "moi@maison.fr", "Réunion contrat", "Tue, 15 Apr 2025 14:00:00 +0200",
         "Le contrat sera signé la semaine prochaine. Merci de confirmer.", None),
        ("newsletter@boutique.com", "moi@maison.fr", "Promotions du week-end", "Sat, 10 May 2025 08:00:00 +0200",
         "Profitez de nos promotions exceptionnelles ce week-end.", None),
    ]
    for i, (s, t, subj, d, body, att) in enumerate(data):
        with open(os.path.join(root, "Archives", "message_%d.eml" % i), "w", encoding="utf-8") as fh:
            fh.write(eml(s, t, subj, d, body, att))
    mbox = os.path.join(root, "Mail", "Local Folders", "Inbox")
    with open(mbox, "w", encoding="utf-8") as fh:
        for s, t, subj, d, body, att in data:
            fh.write("From %s %s\n" % (email.utils.parseaddr(s)[1], "Mon Jan  1 00:00:00 2025"))
            fh.write(eml(s, t, subj + " (mbox)", d, body).replace("\r\n", "\n") + "\n\n")
    print("Exemple créé dans", root)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "exemple")
