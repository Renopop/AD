#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interface graphique (Tkinter) pour recherche_mails.py."""
import datetime as dt
import os
import queue
import sys
import threading
import traceback
import webbrowser

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

import recherche_mails as core


class App(object):
    def __init__(self, root):
        self.root = root
        root.title("Recherche de courriels sur disque - v" + core.VERSION)
        root.minsize(900, 680)
        self.queue = queue.Queue()
        self.worker = None
        self.results = []
        self.criteria = None
        self._build()
        root.after(200, self._poll)

    def _build(self):
        pad = {"padx": 6, "pady": 3}
        main = ttk.Frame(self.root, padding=8); main.pack(fill="both", expand=True)
        src = ttk.LabelFrame(main, text="1. Où chercher", padding=6); src.pack(fill="x", **pad)
        self.folder = tk.StringVar()
        ttk.Entry(src, textvariable=self.folder, width=60).grid(row=0, column=0, sticky="we")
        ttk.Button(src, text="Parcourir...", command=self._browse).grid(row=0, column=1)
        ttk.Label(src, text="dossier ou disque (ex : D:\\)").grid(row=0, column=2, sticky="w")
        src.columnconfigure(0, weight=1)

        flt = ttk.LabelFrame(main, text="2. Critères (cumulatifs, sans tenir compte des accents/majuscules)", padding=6)
        flt.pack(fill="x", **pad)
        self.vars = {}
        rows = [("de", "Expéditeur contient"), ("a", "Destinataire contient"), ("sujet", "Sujet contient"),
                ("texte", "Texte contient (mots séparés par des espaces)"), ("pj", "Nom de pièce jointe contient")]
        for i, (key, label) in enumerate(rows):
            ttk.Label(flt, text=label + " :").grid(row=i, column=0, sticky="e")
            v = tk.StringVar(); self.vars[key] = v
            ttk.Entry(flt, textvariable=v, width=50).grid(row=i, column=1, columnspan=3, sticky="we")
        ttk.Label(flt, text="Du (JJ/MM/AAAA) :").grid(row=5, column=0, sticky="e")
        self.vars["du"] = tk.StringVar(); ttk.Entry(flt, textvariable=self.vars["du"], width=14).grid(row=5, column=1, sticky="w")
        ttk.Label(flt, text="au :").grid(row=5, column=2, sticky="e")
        self.vars["au"] = tk.StringVar(); ttk.Entry(flt, textvariable=self.vars["au"], width=14).grid(row=5, column=3, sticky="w")
        self.with_pj = tk.BooleanVar()
        ttk.Checkbutton(flt, text="seulement les messages avec pièce jointe", variable=self.with_pj).grid(row=6, column=1, sticky="w")
        flt.columnconfigure(1, weight=1)

        act = ttk.Frame(main); act.pack(fill="x", **pad)
        self.btn = ttk.Button(act, text="Chercher", command=self.run_search); self.btn.pack(side="left")
        ttk.Button(act, text="Inventaire (où sont les mails)", command=self.run_inventory).pack(side="left", padx=6)
        ttk.Button(act, text="Adresses rencontrées", command=self.run_addresses).pack(side="left")
        ttk.Button(act, text="Exporter HTML", command=lambda: self._export("html")).pack(side="right")
        ttk.Button(act, text="Exporter CSV", command=lambda: self._export("csv")).pack(side="right", padx=6)
        ttk.Button(act, text="Extraire les .eml...", command=self._extract).pack(side="right")

        self.status = tk.StringVar(value="Prêt."); ttk.Label(main, textvariable=self.status).pack(fill="x", padx=6)
        self.text = scrolledtext.ScrolledText(main, wrap="word", font=("Consolas", 9)); self.text.pack(fill="both", expand=True, **pad)

    def _browse(self):
        d = filedialog.askdirectory(title="Choisir un dossier ou un disque")
        if d:
            self.folder.set(d)

    def _folders(self):
        d = self.folder.get().strip()
        if not d or not os.path.isdir(d):
            messagebox.showerror("Dossier", "Choisissez un dossier ou un disque existant.")
            return None
        return [d]

    def _criteria(self):
        c = core.Criteria()
        c.sender = [x for x in [self.vars["de"].get().strip()] if x]
        c.to = [x for x in [self.vars["a"].get().strip()] if x]
        c.subject = [x for x in [self.vars["sujet"].get().strip()] if x]
        c.text = [w for w in self.vars["texte"].get().split() if w]
        c.attachment = [x for x in [self.vars["pj"].get().strip()] if x]
        c.has_attachment = self.with_pj.get()
        if self.vars["du"].get().strip():
            c.date_from = core.parse_date(self.vars["du"].get())
        if self.vars["au"].get().strip():
            c.date_to = core.parse_date(self.vars["au"].get())
        return c

    def _start(self, fn):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Patientez", "Une opération est déjà en cours."); return
        self.text.delete("1.0", "end"); self.btn.state(["disabled"])
        self.worker = threading.Thread(target=fn, daemon=True); self.worker.start()

    def run_search(self):
        folders = self._folders()
        if not folders:
            return
        try:
            crit = self._criteria()
        except ValueError as e:
            messagebox.showerror("Critères", str(e)); return
        self.criteria = crit

        def work():
            try:
                results = []
                for d in folders:
                    r, _ = core.search(d, crit, None, lambda m: self.queue.put(("status", m)))
                    results.extend(r)
                results.sort(key=lambda x: x.date or dt.datetime.min, reverse=True)
                self.queue.put(("results", (results, crit)))
            except Exception as e:  # noqa: BLE001
                self.queue.put(("error", str(e) + "\n" + traceback.format_exc()))
        self._start(work)

    def run_inventory(self):
        folders = self._folders()
        if not folders:
            return
        def work():
            try:
                txt = "\n\n".join(core.render_inventory(core.inventory(d, None, lambda m: self.queue.put(("status", m)))) for d in folders)
                self.queue.put(("text", txt))
            except Exception as e:  # noqa: BLE001
                self.queue.put(("error", str(e)))
        self._start(work)

    def run_addresses(self):
        folders = self._folders()
        if not folders:
            return
        def work():
            try:
                table, scanned = {}, 0
                for d in folders:
                    t, n = core.collect_addresses(d, None, lambda m: self.queue.put(("status", m)))
                    scanned += n; table.update(t)
                self.queue.put(("text", core.render_addresses(table, scanned)))
            except Exception as e:  # noqa: BLE001
                self.queue.put(("error", str(e)))
        self._start(work)

    def _export(self, kind):
        if not self.results:
            messagebox.showinfo("Export", "Lancez d'abord une recherche."); return
        if kind == "html":
            p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
            if p:
                open(p, "w", encoding="utf-8").write(core.render_results_html(self.results, len(self.results), self.criteria))
                self.status.set("HTML écrit : " + p); webbrowser.open("file://" + os.path.abspath(p))
        else:
            p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if p:
                core.write_results_csv(self.results, p); self.status.set("CSV écrit : " + p)

    def _extract(self):
        if not self.results:
            messagebox.showinfo("Extraire", "Lancez d'abord une recherche."); return
        d = filedialog.askdirectory(title="Dossier où copier les .eml")
        if d:
            n = core.extract_results(self.results, d)
            self.status.set("%d message(s) copié(s) dans %s" % (n, d))
            messagebox.showinfo("Extraire", "%d message(s) copié(s) dans %s" % (n, d))

    def _poll(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "status":
                    self.status.set(payload)
                elif kind == "error":
                    self.btn.state(["!disabled"]); self.status.set("Erreur.")
                    self.text.insert("end", "ERREUR : " + payload + "\n"); messagebox.showerror("Erreur", payload.split("\n")[0])
                elif kind == "text":
                    self.btn.state(["!disabled"]); self.status.set("Terminé.")
                    self.text.delete("1.0", "end"); self.text.insert("end", payload)
                elif kind == "results":
                    self.btn.state(["!disabled"])
                    self.results, crit = payload
                    self.status.set("%d message(s) trouvé(s)." % len(self.results))
                    self.text.delete("1.0", "end")
                    self.text.insert("end", core.render_results(self.results, len(self.results), crit))
        except queue.Empty:
            pass
        self.root.after(200, self._poll)


def run_gui():
    if tk is None:
        print("Tkinter indisponible : utilisez la ligne de commande (--help).", file=sys.stderr); return 1
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista" if sys.platform.startswith("win") else "clam")
    except Exception:
        pass
    App(root); root.mainloop(); return 0


if __name__ == "__main__":
    sys.exit(run_gui())
