#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface graphique (Tkinter, fournie avec Python) pour adguard_analyse.py.

Lancement :  python adguard_analyse.py        (sans argument)
         ou  python adguard_gui.py
"""
import datetime as dt
import json
import os
import queue
import sys
import threading
import traceback
import webbrowser

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except ImportError:  # pragma: no cover
    tk = None

import adguard_analyse as core

CONFIG_NAME = "adguard_analyse.config.json"


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


class App(object):
    def __init__(self, root):
        self.root = root
        root.title("Analyse des journaux AdGuard Home - v" + core.VERSION)
        root.minsize(900, 700)
        self.queue = queue.Queue()
        self.worker = None
        self.analysis = None
        self.report = None
        self.last_html = None
        self._build()
        self._load_config()
        self.root.after(200, self._poll)

    # ------------------------------------------------------------------ UI
    def _build(self):
        pad = {"padx": 6, "pady": 3}
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill="both", expand=True)

        # --- Source
        src = ttk.LabelFrame(main, text="1. Source des journaux", padding=6)
        src.pack(fill="x", **pad)
        self.source = tk.StringVar(value="api")
        ttk.Radiobutton(src, text="API AdGuard Home (réseau)", variable=self.source, value="api").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(src, text="Fichier querylog.json copié depuis le NAS", variable=self.source, value="file").grid(row=0, column=2, columnspan=2, sticky="w")
        ttk.Label(src, text="URL :").grid(row=1, column=0, sticky="e")
        self.url = tk.StringVar(value="http://192.168.1.10:3000")
        ttk.Entry(src, textvariable=self.url, width=32).grid(row=1, column=1, sticky="we")
        ttk.Label(src, text="Identifiant :").grid(row=2, column=0, sticky="e")
        self.user = tk.StringVar()
        ttk.Entry(src, textvariable=self.user, width=32).grid(row=2, column=1, sticky="we")
        ttk.Label(src, text="Mot de passe :").grid(row=3, column=0, sticky="e")
        self.password = tk.StringVar()
        ttk.Entry(src, textvariable=self.password, width=32, show="*").grid(row=3, column=1, sticky="we")
        self.remember_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(src, text="mémoriser le mot de passe (en clair dans le fichier de configuration)",
                        variable=self.remember_pw).grid(row=4, column=1, sticky="w")
        ttk.Label(src, text="Fichier(s) :").grid(row=1, column=2, sticky="e")
        self.files = tk.StringVar()
        ttk.Entry(src, textvariable=self.files, width=40).grid(row=1, column=3, sticky="we")
        ttk.Button(src, text="Parcourir...", command=self._browse).grid(row=1, column=4)
        ttk.Label(src, text="(querylog.json et querylog.json.1 : plusieurs fichiers séparés par ;)").grid(row=2, column=3, sticky="w")
        ttk.Label(src, text="Baux DHCP :").grid(row=3, column=2, sticky="e")
        self.leases = tk.StringVar()
        ttk.Entry(src, textvariable=self.leases, width=40).grid(row=3, column=3, sticky="we")
        ttk.Button(src, text="Parcourir...", command=self._browse_leases).grid(row=3, column=4)
        ttk.Label(src, text="(facultatif, mode fichier : leases.json du dossier data/ pour les adresses MAC)").grid(row=4, column=3, sticky="w")
        ttk.Button(src, text="Tester / lister les appareils", command=self.list_clients).grid(row=5, column=3, sticky="w")
        src.columnconfigure(1, weight=1)
        src.columnconfigure(3, weight=2)

        # --- Filtres
        flt = ttk.LabelFrame(main, text="2. Filtres", padding=6)
        flt.pack(fill="x", **pad)
        ttk.Label(flt, text="Appareil (IP ou nom) :").grid(row=0, column=0, sticky="e")
        self.client = tk.StringVar()
        self.client_box = ttk.Combobox(flt, textvariable=self.client, width=40)
        self.client_box.grid(row=0, column=1, columnspan=2, sticky="we")
        ttk.Label(flt, text="vide = tous les appareils").grid(row=0, column=3, sticky="w")

        ttk.Label(flt, text="Du (JJ/MM/AAAA) :").grid(row=1, column=0, sticky="e")
        today = dt.date.today()
        self.date_from = tk.StringVar(value=(today - dt.timedelta(days=6)).strftime("%d/%m/%Y"))
        ttk.Entry(flt, textvariable=self.date_from, width=12).grid(row=1, column=1, sticky="w")
        ttk.Label(flt, text="au :").grid(row=1, column=2, sticky="e")
        self.date_to = tk.StringVar(value=today.strftime("%d/%m/%Y"))
        ttk.Entry(flt, textvariable=self.date_to, width=12).grid(row=1, column=3, sticky="w")
        quick = ttk.Frame(flt)
        quick.grid(row=1, column=4, sticky="w")
        for label, days in (("Aujourd'hui", 1), ("7 jours", 7), ("30 jours", 30), ("90 jours", 90)):
            ttk.Button(quick, text=label, width=11, command=lambda d=days: self._quick_days(d)).pack(side="left")

        ttk.Label(flt, text="Plages horaires :").grid(row=2, column=0, sticky="e")
        self.hours = tk.StringVar()
        ttk.Entry(flt, textvariable=self.hours, width=30).grid(row=2, column=1, columnspan=2, sticky="we")
        ttk.Label(flt, text="ex : 22h-6h   ou   12h-14h, 22h-7h   (vide = toute la journée)").grid(row=2, column=3, columnspan=2, sticky="w")

        ttk.Label(flt, text="Jours :").grid(row=3, column=0, sticky="e")
        days_fr = ttk.Frame(flt)
        days_fr.grid(row=3, column=1, columnspan=4, sticky="w")
        self.day_vars = []
        for i, name in enumerate(core.WEEKDAYS_FR):
            v = tk.BooleanVar(value=True)
            self.day_vars.append(v)
            ttk.Checkbutton(days_fr, text=name, variable=v).pack(side="left")
        ttk.Button(days_fr, text="Week-end", width=9, command=lambda: self._set_days({5, 6})).pack(side="left", padx=(12, 0))
        ttk.Button(days_fr, text="Semaine", width=9, command=lambda: self._set_days({0, 1, 2, 3, 4})).pack(side="left")
        ttk.Button(days_fr, text="Tous", width=6, command=lambda: self._set_days(set(range(7)))).pack(side="left")

        ttk.Label(flt, text="Catégories :").grid(row=4, column=0, sticky="e")
        cats_fr = ttk.Frame(flt)
        cats_fr.grid(row=4, column=1, columnspan=4, sticky="w")
        self.cat_vars = {}
        for c in core.CATEGORIES:
            v = tk.BooleanVar(value=True)
            self.cat_vars[c] = v
            ttk.Checkbutton(cats_fr, text=core.CATEGORY_LABELS[c], variable=v).pack(side="left")

        ttk.Label(flt, text="Récurrent si vu au moins").grid(row=5, column=0, sticky="e")
        self.threshold = tk.IntVar(value=3)
        ttk.Spinbox(flt, from_=1, to=90, textvariable=self.threshold, width=5).grid(row=5, column=1, sticky="w")
        ttk.Label(flt, text="jours différents ;   nouvelle session après").grid(row=5, column=2, sticky="e")
        self.gap = tk.IntVar(value=10)
        ttk.Spinbox(flt, from_=1, to=180, textvariable=self.gap, width=5).grid(row=5, column=3, sticky="w")
        ttk.Label(flt, text="minutes sans requête sensible").grid(row=5, column=4, sticky="w")
        self.top_sites = tk.BooleanVar(value=True)
        ttk.Checkbutton(flt, text="ajouter au rapport les 60 sites les plus visités par l'appareil, toutes catégories "
                                  "(pour repérer un site de rencontres inconnu des listes)",
                        variable=self.top_sites).grid(row=6, column=0, columnspan=5, sticky="w")
        flt.columnconfigure(1, weight=1)

        # --- Actions
        act = ttk.Frame(main)
        act.pack(fill="x", **pad)
        self.btn_report = ttk.Button(act, text="Générer le rapport", command=self.run_report)
        self.btn_report.pack(side="left")
        self.open_html = tk.BooleanVar(value=True)
        ttk.Checkbutton(act, text="ouvrir le rapport HTML dans le navigateur", variable=self.open_html).pack(side="left", padx=8)
        ttk.Button(act, text="Détail d'activité (applis)", command=self.run_activity).pack(side="left")
        ttk.Button(act, text="Ouvrir le dernier rapport", command=self._open_last).pack(side="left", padx=8)
        ttk.Button(act, text="Exporter CSV (Excel)", command=self.export_csv).pack(side="left", padx=8)
        ttk.Button(act, text="Enregistrer les paramètres", command=self._save_config).pack(side="right")
        ttk.Button(act, text="Ouvrir le dossier des listes", command=self._open_lists).pack(side="right", padx=8)

        self.status = tk.StringVar(value="Prêt.")
        ttk.Label(main, textvariable=self.status, foreground="#335").pack(fill="x", padx=6)

        self.text = scrolledtext.ScrolledText(main, wrap="none", font=("Consolas", 9))
        self.text.pack(fill="both", expand=True, **pad)

    # ------------------------------------------------------------------ helpers
    def _browse(self):
        paths = filedialog.askopenfilenames(title="Choisir querylog.json",
                                            filetypes=[("Journal AdGuard", "querylog.json*"), ("Tous", "*.*")])
        if paths:
            self.files.set(";".join(paths))
            self.source.set("file")

    def _browse_leases(self):
        path = filedialog.askopenfilename(title="Choisir leases.json", filetypes=[("Baux AdGuard", "leases.json"), ("Tous", "*.*")])
        if path:
            self.leases.set(path)

    def _quick_days(self, n):
        today = dt.date.today()
        self.date_from.set((today - dt.timedelta(days=n - 1)).strftime("%d/%m/%Y"))
        self.date_to.set(today.strftime("%d/%m/%Y"))

    def _set_days(self, days):
        for i, v in enumerate(self.day_vars):
            v.set(i in days)

    def _open_lists(self):
        d = core.find_lists_directory()
        if not d:
            messagebox.showwarning("Listes", "Dossier 'listes' introuvable à côté du programme.")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(d)  # type: ignore[attr-defined]
            else:
                webbrowser.open("file://" + d)
        except Exception as e:
            messagebox.showinfo("Listes", "Dossier des listes : %s\n(%s)" % (d, e))

    def _open_last(self):
        if self.last_html and os.path.isfile(self.last_html):
            webbrowser.open("file://" + os.path.abspath(self.last_html))
        else:
            messagebox.showinfo("Rapport", "Aucun rapport généré pour l'instant.")

    def _log(self, msg):
        self.text.insert("end", msg + "\n")
        self.text.see("end")

    def _config_path(self):
        return os.path.join(app_dir(), CONFIG_NAME)

    def _save_config(self):
        cfg = {
            "source": self.source.get(), "url": self.url.get(), "user": self.user.get(),
            "files": self.files.get(), "leases": self.leases.get(), "client": self.client.get(), "hours": self.hours.get(),
            "days": [v.get() for v in self.day_vars],
            "categories": {c: v.get() for c, v in self.cat_vars.items()},
            "threshold": self.threshold.get(), "gap": self.gap.get(), "open_html": self.open_html.get(),
            "top_sites": self.top_sites.get(),
            "remember_pw": self.remember_pw.get(),
        }
        if self.remember_pw.get():
            cfg["password"] = self.password.get()
        try:
            with open(self._config_path(), "w", encoding="utf-8") as fh:
                json.dump(cfg, fh, indent=2, ensure_ascii=False)
            self.status.set("Paramètres enregistrés dans " + self._config_path())
        except OSError as e:
            messagebox.showerror("Configuration", "Impossible d'écrire la configuration : %s" % e)

    def _load_config(self):
        p = self._config_path()
        if not os.path.isfile(p):
            return
        try:
            with open(p, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError):
            return
        self.source.set(cfg.get("source", "api"))
        self.url.set(cfg.get("url", self.url.get()))
        self.user.set(cfg.get("user", ""))
        self.password.set(cfg.get("password", ""))
        self.remember_pw.set(bool(cfg.get("remember_pw")))
        self.files.set(cfg.get("files", ""))
        self.leases.set(cfg.get("leases", ""))
        self.client.set(cfg.get("client", ""))
        self.hours.set(cfg.get("hours", ""))
        for v, val in zip(self.day_vars, cfg.get("days", [True] * 7)):
            v.set(bool(val))
        for c, val in cfg.get("categories", {}).items():
            if c in self.cat_vars:
                self.cat_vars[c].set(bool(val))
        self.threshold.set(int(cfg.get("threshold", 3)))
        self.gap.set(int(cfg.get("gap", 10)))
        self.open_html.set(bool(cfg.get("open_html", True)))
        self.top_sites.set(bool(cfg.get("top_sites", True)))

    def _job(self, for_clients=False):
        job = core.Job()
        if self.source.get() == "api":
            if not self.url.get().strip():
                raise ValueError("Indiquez l'URL d'AdGuard Home (ex : http://192.168.1.10:3000).")
            job.api_url = self.url.get().strip()
            job.api_user = self.user.get().strip() or None
            job.api_password = self.password.get()
        else:
            paths = [p.strip() for p in self.files.get().split(";") if p.strip()]
            if not paths:
                raise ValueError("Choisissez au moins un fichier querylog.json.")
            job.log_paths = paths
            if self.leases.get().strip():
                job.leases_path = self.leases.get().strip()
        if not for_clients:
            raw = self.client.get()
            # valeur choisie dans la liste : "192.168.1.42   (iPhone)   - iPhone/iPad" -> garder l'IP
            if "   " in raw:
                raw = raw.split("   ")[0]
            job.clients = [c.strip() for c in raw.split(",") if c.strip()]
        if self.date_from.get().strip():
            job.date_from = core.parse_date(self.date_from.get())
        if self.date_to.get().strip():
            job.date_to = core.parse_date(self.date_to.get())
        if job.date_from and job.date_to and job.date_from > job.date_to:
            raise ValueError("La date de début est après la date de fin.")
        job.hour_ranges = core.parse_hour_ranges(self.hours.get())
        days = {i for i, v in enumerate(self.day_vars) if v.get()}
        job.weekdays = days if 0 < len(days) < 7 else None
        job.categories = [c for c, v in self.cat_vars.items() if v.get()] or list(core.CATEGORIES)
        job.threshold_days = max(1, int(self.threshold.get()))
        job.gap_minutes = max(1, int(self.gap.get()))
        job.top_sites = 60 if self.top_sites.get() else 0
        return job

    # ------------------------------------------------------------------ actions
    def _start(self, target):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Patientez", "Une analyse est déjà en cours.")
            return
        self.text.delete("1.0", "end")
        self.btn_report.state(["disabled"])
        self.worker = threading.Thread(target=target, daemon=True)
        self.worker.start()

    def list_clients(self):
        try:
            job = self._job(for_clients=True)
        except ValueError as e:
            messagebox.showerror("Paramètres", str(e))
            return

        def work():
            try:
                analysis = core.run_analysis(job, lambda m: self.queue.put(("status", m)), for_clients=True)
                self.queue.put(("clients", analysis))
            except Exception as e:  # noqa: BLE001
                self.queue.put(("error", "%s\n%s" % (e, traceback.format_exc() if not isinstance(e, (ValueError, RuntimeError, FileNotFoundError)) else "")))
        self._start(work)

    def run_report(self):
        try:
            job = self._job()
        except ValueError as e:
            messagebox.showerror("Paramètres", str(e))
            return

        def work():
            try:
                analysis = core.run_analysis(job, lambda m: self.queue.put(("status", m)))
                rep = core.build_report(analysis, job.threshold_days, job.gap_minutes, top_sites=job.top_sites)
                out_dir = os.path.join(app_dir(), "rapports")
                os.makedirs(out_dir, exist_ok=True)
                name = "rapport_%s.html" % dt.datetime.now().strftime("%Y-%m-%d_%Hh%M")
                path = os.path.join(out_dir, name)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(core.render_html(rep))
                self.queue.put(("report", (analysis, rep, path)))
            except Exception as e:  # noqa: BLE001
                self.queue.put(("error", "%s\n%s" % (e, traceback.format_exc() if not isinstance(e, (ValueError, RuntimeError, FileNotFoundError)) else "")))
        self._start(work)

    def run_activity(self):
        try:
            job = self._job()
        except ValueError as e:
            messagebox.showerror("Paramètres", str(e))
            return
        if not job.clients:
            messagebox.showinfo("Appareil", "Choisissez d'abord un appareil (IP ou nom) : le détail d'activité porte sur un seul appareil.")
            return
        job.activity = True

        def work():
            try:
                analysis = core.run_analysis(job, lambda m: self.queue.put(("status", m)))
                act = core.build_activity(analysis, job.gap_minutes)
                out_dir = os.path.join(app_dir(), "rapports")
                os.makedirs(out_dir, exist_ok=True)
                path = os.path.join(out_dir, "activite_%s.html" % dt.datetime.now().strftime("%Y-%m-%d_%Hh%M"))
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(core.render_activity_html(act, analysis.filters))
                self.queue.put(("activity", (analysis, act, path)))
            except Exception as e:  # noqa: BLE001
                self.queue.put(("error", "%s\n%s" % (e, traceback.format_exc() if not isinstance(e, (ValueError, RuntimeError, FileNotFoundError)) else "")))
        self._start(work)

    def export_csv(self):
        if not self.report:
            messagebox.showinfo("CSV", "Générez d'abord un rapport.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialfile="detail_%s.csv" % dt.date.today().isoformat())
        if path:
            core.write_csv(self.report, path)
            self.status.set("CSV écrit : " + path)

    def _poll(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "status":
                    self.status.set(payload)
                    self._log("  [..] " + payload)
                elif kind == "error":
                    self.btn_report.state(["!disabled"])
                    self.status.set("Erreur.")
                    self._log("ERREUR : " + payload)
                    messagebox.showerror("Erreur", payload.split("\n")[0])
                elif kind == "clients":
                    self.btn_report.state(["!disabled"])
                    self.analysis = payload
                    self._log("")
                    self._log(core.render_clients_text(payload))
                    values = []
                    for cs in sorted(payload.clients.values(), key=lambda c: -c.count):
                        mac, vendor, dhcp_name, _ = payload.lease_info(cs.ip)
                        names = sorted(set(list(cs.names) + ([payload.aliases[cs.ip.lower()]] if cs.ip.lower() in payload.aliases else [])
                                           + ([dhcp_name] if dhcp_name else [])))
                        values.append(cs.ip + ("   (%s)" % ", ".join(names) if names else "") + "   - " + cs.guess()
                                      + ("   - %s %s" % (mac, vendor) if mac else ""))
                    self.client_box["values"] = values
                    self.status.set("%d appareil(s) trouvé(s). Choisissez-en un dans la liste puis générez le rapport." % len(values))
                elif kind == "activity":
                    self.btn_report.state(["!disabled"])
                    analysis, act, path = payload
                    self.analysis, self.last_html = analysis, path
                    self._log("")
                    self._log(core.render_activity_text(act, analysis.filters))
                    self.status.set("Détail d'activité HTML : " + path)
                    if self.open_html.get():
                        webbrowser.open("file://" + os.path.abspath(path))
                elif kind == "report":
                    self.btn_report.state(["!disabled"])
                    analysis, rep, path = payload
                    self.analysis, self.report, self.last_html = analysis, rep, path
                    self._log("")
                    self._log(core.render_text(rep))
                    self.status.set("Rapport HTML : " + path)
                    if self.open_html.get():
                        webbrowser.open("file://" + os.path.abspath(path))
        except queue.Empty:
            pass
        self.root.after(200, self._poll)


def run_gui():
    if tk is None:
        print("Tkinter n'est pas disponible : utilisez la ligne de commande (--help).", file=sys.stderr)
        return 1
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista" if sys.platform.startswith("win") else "clam")
    except Exception:
        pass
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(run_gui())
