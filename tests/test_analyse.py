# -*- coding: utf-8 -*-
"""Tests automatisés :  python3 -m unittest discover -s tests -v"""
import datetime as dt
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import adguard_analyse as core  # noqa: E402

PARIS = dt.timezone(dt.timedelta(hours=2))


def make_classifier():
    c = core.Classifier()
    assert c.load_directory(os.path.join(ROOT, "listes"))
    return c


class TestTemps(unittest.TestCase):
    def test_parse_time_nanosecondes(self):
        t = core.parse_time("2026-09-20T22:13:04.123456789+02:00")
        self.assertEqual(t.hour, 22)
        self.assertEqual(t.microsecond, 123456)
        self.assertEqual(t.utcoffset(), dt.timedelta(hours=2))

    def test_parse_time_utc(self):
        t = core.parse_time("2026-09-20T20:13:04Z")
        self.assertEqual(t.utcoffset(), dt.timedelta(0))
        self.assertIsNone(core.parse_time("n'importe quoi"))

    def test_plages_horaires(self):
        r = core.parse_hour_ranges("22h-6h, 12:00-14:00")
        self.assertEqual(r, [(1320, 360), (720, 840)])
        self.assertTrue(core.minute_in_ranges(23 * 60, r))
        self.assertTrue(core.minute_in_ranges(2 * 60, r))
        self.assertFalse(core.minute_in_ranges(6 * 60, r))
        self.assertTrue(core.minute_in_ranges(13 * 60, r))
        self.assertFalse(core.minute_in_ranges(15 * 60, r))
        self.assertTrue(core.minute_in_ranges(15 * 60, []))
        with self.assertRaises(ValueError):
            core.parse_hour_ranges("22h")

    def test_dates(self):
        self.assertEqual(core.parse_date("21/09/2026"), dt.date(2026, 9, 21))
        self.assertEqual(core.parse_date("2026-09-21"), dt.date(2026, 9, 21))
        with self.assertRaises(ValueError):
            core.parse_date("31/31/2026")

    def test_jours_semaine(self):
        self.assertEqual(core.parse_weekdays("weekend"), {5, 6})
        self.assertEqual(core.parse_weekdays("lun,mer"), {0, 2})
        self.assertIsNone(core.parse_weekdays(""))


class TestDomaines(unittest.TestCase):
    def test_base_domain(self):
        self.assertEqual(core.base_domain("fr.pornhub.com"), "pornhub.com")
        self.assertEqual(core.base_domain("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(core.base_domain("ome.tv"), "ome.tv")

    def test_classification(self):
        c = make_classifier()
        self.assertEqual(c.classify("fr.pornhub.com")[0], "porno")
        self.assertEqual(c.classify("ei.phncdn.com")[0], "porno")
        self.assertEqual(c.classify("api.gotinder.com")[0], "rencontres")
        self.assertEqual(c.classify("ome.tv")[0], "chat-aleatoire")
        self.assertEqual(c.classify("www.free-porn-videos.xxx")[1], "mot-clé")
        self.assertEqual(c.classify("site-de-rencontre-gratuit.fr")[0], "rencontres")
        self.assertEqual(c.classify("sexemodel.com")[0], "porno")
        self.assertEqual(c.classify("sextape-amateur.net")[0], "porno")

    def test_faux_positifs(self):
        c = make_classifier()
        for host in ("essex.ac.uk", "www.adultswim.com", "wizzair.com", "unisexshop.com", "analytics.google.com",
                     "www.canal-plus.com", "dickies.com", "cockpit-app.fr", "www.sussex.ac.uk", "javadoc.io"):
            self.assertIsNone(c.classify(host)[0], host)

    def test_raison_adguard(self):
        c = make_classifier()
        self.assertEqual(c.classify("site-inconnu.example", reason="FilteredParental")[0], "porno")
        self.assertEqual(c.classify("site-inconnu.example", reason="FilteredBlockedService", service_name="tinder")[0], "rencontres")
        self.assertIsNone(c.classify("site-inconnu.example", reason="FilteredBlockList")[0])

    def test_syntaxe_mots_cles(self):
        self.assertTrue(core.Keyword("^sex").matches("sexy"))
        self.assertFalse(core.Keyword("^sex").matches("essex"))
        self.assertTrue(core.Keyword("sex$").matches("essex"))
        self.assertTrue(core.Keyword("=adult").matches("adult"))
        self.assertFalse(core.Keyword("=adult").matches("adultswim"))

    def test_format_hosts_et_adguard(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "porno.txt")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("# commentaire\n0.0.0.0 exemple-hosts.com\n||exemple-adguard.com^\nexemple-simple.com\n")
            c = core.Classifier()
            c.load_directory(d)
            self.assertEqual(c.classify("www.exemple-hosts.com")[0], "porno")
            self.assertEqual(c.classify("exemple-adguard.com")[0], "porno")
            self.assertEqual(c.classify("a.exemple-simple.com")[0], "porno")


def entry(t, host, ip, reason=0, filtered=False):
    return core.entry_from_file({"T": t.strftime("%Y-%m-%dT%H:%M:%S.000000000+02:00"), "QH": host, "QT": "A",
                                 "IP": ip, "Result": {"IsFiltered": filtered, "Reason": reason} if filtered else {}})


class TestAnalyse(unittest.TestCase):
    def setUp(self):
        self.c = make_classifier()
        base = dt.datetime(2026, 9, 1, 0, 0, tzinfo=PARIS)
        self.entries = []
        for day in range(6):
            d = base + dt.timedelta(days=day)
            self.entries.append(entry(d + dt.timedelta(hours=10), "www.google.com", "192.168.1.42"))
            self.entries.append(entry(d + dt.timedelta(hours=23, minutes=10), "fr.pornhub.com", "192.168.1.42", 5, True))
            self.entries.append(entry(d + dt.timedelta(hours=23, minutes=12), "ei.phncdn.com", "192.168.1.42"))
            if day % 2 == 0:
                self.entries.append(entry(d + dt.timedelta(hours=12, minutes=30), "api.gotinder.com", "192.168.1.31"))
        self.entries.append(entry(base + dt.timedelta(days=10, hours=8), "www.xnxx.com", "192.168.1.42"))

    def analyse(self, **kw):
        job = core.Job()
        for k, v in kw.items():
            setattr(job, k, v)
        job.tz = "+02:00"
        f = core.build_filters(job)
        a = core.Analysis(f, self.c, {"192.168.1.42": "iPhone-Ado"})
        a.feed(self.entries)
        return a

    def test_filtre_client_et_dates(self):
        a = self.analyse(clients=["192.168.1.42"], date_from=dt.date(2026, 9, 1), date_to=dt.date(2026, 9, 6))
        self.assertEqual(a.total_selected, 18)
        self.assertEqual(len(a.records), 12)
        self.assertEqual(a.records[0].client_name, "iPhone-Ado")
        a = self.analyse(clients=["iphone"], date_from=dt.date(2026, 9, 1), date_to=dt.date(2026, 9, 6))
        self.assertEqual(len(a.records), 12)

    def test_filtre_heures_nuit(self):
        a = self.analyse(clients=["192.168.1.42"], hour_ranges=[(22 * 60, 6 * 60)])
        self.assertEqual(len(a.records), 12)
        self.assertTrue(all(r.time.hour == 23 for r in a.records))
        a = self.analyse(clients=["192.168.1.42"], hour_ranges=[(7 * 60, 9 * 60)])
        self.assertEqual([r.host for r in a.records], ["www.xnxx.com"])

    def test_filtre_jours_semaine(self):
        a = self.analyse(weekdays={5, 6})  # 5 et 6 septembre 2026 = samedi, dimanche
        self.assertTrue(all(r.time.weekday() in (5, 6) for r in a.records))
        self.assertEqual(len(a.records), 5)

    def test_rapport_recurrence_sessions(self):
        a = self.analyse(clients=["192.168.1.42"], date_from=dt.date(2026, 9, 1), date_to=dt.date(2026, 9, 11))
        rep = core.build_report(a, threshold_days=3, gap_minutes=10)
        self.assertEqual(rep["n_days"], 11)
        self.assertEqual(len(rep["sessions"]), 7)
        rec = {s["domain"] for s in rep["recurrent"]}
        self.assertEqual(rec, {"pornhub.com", "phncdn.com"})
        self.assertEqual(rep["blocked_by_cat"]["porno"], 6)
        slots = core.typical_slots(rep["hours"])
        self.assertIn("23h-00h", slots)
        txt = core.render_text(rep, detail=True)
        self.assertIn("pornhub.com", txt)
        html_out = core.render_html(rep)
        self.assertIn("<table", html_out)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.csv")
            core.write_csv(rep, p)
            with open(p, encoding="utf-8-sig") as fh:
                lines = fh.read().splitlines()
            self.assertEqual(len(lines), 1 + len(rep["records"]))

    def test_categories_limitees(self):
        a = self.analyse(categories=["rencontres"])
        self.assertTrue(all(r.category == "rencontres" for r in a.records))
        self.assertEqual(len(a.records), 3)

    def test_clients_devine(self):
        base = dt.datetime(2026, 9, 1, 12, 0, tzinfo=PARIS)
        es = [entry(base, "time-ios.apple.com", "10.0.0.5"), entry(base, "api.snapchat.com", "10.0.0.5"),
              entry(base, "mask.icloud.com", "10.0.0.5"), entry(base, "connectivitycheck.gstatic.com", "10.0.0.6")]
        a = core.Analysis(core.Filters(), self.c)
        a.feed(es)
        self.assertTrue(a.clients["10.0.0.5"].guess().startswith("iPhone"))
        self.assertEqual(a.clients["10.0.0.6"].guess(), "Android")
        self.assertEqual(a.clients["10.0.0.5"].apps["Snapchat"], 1)
        rep = core.build_report(a)
        self.assertTrue(any("Private Relay" in w for w in rep["warnings"]))
        self.assertIn("iPhone", core.render_clients_text(a))


# ----------------------------------------------------------------------------- faux serveur AdGuard
class FakeAdGuard(http.server.BaseHTTPRequestHandler):
    entries = []  # du plus récent au plus ancien

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Authorization") != "Basic YWRtaW46c2VjcmV0":  # admin:secret
            return self._send(401, {"message": "unauthorized"})
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        if url.path == "/control/status":
            return self._send(200, {"version": "v0.107.0-test"})
        if url.path == "/control/clients":
            return self._send(200, {"clients": [{"name": "iPhone-Ado", "ids": ["192.168.1.42"]}], "auto_clients": []})
        if url.path == "/control/querylog":
            limit = int(q.get("limit", ["500"])[0])
            older = q.get("older_than", [None])[0]
            search = q.get("search", [None])[0]
            data = [e for e in self.entries if (older is None or e["time"] < older)
                    and (search is None or search in e["client"] or search in e["question"]["name"])]
            page = data[:limit]
            return self._send(200, {"data": page, "oldest": page[-1]["time"] if page else ""})
        self._send(404, {})


class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = dt.datetime(2026, 9, 10, 0, 0, tzinfo=PARIS)
        es = []
        for i in range(1200):
            t = base - dt.timedelta(minutes=7 * i)
            host = "fr.pornhub.com" if i % 50 == 0 else "www.google.com"
            es.append({"time": t.strftime("%Y-%m-%dT%H:%M:%S.000000000+02:00"),
                       "question": {"name": host, "type": "A", "class": "IN"},
                       "client": "192.168.1.42" if i % 3 else "192.168.1.20",
                       "client_info": {"name": "iphone-de-ado" if i % 3 else ""},
                       "reason": "FilteredParental" if host != "www.google.com" else "NotFilteredNotFound",
                       "rule": "", "rules": [], "status": "NOERROR"})
        FakeAdGuard.entries = es
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), FakeAdGuard)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_pagination_et_borne_de_date(self):
        api = core.AdGuardAPI(self.url, "admin", "secret")
        self.assertEqual(api.status()["version"], "v0.107.0-test")
        self.assertEqual(api.clients()["192.168.1.42"], "iPhone-Ado")
        since = dt.datetime(2026, 9, 8, 0, 0, tzinfo=PARIS)
        got = list(api.iter_querylog(since=since, limit=100))
        # 2 jours * 24 h * 60 / 7 min ~ 411 entrées, arrondi à la page de 100 suivante
        self.assertGreaterEqual(len(got), 411)
        self.assertLess(len(got), 411 + 100)
        self.assertEqual(got[1].client_name, "iphone-de-ado")
        self.assertTrue(got[0].time > got[-1].time)

    def test_mauvais_mot_de_passe(self):
        api = core.AdGuardAPI(self.url, "admin", "faux")
        with self.assertRaises(RuntimeError):
            api.status()

    def test_run_analysis_api(self):
        job = core.Job()
        job.api_url, job.api_user, job.api_password = self.url, "admin", "secret"
        job.clients = ["192.168.1.42"]
        job.date_from, job.date_to = dt.date(2026, 9, 5), dt.date(2026, 9, 9)
        job.tz = "+02:00"
        a = core.run_analysis(job)
        self.assertTrue(a.total_selected > 0)
        self.assertTrue(all(r.client == "192.168.1.42" for r in a.records))
        self.assertTrue(all(r.blocked for r in a.records))
        self.assertEqual(a.records[0].client_name, "iphone-de-ado")


class TestCLI(unittest.TestCase):
    def test_job_from_args(self):
        p = core.build_parser()
        args = p.parse_args(["rapport", "--log", "x.json", "--client", "192.168.1.42", "--jours", "7",
                             "--heures", "22h-6h", "--weekend", "--categories", "porno"])
        job = core.job_from_args(args)
        self.assertEqual(job.hour_ranges, [(1320, 360)])
        self.assertEqual(job.weekdays, {5, 6})
        self.assertEqual(job.categories, ["porno"])
        self.assertEqual((job.date_to - job.date_from).days, 6)
        with self.assertRaises(ValueError):
            core.job_from_args(p.parse_args(["--log", "x", "--categories", "inconnue"]))

    def test_exemple_complet(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "querylog.json")
            subprocess.check_call([sys.executable, os.path.join(ROOT, "exemples", "generer_exemple.py"), log, "--jours", "5"])
            html_path = os.path.join(d, "r.html")
            out = subprocess.run([sys.executable, os.path.join(ROOT, "adguard_analyse.py"), "rapport", "--log", log,
                                  "--client", "192.168.1.42", "--tz", "+02:00", "--html", html_path, "--seuil-recurrence", "2"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.assertIn("RAPPORT", out.stdout.decode("utf-8"))
            self.assertTrue(os.path.getsize(html_path) > 1000)
            out = subprocess.run([sys.executable, os.path.join(ROOT, "adguard_analyse.py"), "clients", "--log", d],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.assertIn("iPhone", out.stdout.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()


class TestRencontres(unittest.TestCase):
    def test_priorite_rencontres_sur_porno(self):
        c = make_classifier()
        self.assertEqual(c.classify("sexe-rencontre.com")[0], "rencontres")
        self.assertEqual(c.classify("sexy-cougars.net")[0], "rencontres")
        self.assertEqual(c.classify("www.xvideos.com")[0], "porno")

    def test_listes_externes_livrees(self):
        c = make_classifier()
        self.assertEqual(c.classify("affiny.fr")[0], "rencontres")            # UT1
        self.assertEqual(c.classify("www.c-dating.fr")[0], "rencontres")      # ShadowWhisperer
        self.assertEqual(c.classify("www.cougarlife.com")[0], "rencontres")
        self.assertIsNone(c.classify("www.meetup.com")[0])

    def test_top_sites(self):
        c = make_classifier()
        base = dt.datetime(2026, 9, 1, 12, 0, tzinfo=PARIS)
        es = [entry(base, "www.google.com", "10.0.0.5"), entry(base, "api.gotinder.com", "10.0.0.5"),
              entry(base, "www.google.com", "10.0.0.5")]
        a = core.Analysis(core.Filters(clients=["10.0.0.5"]), c, keep_all_hosts=True)
        a.feed(es)
        rep = core.build_report(a, top_sites=10)
        self.assertEqual(rep["top_sites"][0], ("google.com", 2, None))
        self.assertEqual(rep["top_sites"][1], ("gotinder.com", 1, "rencontres"))
        self.assertIn("SITES LES PLUS VISITÉS PAR L'APPAREIL", core.render_text(rep))
        self.assertIn("Sites les plus visités par l'appareil", core.render_html(rep))


class TestTirets(unittest.TestCase):
    def test_mots_cles_dans_noms_a_tirets(self):
        c = make_classifier()
        self.assertEqual(c.classify("hot-matures.vip")[0], "porno")
        self.assertEqual(c.classify("rencontre-mature.fr")[0], "rencontres")
        self.assertEqual(c.classify("strip-chat.webcam")[0], "porno")
        self.assertEqual(c.classify("les-cougars-de-lyon.fr")[0], "rencontres")
        self.assertIsNone(c.classify("mon-site-essex.co.uk")[0])
        self.assertEqual(c.classify("wizzapp.com")[0], "rencontres")
        self.assertEqual(c.classify("api.replika.com")[0], "rencontres")
