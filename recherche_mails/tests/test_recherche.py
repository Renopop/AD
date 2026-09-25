# -*- coding: utf-8 -*-
import datetime as dt, os, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import recherche_mails as core
import exemples_generer

class TestBase(unittest.TestCase):
    def test_norm(self):
        self.assertEqual(core.norm("  Éléve  ÀÀ "), "eleve aa")
    def test_parse_date(self):
        self.assertEqual(core.parse_date("03/03/2025"), dt.date(2025, 3, 3))
        with self.assertRaises(ValueError):
            core.parse_date("nimp")
    def test_html_to_text(self):
        self.assertIn("Bonjour", core.html_to_text("<p>Bonjour<br><b>tout</b></p>"))

class TestRecherche(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        exemples_generer.main(cls.tmp)
    def _crit(self, **kw):
        c = core.Criteria()
        for k, v in kw.items():
            setattr(c, k, v)
        return c
    def test_inventaire(self):
        inv = core.inventory(self.tmp)
        self.assertEqual(inv["counts"]["eml"], 3)
        self.assertEqual(inv["counts"]["mbox"], 1)
        self.assertIn("INVENTAIRE", core.render_inventory(inv))
    def test_de(self):
        r, n = core.search(self.tmp, self._crit(sender=["dupont"]))
        self.assertTrue(n >= 6)
        self.assertTrue(all("dupont" in core.norm(m.sender) for m in r))
        self.assertEqual(len(r), 2)   # .eml + version mbox
    def test_texte_et_dates(self):
        r, _ = core.search(self.tmp, self._crit(text=["contrat"]))
        self.assertTrue(all("contrat" in core.norm(m.body + m.subject) for m in r))
        r2, _ = core.search(self.tmp, self._crit(date_from=dt.date(2025, 5, 1)))
        self.assertTrue(all(m.date.date() >= dt.date(2025, 5, 1) for m in r2))
    def test_piece_jointe(self):
        r, _ = core.search(self.tmp, self._crit(attachment=[".pdf"]))
        self.assertTrue(r and all(m.attachments for m in r))
        r2, _ = core.search(self.tmp, self._crit(has_attachment=True))
        self.assertTrue(all(m.attachments for m in r2))
    def test_accents_insensible(self):
        r, _ = core.search(self.tmp, self._crit(subject=["reunion"]))
        self.assertTrue(any("Réunion" in m.subject for m in r))
    def test_exports_et_extraction(self):
        r, n = core.search(self.tmp, self._crit(sender=["dupont"]))
        self.assertIn("<table", core.render_results_html(r, n, self._crit(sender=["dupont"])))
        with tempfile.TemporaryDirectory() as d:
            core.write_results_csv(r, os.path.join(d, "r.csv"))
            self.assertTrue(os.path.getsize(os.path.join(d, "r.csv")) > 50)
            dest = os.path.join(d, "extr")
            self.assertEqual(core.extract_results(r, dest), len(r))
            self.assertEqual(len([f for f in os.listdir(dest) if f.endswith(".eml")]), len(r))
    def test_adresses(self):
        table, n = core.collect_addresses(self.tmp)
        self.assertIn("jean.dupont@example.com", table)
        self.assertEqual(table["moi@maison.fr"]["a"], 6)
        with tempfile.TemporaryDirectory() as d:
            core.write_addresses_csv(table, os.path.join(d, "a.csv"))
            self.assertTrue(os.path.getsize(os.path.join(d, "a.csv")) > 50)
    def test_cli(self):
        import subprocess
        out = subprocess.run([sys.executable, os.path.join(ROOT, "recherche_mails.py"), "chercher",
                              "--dossier", self.tmp, "--de", "dupont"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        self.assertIn("trouvé", out.stdout.decode("utf-8"))

if __name__ == "__main__":
    unittest.main()
