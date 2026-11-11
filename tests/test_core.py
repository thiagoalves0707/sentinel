"""Testes das partes críticas: escopo, CVSS, scanner de segredos e escape do relatório.

    python -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import cvss  # noqa: E402
import report  # noqa: E402
import secrets_scan  # noqa: E402
from _common import check_target, normalize_target  # noqa: E402

SCOPE = {
    "in_scope": ["10.10.10.0/24", "*.acme.com", "shop.acme.com.br", "192.168.1.10-192.168.1.20",
                 "https://api.lab.local/v1", "2001:db8::/64"],
    "out_of_scope": ["10.10.10.1", "admin.acme.com"],
}


class TestScope(unittest.TestCase):
    def assertScope(self, target, expected):
        ok, why = check_target(SCOPE, target)
        self.assertEqual(ok, expected, f"{target}: {why}")

    def test_ips_e_redes(self):
        self.assertScope("10.10.10.5", True)
        self.assertScope("10.10.10.5:22", True)
        self.assertScope("10.10.11.5", False)
        self.assertScope("192.168.1.15", True)
        self.assertScope("192.168.1.21", False)
        self.assertScope("[2001:db8::5]:443", True)

    def test_exclusao_sempre_vence(self):
        self.assertScope("10.10.10.1", False)
        self.assertScope("admin.acme.com", False)
        self.assertScope("x.admin.acme.com", False)   # subdomínio de algo proibido também é proibido

    def test_dominios(self):
        self.assertScope("app.acme.com", True)
        self.assertScope("https://app.acme.com:8443/login", True)
        self.assertScope("acme.com", False)             # *.acme.com não inclui o domínio raiz
        self.assertScope("evilacme.com", False)
        self.assertScope("app.acme.com.evil.com", False)
        self.assertScope("api.lab.local", True)

    def test_janela_de_tempo(self):
        s = dict(SCOPE, window={"start": "2000-01-01", "end": "2000-01-02"})
        self.assertFalse(check_target(s, "10.10.10.5")[0])

    def test_normalize(self):
        self.assertEqual(normalize_target("HTTPS://App.Acme.com:443/x?y=1"), "app.acme.com")
        self.assertEqual(normalize_target("[::1]:8080"), "::1")


class TestCVSS(unittest.TestCase):
    CASES = {
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
        "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
        "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
        "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
        "AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
        "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    }

    def test_notas_oficiais(self):
        for vec, expected in self.CASES.items():
            self.assertEqual(cvss.score("CVSS:3.1/" + vec), expected, vec)

    def test_severidade(self):
        self.assertEqual(cvss.severity(9.8), "critical")
        self.assertEqual(cvss.severity(7.0), "high")
        self.assertEqual(cvss.severity(6.1), "medium")
        self.assertEqual(cvss.severity(1.6), "low")

    def test_vetor_invalido(self):
        with self.assertRaises(ValueError):
            cvss.score("CVSS:3.1/AV:N/AC:L")
        with self.assertRaises(ValueError):
            cvss.score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestSecrets(unittest.TestCase):
    def scan(self, line):
        out = []
        secrets_scan.scan_text(line, "x", out)
        return out

    def test_acha_segredos_reais(self):
        # Montados em pedaços para este próprio arquivo não disparar o scanner.
        gh = "ghp_" + "R7d" * 12
        self.assertTrue(self.scan(f'token = "{gh}"'))
        self.assertTrue(self.scan("AKIA" + "Q3EXJ7LM2NPZ5K4T"))
        self.assertTrue(self.scan("-----BEGIN OPENSSH " + "PRIVATE KEY-----"))
        self.assertTrue(self.scan('DB_PASSWORD="k9$Lq2!vZr7#pW"'))  # sentinel:ignore (exemplo de teste)

    def test_ignora_codigo(self):
        self.assertFalse(self.scan("secret = m.group(1) if m.groups() else m.group(0)"))
        self.assertFalse(self.scan("password = config.database.password"))

    def test_ignora_placeholders(self):
        self.assertFalse(self.scan("GEMINI_API_KEY=cole_sua_chave_aqui"))
        self.assertFalse(self.scan("password = os.environ['DB_PASS']"))
        self.assertFalse(self.scan('api_key: "<SUA_CHAVE>"'))
        self.assertFalse(self.scan("api_key = process.env.KEY"))

    def test_mascara(self):
        res = self.scan('token = "' + "ghp_" + "R7d" * 12 + '"')
        self.assertNotIn("R7dR7dR7dR7d", res[0]["preview"])


class TestRelatorio(unittest.TestCase):
    def test_markdown_escapa_html(self):
        out = report.md("<script>alert(1)</script> **ok**")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("<strong>ok</strong>", out)


if __name__ == "__main__":
    unittest.main()
