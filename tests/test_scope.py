import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxyhunter.scanner import load_scope


class ScopeTests(unittest.TestCase):
    def test_requires_acknowledgement(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "config").mkdir()
            cfg = root / "config/settings.json"
            cfg.write_text(json.dumps({"authorized_scope_ack": False}), encoding="utf-8")
            (root / "config/cidrs.txt").write_text("192.0.2.0/30\n", encoding="utf-8")
            (root / "config/ports.txt").write_text("1080\n", encoding="utf-8")
            with patch("proxyhunter.scanner.ROOT", root):
                with self.assertRaises(SystemExit):
                    load_scope(cfg)

    def test_empty_scope_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "config").mkdir()
            cfg = root / "config/settings.json"
            cfg.write_text(json.dumps({"authorized_scope_ack": True}), encoding="utf-8")
            (root / "config/cidrs.txt").write_text("# none\n", encoding="utf-8")
            (root / "config/ports.txt").write_text("1080\n", encoding="utf-8")
            with patch("proxyhunter.scanner.ROOT", root):
                with self.assertRaises(SystemExit):
                    load_scope(cfg)


if __name__ == "__main__":
    unittest.main()
