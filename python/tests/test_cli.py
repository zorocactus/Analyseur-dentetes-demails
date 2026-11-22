import builtins
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from header_analyzer.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class CliTests(unittest.TestCase):
    def test_default_cli_does_not_import_optional_network_or_geoip_packages(self):
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if name.split(".", 1)[0] in {"dns", "geoip2"}:
                raise AssertionError(f"Optional package imported in offline mode: {name}")
            return original_import(name, *args, **kwargs)

        output = io.StringIO()
        with patch("builtins.__import__", side_effect=guarded_import):
            with redirect_stdout(output):
                result = main([str(SAMPLES / "legit.eml"), "--no-color"])
        self.assertEqual(result, 0)
        self.assertIn("Score : 0/100", output.getvalue())

    @patch("header_analyzer.cli._apply_geoip")
    @patch(
        "header_analyzer.cli._query_dns",
        return_value=(
            {
                "TXT:github.com": ["v=spf1 -all"],
                "TXT:_dmarc.github.com": ["v=DMARC1; p=reject"],
            },
            {"github.com": "NOERROR", "_dmarc.github.com": "NOERROR"},
        ),
    )
    def test_opt_in_cli_adapters_are_called(self, query_dns, apply_geoip):
        with redirect_stdout(io.StringIO()):
            result = main(
                [
                    str(SAMPLES / "legit.eml"),
                    "--dns",
                    "--geoip",
                    "local.mmdb",
                    "--json",
                ]
            )
        self.assertEqual(result, 0)
        query_dns.assert_called_once()
        self.assertEqual(apply_geoip.call_args.args[1], "local.mmdb")


if __name__ == "__main__":
    unittest.main()
