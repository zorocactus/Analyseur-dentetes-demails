import unittest
from pathlib import Path

from header_analyzer import analyze
from header_analyzer.analyzer import levenshtein, registrable, check_lookalike, DEFAULT_BRANDS
from header_analyzer.dns_checks import (
    needed_dns_queries,
    parse_dkim_key,
    parse_dmarc,
    parse_spf,
)

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def codes(report):
    return {f["code"] for f in report.findings}


class AnalyzerTests(unittest.TestCase):
    def test_legit_mail_is_clean(self):
        r = analyze((SAMPLES / "legit.eml").read_bytes())
        self.assertEqual(r.findings, [])
        self.assertEqual(r.score, 0)

    def test_phishing_sample_is_flagged(self):
        r = analyze((SAMPLES / "phishing.eml").read_bytes())
        self.assertGreaterEqual(r.score, 45)
        for expected in ("spf_fail", "dmarc_fail", "reply_to", "homoglyph", "urgency"):
            self.assertIn(expected, codes(r))

    def test_no_auth_headers(self):
        r = analyze(b"From: a@example.com\nSubject: hi\n\nbody")
        self.assertIn("no_auth", codes(r))

    def test_display_name_with_other_email(self):
        raw = b'From: "support@paypal.com" <x@evil.ru>\nAuthentication-Results: m; spf=pass dkim=pass dmarc=pass\n\n'
        self.assertIn("display_email", codes(analyze(raw)))

    def test_subdomain_trick(self):
        self.assertIn("subdomain_trick", {f.code for f in check_lookalike("paypal.com.evil.ru", DEFAULT_BRANDS)})

    def test_brand_match_requires_domain_label_boundaries(self):
        for domain in ("pineapple.com", "groups.com"):
            with self.subTest(domain=domain):
                self.assertEqual(check_lookalike(domain, DEFAULT_BRANDS), [])
        self.assertIn(
            "subdomain_trick",
            {finding.code for finding in check_lookalike("paypal.com.evil.ru", DEFAULT_BRANDS)},
        )

    def test_short_brand_names_do_not_trigger_typo_or_keyword_findings(self):
        for domain in ("ubs.com", "us-store.com"):
            with self.subTest(domain=domain):
                self.assertEqual(check_lookalike(domain, DEFAULT_BRANDS), [])

    def test_display_brand_requires_a_whole_word_and_ignores_office(self):
        for display_name in ("Startups Weekly", "Home Office Team"):
            raw = (
                f'From: "{display_name}" <news@example.net>\n'
                "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
            ).encode()
            with self.subTest(display_name=display_name):
                self.assertNotIn("display_brand", codes(analyze(raw)))

        flagged = analyze(
            b'From: "PayPal Support" <news@example.net>\n'
            b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
        )
        self.assertIn("display_brand", codes(flagged))
        self.assertNotIn("office.com", DEFAULT_BRANDS)

    def test_phase_zero_legitimate_domain_and_display_names_score_zero(self):
        cases = [
            ("Newsletter", "pineapple.com"),
            ("Updates", "groups.com"),
            ("Support", "ubs.com"),
            ("Store", "us-store.com"),
            ("Startups Weekly", "example.net"),
            ("Home Office Team", "example.net"),
        ]
        for display_name, domain in cases:
            raw = (
                f"Received: from {domain} (HELO {domain} [8.8.8.8]) "
                f"by mx.{domain}; Fri, 20 Nov 2026 09:00:01 +0000\n"
                f"Authentication-Results: mx.{domain}; spf=pass; dkim=pass; dmarc=pass\n"
                f'From: "{display_name}" <news@{domain}>\n\n'
            ).encode()
            with self.subTest(display_name=display_name, domain=domain):
                report = analyze(raw)
                self.assertEqual(report.score, 0)
                self.assertEqual(report.findings, [])

    def test_homoglyph_variants_cover_digit_one_and_cl(self):
        self.assertIn(
            "homoglyph",
            {finding.code for finding in check_lookalike("paypa1.com", ("paypai.com",))},
        )
        self.assertIn(
            "homoglyph",
            {finding.code for finding in check_lookalike("clhl.com", ("dhl.com",))},
        )

    def test_typosquat_and_keyword(self):
        self.assertIn("typosquat", {f.code for f in check_lookalike("micosoft.com", DEFAULT_BRANDS)})
        self.assertIn("brand_keyword", {f.code for f in check_lookalike("paypal-secure.com", DEFAULT_BRANDS)})

    def test_findings_include_category(self):
        report = analyze((SAMPLES / "phishing.eml").read_bytes())
        self.assertTrue({"auth", "domain", "headers"}.issubset(
            {finding["category"] for finding in report.findings}
        ))

    def test_received_routing_samples(self):
        samples = {
            "received_missing.eml": "received_missing",
            "received_private_ip.eml": "received_private_ip",
            "received_backwards_time.eml": "received_time_reversed",
            "received_long_delay.eml": "received_delay",
            "received_helo_mismatch.eml": "received_helo_mismatch",
            "received_long_chain.eml": "received_long_chain",
        }
        for filename, expected_code in samples.items():
            with self.subTest(filename=filename):
                report = analyze((SAMPLES / filename).read_bytes())
                self.assertIn(expected_code, codes(report))

    def test_received_hops_are_ordered_from_origin_to_destination(self):
        report = analyze((SAMPLES / "received_chain.eml").read_bytes())
        self.assertEqual(len(report.hops), 2)
        self.assertEqual(report.hops[0]["from_name"], "github.com")
        self.assertEqual(report.hops[1]["from_name"], "relay.example.net")
        self.assertEqual(report.hops[1]["delay_seconds"], 300)
        self.assertNotIn("received_private_ip", codes(report))

    def test_link_rules_have_sample_coverage(self):
        samples = {
            "links_text_mismatch.eml": "link_text_mismatch",
            "links_ip_host.eml": "link_ip",
            "links_userinfo.eml": "link_userinfo",
            "links_unsafe_schemes.eml": "link_unsafe_scheme",
            "links_lookalike.eml": "link_lookalike",
            "links_shortener.eml": "link_shortener",
            "links_http.eml": "link_http",
            "links_idn.eml": "link_idn",
            "links_deep_subdomain.eml": "link_deep_subdomain",
            "links_tracking_pixel.eml": "tracking_pixel",
        }
        for filename, expected_code in samples.items():
            with self.subTest(filename=filename):
                report = analyze((SAMPLES / filename).read_bytes())
                self.assertIn(expected_code, codes(report))

    def test_urls_are_defanged_and_include_plain_language_reasons(self):
        report = analyze((SAMPLES / "links_text_mismatch.eml").read_bytes())
        flagged = next(link for link in report.urls if link["domain"] == "evil.example")
        self.assertTrue(flagged["flagged"])
        self.assertTrue(any("paypal.com" in reason for reason in flagged["reasons"]))
        self.assertFalse(any("https://" in link["defanged"] for link in report.urls))

    def test_only_one_by_one_images_are_reported_as_tracking_pixels(self):
        raw = (
            b"From: Sender <person@example.net>\n"
            b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
            b"Content-Type: text/html; charset=utf-8\n\n"
            b'<img src="https://images.example.net/logo.png" width="1" height="80">'
        )
        self.assertNotIn("tracking_pixel", codes(analyze(raw)))

    def test_link_category_is_capped_and_newsletter_stays_low_risk(self):
        noisy = analyze((SAMPLES / "links_many_flags.eml").read_bytes())
        link_points = sum(
            finding["points"] for finding in noisy.findings if finding["category"] == "links"
        )
        self.assertLessEqual(link_points, 40)

        newsletter = analyze((SAMPLES / "legitimate_newsletter_links.eml").read_bytes())
        self.assertLess(newsletter.score, 20)
        self.assertTrue(any(not link["flagged"] for link in newsletter.urls))

    def test_attachment_urls_are_ignored_and_unique_url_limit_is_enforced(self):
        attached = analyze((SAMPLES / "links_attachment.eml").read_bytes())
        self.assertNotIn("evil.example.net", {link["domain"] for link in attached.urls})

        body = " ".join(f"https://host{index}.test/path" for index in range(205))
        report = analyze(
            (
                "From: Sender <person@example.net>\n"
                "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n"
                f"{body}"
            ).encode()
        )
        self.assertEqual(len(report.urls), 200)

    def test_messages_over_25_megabytes_are_rejected(self):
        with self.assertRaises(ValueError):
            analyze(b"From: person@example.net\n\n" + b"x" * (25 * 1024 * 1024 + 1))

    def test_dns_queries_and_pure_record_parsers(self):
        queries = needed_dns_queries((SAMPLES / "dns_dkim_missing.eml").read_bytes())
        self.assertEqual(
            queries,
            [
                ("example.net", "TXT"),
                ("_dmarc.example.net", "TXT"),
                ("selector1._domainkey.example.net", "TXT"),
            ],
        )
        self.assertEqual(parse_spf(["v=spf1 include:mail.example.net ~all"])["all_qualifier"], "~")
        self.assertEqual(parse_spf(["v=spf1 -all"])["all_qualifier"], "-")
        self.assertEqual(parse_dmarc(["v=DMARC1; p=none"])["policy"], "none")
        self.assertTrue(parse_dkim_key(["v=DKIM1; p="])["revoked"])

    def test_dns_findings_for_missing_records_and_policies(self):
        baseline = (SAMPLES / "dns_baseline.eml").read_bytes()
        missing = analyze(
            baseline,
            dns_records={"TXT:example.net": [], "TXT:_dmarc.example.net": []},
            dns_status={"example.net": "NOERROR", "_dmarc.example.net": "NOERROR"},
        )
        self.assertIn("dns_spf_missing", codes(missing))
        self.assertIn("dns_dmarc_missing", codes(missing))

        permissive = analyze(
            (SAMPLES / "dns_spf_permissive.eml").read_bytes(),
            dns_records={
                "TXT:example.net": ["v=spf1 +all"],
                "TXT:_dmarc.example.net": ["v=DMARC1; p=reject"],
            },
            dns_status={"example.net": "NOERROR", "_dmarc.example.net": "NOERROR"},
        )
        self.assertIn("dns_spf_permissive", codes(permissive))

        weak = analyze(
            (SAMPLES / "dns_spf_weak.eml").read_bytes(),
            dns_records={
                "TXT:example.net": ["v=spf1 ?all"],
                "TXT:_dmarc.example.net": ["v=DMARC1; p=reject"],
            },
            dns_status={"example.net": "NOERROR", "_dmarc.example.net": "NOERROR"},
        )
        weak_finding = next(f for f in weak.findings if f["code"] == "dns_spf_weak_all")
        self.assertEqual(weak_finding["severity"], "info")
        self.assertEqual(weak_finding["points"], 0)

        dmarc_none = analyze(
            (SAMPLES / "dns_dmarc_none.eml").read_bytes(),
            dns_records={
                "TXT:example.net": ["v=spf1 -all"],
                "TXT:_dmarc.example.net": ["v=DMARC1; p=none"],
            },
            dns_status={"example.net": "NOERROR", "_dmarc.example.net": "NOERROR"},
        )
        self.assertIn("dns_dmarc_none", codes(dmarc_none))

    def test_dns_dkim_missing_revoked_nxdomain_and_unavailable(self):
        missing_key = analyze(
            (SAMPLES / "dns_dkim_missing.eml").read_bytes(),
            dns_records={
                "TXT:example.net": ["v=spf1 -all"],
                "TXT:_dmarc.example.net": ["v=DMARC1; p=reject"],
                "TXT:selector1._domainkey.example.net": [],
            },
            dns_status={
                "example.net": "NOERROR",
                "_dmarc.example.net": "NOERROR",
                "selector1._domainkey.example.net": "NOERROR",
            },
        )
        self.assertIn("dns_dkim_missing", codes(missing_key))

        revoked = analyze(
            (SAMPLES / "dns_dkim_revoked.eml").read_bytes(),
            dns_records={
                "TXT:example.net": ["v=spf1 -all"],
                "TXT:_dmarc.example.net": ["v=DMARC1; p=reject"],
                "TXT:selector1._domainkey.example.net": ["v=DKIM1; p="],
            },
            dns_status={
                "example.net": "NOERROR",
                "_dmarc.example.net": "NOERROR",
                "selector1._domainkey.example.net": "NOERROR",
            },
        )
        self.assertIn("dns_dkim_revoked", codes(revoked))

        nxdomain = analyze(
            (SAMPLES / "dns_nxdomain.eml").read_bytes(),
            dns_records={"TXT:nonexistent.invalid": None, "TXT:_dmarc.nonexistent.invalid": None},
            dns_status={"nonexistent.invalid": "NXDOMAIN", "_dmarc.nonexistent.invalid": "NXDOMAIN"},
        )
        self.assertIn("dns_sender_nxdomain", codes(nxdomain))
        self.assertNotIn("dns_spf_missing", codes(nxdomain))

        unavailable = analyze(
            (SAMPLES / "dns_unavailable.eml").read_bytes(),
            dns_records={"TXT:example.net": None, "TXT:_dmarc.example.net": None},
            dns_status={"example.net": "SERVFAIL", "_dmarc.example.net": "SERVFAIL"},
        )
        self.assertIn("dns_unavailable", codes(unavailable))
        self.assertFalse(any(f["code"] == "dns_spf_missing" for f in unavailable.findings))

    def test_dns_is_opt_in_and_findings_are_categorized(self):
        report = analyze((SAMPLES / "dns_baseline.eml").read_bytes())
        self.assertIsNone(report.dns)
        self.assertFalse(any(f["category"] == "dns" for f in report.findings))

        checked = analyze(
            (SAMPLES / "dns_baseline.eml").read_bytes(),
            dns_records={"TXT:example.net": [], "TXT:_dmarc.example.net": []},
            dns_status={"example.net": "NOERROR", "_dmarc.example.net": "NOERROR"},
        )
        self.assertTrue(all(f["category"] == "dns" for f in checked.findings if f["code"].startswith("dns_")))
        self.assertIsNotNone(checked.dns)

    def test_real_brand_domain_not_flagged(self):
        self.assertEqual(check_lookalike("mail.google.com", DEFAULT_BRANDS), [])

    def test_helpers(self):
        self.assertEqual(levenshtein("paypal", "paypa1"), 1)
        self.assertEqual(registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable("mail.usthb.dz"), "usthb.dz")


if __name__ == "__main__":
    unittest.main()
