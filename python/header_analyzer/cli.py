"""Interface en ligne de commande : python -m header_analyzer mail.eml"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .analyzer import DEFAULT_BRANDS, analyze

COLORS = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


def _paint(text: str, key: str, enabled: bool) -> str:
    return f"{COLORS.get(key, '')}{text}{RESET}" if enabled else text


def render(path: str, report: dict, color: bool) -> str:
    lines = [f"=== {path} ===",
             f"De         : {report['display_name']} <{report['sender']}>",
             f"Reply-To   : {report['reply_to'] or '-'}",
             f"Return-Path: {report['return_path'] or '-'}",
             f"Sujet      : {report['subject']}",
             "Auth       : " + "  ".join(f"{k.upper()}={report['auth'].get(k) or 'n/a'}" for k in ("spf", "dkim", "dmarc")),
             ""]
    if report["findings"]:
        for f in report["findings"]:
            tag = _paint(f"[{f['severity'].upper():6}]", f["severity"], color)
            lines.append(f"{tag} {f['message']}")
    else:
        lines.append("Aucune anomalie trouvée.")
    if report.get("hops"):
        lines += ["", "Parcours du mail :"]
        for hop in report["hops"]:
            ip_text = ", ".join(hop["ips"]) or "IP non fournie"
            timestamp = hop["timestamp"] or "heure inconnue"
            delay = (
                f" ; délai {hop['delay_seconds']} s"
                if hop["delay_seconds"] is not None
                else ""
            )
            lines.append(
                f"- {timestamp} : {hop['from_name'] or '?'} -> {hop['by_name'] or '?'} "
                f"({ip_text}){delay}"
            )
            for address, location in hop.get("geoip", {}).items():
                place = ", ".join(filter(None, (location.get("city"), location.get("country"))))
                if place:
                    lines.append(f"  {address} : {place}")
    if report.get("urls"):
        lines += ["", "Liens trouvés :"]
        for url in report["urls"]:
            label = "à examiner" if url["flagged"] else "aucun indice de lien"
            lines.append(f"- {url['defanged']} ({label})")
            lines.extend(f"  {reason}" for reason in url["reasons"])
    if report.get("dns"):
        lines += ["", "Vérification DNS :"]
        lines.append(
            "  " + ("disponible" if report["dns"]["available"] else "partiellement indisponible")
        )
        for query in report["dns"]["queries"]:
            lines.append(f"- TXT {query['name']} : {query['status']}")
    level = "high" if report["score"] >= 45 else "medium" if report["score"] >= 20 else "info"
    lines += ["", _paint(f"Score : {report['score']}/100 — {report['verdict']}", level, color)]
    return "\n".join(lines)


def _query_dns(
    raw: bytes,
) -> tuple[dict[str, Optional[list[str]]], dict[str, str]]:
    try:
        import dns.exception
        import dns.resolver
    except ImportError as exc:
        raise RuntimeError("Installe l'extra DNS avec « pip install email-header-analyzer[dns] ».") from exc

    from .dns_checks import needed_dns_queries

    resolver = dns.resolver.Resolver()
    records: dict[str, list[str] | None] = {}
    statuses: dict[str, str] = {}
    for name, record_type in needed_dns_queries(raw):
        key = f"{record_type}:{name}"
        try:
            answer = resolver.resolve(
                name,
                record_type,
                lifetime=5,
                raise_on_no_answer=False,
            )
        except dns.resolver.NXDOMAIN:
            records[key] = []
            statuses[name] = "NXDOMAIN"
        except dns.exception.DNSException:
            records[key] = None
            statuses[name] = "SERVFAIL"
        else:
            statuses[name] = "NOERROR"
            rrset = getattr(answer, "rrset", None)
            if rrset is None:
                records[key] = []
            else:
                values = []
                for item in rrset:
                    chunks = getattr(item, "strings", None)
                    if chunks:
                        values.append(
                            b"".join(chunks).decode("utf-8", errors="replace")
                        )
                    else:
                        values.append(str(item).strip('"'))
                records[key] = values
    return records, statuses


def _apply_geoip(report: dict, database_path: str) -> None:
    try:
        import geoip2.database
        import geoip2.errors
        import maxminddb.errors
    except ImportError as exc:
        raise RuntimeError(
            "Installe l'extra GeoIP avec « pip install email-header-analyzer[geoip] »."
        ) from exc

    try:
        reader = geoip2.database.Reader(database_path)
    except (OSError, ValueError, maxminddb.errors.InvalidDatabaseError) as exc:
        raise RuntimeError(f"Impossible d'ouvrir la base GeoIP locale : {exc}") from exc

    try:
        for hop in report["hops"]:
            locations = {}
            for address in hop["ips"]:
                try:
                    result = reader.city(address)
                except geoip2.errors.AddressNotFoundError:
                    continue
                city = result.city.name
                country = result.country.name
                locations[address] = {"city": city, "country": country}
            if locations:
                hop["geoip"] = locations
    finally:
        reader.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="header_analyzer", description="Détecte les signes de phishing dans les en-têtes d'un email (.eml).")
    p.add_argument("files", nargs="+", help="fichier(s) .eml à analyser")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    p.add_argument("--brand", action="append", default=[], metavar="DOMAINE",
                   help="domaine de marque supplémentaire à protéger (répétable), ex. --brand usthb.dz")
    p.add_argument("--no-color", action="store_true", help="désactive les couleurs")
    p.add_argument("--dns", action="store_true", help="vérifie les enregistrements TXT (extra dnspython requis)")
    p.add_argument("--geoip", metavar="PATH", help="géolocalise les IP via une base GeoLite2 locale (extra geoip requis)")
    args = p.parse_args(argv)

    brands = list(DEFAULT_BRANDS) + args.brand
    color = sys.stdout.isatty() and not args.no_color and not args.json
    worst = 0
    results = {}
    for name in args.files:
        try:
            raw = Path(name).read_bytes()
        except OSError as exc:
            print(f"Erreur : {exc}", file=sys.stderr)
            return 3
        try:
            dns_records, dns_status = _query_dns(raw) if args.dns else (None, None)
            report = analyze(
                raw,
                brands,
                dns_records=dns_records,
                dns_status=dns_status,
            ).to_dict()
            if args.geoip:
                _apply_geoip(report, args.geoip)
        except RuntimeError as exc:
            print(f"Erreur : {exc}", file=sys.stderr)
            return 3
        results[name] = report
        worst = max(worst, 2 if report["score"] >= 45 else 1 if report["score"] >= 20 else 0)
        if not args.json:
            print(render(name, report, color), end="\n\n")
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    return worst  # 0 = ok, 1 = suspect, 2 = phishing probable


if __name__ == "__main__":
    sys.exit(main())
