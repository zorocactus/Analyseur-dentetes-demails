"""Pure DNS record parsers and analysis of caller-supplied TXT answers."""
from __future__ import annotations

import re
from email import policy
from email.parser import BytesParser
from typing import Iterable, Optional, Union

from .analyzer import Finding, domain_of

DNS_POINTS = {
    "dns_spf_missing": 10,
    "dns_spf_permissive": 20,
    "dns_dmarc_missing": 10,
    "dns_dmarc_none": 5,
    "dns_dkim_missing": 15,
    "dns_dkim_revoked": 15,
    "dns_sender_nxdomain": 25,
    "dns_unavailable": 0,
    "dns_spf_weak_all": 0,
}

_TAG_RE = re.compile(r"(?:^|;)\s*([a-z][a-z0-9_-]*)\s*=\s*([^;]*)", re.IGNORECASE)


def _normalize_txt(value: str) -> str:
    value = value.strip()
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', value)
    if chunks:
        return "".join(chunks)
    return value


def _records(values: Optional[Iterable[str]]) -> list[str]:
    return [_normalize_txt(value) for value in values or []]


def needed_dns_queries(raw: bytes) -> list[tuple[str, str]]:
    message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    sender_domain = domain_of(str(message.get("From", "")))
    if not sender_domain:
        return []

    queries: list[tuple[str, str]] = [
        (sender_domain, "TXT"),
        (f"_dmarc.{sender_domain}", "TXT"),
    ]
    for signature in message.get_all("DKIM-Signature", []):
        tags = {key.lower(): value.strip() for key, value in _TAG_RE.findall(str(signature))}
        selector = tags.get("s")
        domain = tags.get("d")
        if selector and domain:
            queries.append((f"{selector}._domainkey.{domain.lower()}", "TXT"))

    return list(dict.fromkeys(queries))


def parse_spf(records: Optional[Iterable[str]]) -> dict[str, Optional[str]]:
    for record in _records(records):
        if not re.match(r"(?i)^v=spf1(?:\s|$)", record):
            continue
        qualifier = None
        for token in record.split():
            match = re.fullmatch(r"([+?~-]?)all", token, re.IGNORECASE)
            if match:
                qualifier = match.group(1) or "+"
        return {"record": record, "all_qualifier": qualifier}
    return {"record": None, "all_qualifier": None}


def parse_dmarc(records: Optional[Iterable[str]]) -> dict[str, Optional[str]]:
    for record in _records(records):
        if not re.match(r"(?i)^v=dmarc1(?:\s*;|\s*$)", record):
            continue
        tags = {key.lower(): value.strip().lower() for key, value in _TAG_RE.findall(record)}
        return {"record": record, "policy": tags.get("p")}
    return {"record": None, "policy": None}


def parse_dkim_key(records: Optional[Iterable[str]]) -> dict[str, Union[Optional[str], bool]]:
    for record in _records(records):
        if not re.search(r"(?i)(?:^|;)\s*p\s*=", record):
            continue
        tags = {key.lower(): value.strip() for key, value in _TAG_RE.findall(record)}
        public_key = tags.get("p")
        return {
            "record": record,
            "public_key": public_key,
            "revoked": public_key is not None and not public_key,
        }
    return {"record": None, "public_key": None, "revoked": False}


def _finding(code: str, severity: str, message: str) -> Finding:
    return Finding(severity, code, message, DNS_POINTS[code], category="dns")


def analyze_dns_records(
    raw: bytes,
    sender_domain: str,
    dns_records: dict[str, Optional[list[str]]],
    dns_status: Optional[dict[str, str]] = None,
) -> tuple[dict, list[Finding]]:
    queries = needed_dns_queries(raw)
    if not queries:
        return {"available": False, "queries": [], "spf": None, "dmarc": None, "dkim": []}, []

    records = {
        f"{record_type.upper()}:{name.lower()}": values
        for key, values in dns_records.items()
        for record_type, name in [key.split(":", 1)]
    }
    statuses = {name.lower(): status.upper() for name, status in (dns_status or {}).items()}
    failed_queries: list[str] = []

    def values_for(name: str, record_type: str = "TXT") -> Optional[list[str]]:
        key = f"{record_type.upper()}:{name.lower()}"
        status = statuses.get(name.lower())
        if status == "NXDOMAIN":
            return []
        if status and status not in {"NOERROR", "NXDOMAIN"}:
            failed_queries.append(key)
            return None
        if key not in records or records[key] is None:
            failed_queries.append(key)
            return None
        return records[key]

    spf_name = sender_domain.lower()
    dmarc_name = f"_dmarc.{sender_domain.lower()}"
    spf_values = values_for(spf_name)
    dmarc_values = values_for(dmarc_name)
    spf = parse_spf(spf_values)
    dmarc = parse_dmarc(dmarc_values)
    findings: list[Finding] = []
    sender_nxdomain = statuses.get(spf_name) == "NXDOMAIN"

    if sender_nxdomain:
        findings.append(
            _finding(
                "dns_sender_nxdomain",
                "high",
                f"Le domaine de l'expéditeur « {sender_domain} » n'existe pas (réponse NXDOMAIN).",
            )
        )
    elif spf_values is not None:
        if spf["record"] is None:
            findings.append(
                _finding("dns_spf_missing", "medium", f"Aucun enregistrement SPF TXT n'a été trouvé pour « {sender_domain} ».")  # noqa: E501
            )
        elif spf["all_qualifier"] == "+":
            findings.append(
                _finding("dns_spf_permissive", "high", f"Le SPF de « {sender_domain} » se termine par +all et autorise tous les expéditeurs.")
            )
        elif spf["all_qualifier"] in {"~", "?"}:
            findings.append(
                _finding("dns_spf_weak_all", "info", f"Le SPF de « {sender_domain} » utilise {spf['all_qualifier']}all ; cet indice seul n'augmente pas le score.")
            )

    if dmarc_values is not None and not sender_nxdomain:
        if dmarc["record"] is None:
            findings.append(
                _finding("dns_dmarc_missing", "medium", f"Aucun enregistrement DMARC TXT n'a été trouvé pour « {sender_domain} ».")
            )
        elif dmarc["policy"] == "none":
            findings.append(
                _finding("dns_dmarc_none", "low", f"La politique DMARC de « {sender_domain} » est p=none (surveillance sans action).")
            )

    dkim_results: list[dict] = []
    for name, record_type in queries:
        if "._domainkey." not in name:
            continue
        key_values = values_for(name, record_type)
        parsed_key = parse_dkim_key(key_values)
        result = {
            "name": name,
            "record": parsed_key["record"],
            "revoked": parsed_key["revoked"],
            "available": key_values is not None,
        }
        dkim_results.append(result)
        if key_values is None:
            continue
        if parsed_key["record"] is None:
            findings.append(
                _finding("dns_dkim_missing", "medium", f"Aucun enregistrement DKIM n'a été trouvé pour le sélecteur « {name} ».")
            )
        elif parsed_key["revoked"]:
            findings.append(
                _finding("dns_dkim_revoked", "high", f"La clé DKIM du sélecteur « {name} » est révoquée (p= vide).")
            )

    if failed_queries:
        findings.append(
            _finding("dns_unavailable", "info", "Vérification DNS indisponible pour une ou plusieurs requêtes.")
        )

    query_results = []
    for name, record_type in queries:
        status = statuses.get(name.lower())
        key = f"{record_type.upper()}:{name.lower()}"
        if not status:
            status = "UNAVAILABLE" if records.get(key) is None else "NOERROR"
        query_results.append({"name": name, "type": record_type, "status": status})

    return (
        {
            "available": not failed_queries,
            "sender_domain": sender_domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim_results,
            "queries": query_results,
        },
        findings,
    )
