"""Parse and assess the Received chain without performing network I/O."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable, Optional

from .analyzer import Finding, registrable

_FROM_RE = re.compile(r"\bfrom\s+([^\s();]+)", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s();]+)", re.IGNORECASE)
_HELO_RE = re.compile(r"\bHELO\s+([^\s)\]]+)", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

ROUTING_POINTS = {
    "received_missing": 5,
    "received_private_ip": 20,
    "received_time_reversed": 10,
    "received_delay": 10,
    "received_helo_mismatch": 5,
    "received_long_chain": 5,
}


def _parse_timestamp(value: str) -> Optional[datetime]:
    if ";" not in value:
        return None
    try:
        timestamp = parsedate_to_datetime(value.rsplit(";", 1)[1].strip())
    except (TypeError, ValueError, OverflowError):
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _extract_ips(value: str) -> list[str]:
    candidates = re.findall(r"\[([^\]]+)\]", value)
    candidates.extend(_IPV4_RE.findall(value))
    addresses: list[str] = []
    for candidate in candidates:
        candidate = re.sub(r"(?i)^ipv6:", "", candidate.strip())
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def _parse_hop(value: str) -> tuple[dict, Optional[datetime]]:
    from_match = _FROM_RE.search(value)
    by_match = _BY_RE.search(value)
    helo_match = _HELO_RE.search(value)
    from_name = from_match.group(1).strip("[]") if from_match else ""
    timestamp = _parse_timestamp(value)
    return (
        {
            "from_name": from_name,
            "by_name": by_match.group(1).strip("[]") if by_match else "",
            "helo_name": helo_match.group(1).strip("[]") if helo_match else from_name,
            "ips": _extract_ips(value),
            "timestamp": timestamp.isoformat() if timestamp else None,
            "delay_seconds": None,
        },
        timestamp,
    )


def _finding(code: str, severity: str, message: str) -> Finding:
    return Finding(severity, code, message, ROUTING_POINTS[code], category="routing")


def analyze_received(
    received_values: Iterable[str],
    sender_domain: str,
) -> tuple[list[dict], list[Finding]]:
    raw_values = list(received_values)
    if not raw_values:
        return [], [
            _finding(
                "received_missing",
                "low",
                "Aucun en-tête Received n'est présent : le parcours du message ne peut pas être vérifié.",
            )
        ]

    parsed = [_parse_hop(value) for value in reversed(raw_values)]
    hops = [hop for hop, _ in parsed]
    timestamps = [timestamp for _, timestamp in parsed]
    findings: list[Finding] = []

    for index in range(1, len(hops)):
        previous, current = timestamps[index - 1], timestamps[index]
        if previous is None or current is None:
            continue
        delay = int((current - previous).total_seconds())
        hops[index]["delay_seconds"] = delay
        if delay < -300:
            findings.append(
                _finding(
                    "received_time_reversed",
                    "medium",
                    f"Les dates Received reculent de plus de 5 minutes entre deux sauts ({abs(delay) // 60} min).",
                )
            )
        elif delay > 24 * 60 * 60:
            findings.append(
                _finding(
                    "received_delay",
                    "medium",
                    f"Plus de 24 heures séparent deux sauts Received ({delay // 3600} h).",
                )
            )

    first_external_hop = next((hop for hop in hops if hop["ips"]), None)
    if first_external_hop:
        for value in first_external_hop["ips"]:
            address = ipaddress.ip_address(value)
            if (
                address.is_private
                or address.is_reserved
                or address.is_loopback
                or address.is_link_local
                or address.is_unspecified
                or address.is_multicast
            ):
                findings.append(
                    _finding(
                        "received_private_ip",
                        "high",
                        f"Le premier saut avec une adresse IP utilise une adresse privée ou réservée ({address}).",
                    )
                )
                break

        helo_name = first_external_hop["helo_name"]
        if (
            sender_domain
            and helo_name
            and registrable(helo_name) != registrable(sender_domain)
        ):
            findings.append(
                _finding(
                    "received_helo_mismatch",
                    "low",
                    f"Le premier HELO (« {helo_name} ») diffère du domaine de l'expéditeur (« {sender_domain} »).",
                )
            )

    if len(hops) > 10:
        findings.append(
            _finding(
                "received_long_chain",
                "low",
                f"La chaîne contient {len(hops)} sauts Received, soit plus de 10.",
            )
        )

    return hops, findings
