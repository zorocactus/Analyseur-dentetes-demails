"""Extract and score email body URLs without following or resolving them."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.parse import urlsplit

from .analyzer import Finding, check_lookalike, registrable

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_URLS = 200
MAX_URL_LENGTH = 2048

_URL_RE = re.compile(
    r"""(?i)(?:https?://|hxxps?://|www\.|javascript:|data:)[^\s<>"'`]{1,2048}"""
)
_DISPLAY_DOMAIN_RE = re.compile(
    r"(?i)(?<![\w.-])(?:https?://)?(?:www\.)?"
    r"([a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,63})(?![\w.-])"
)
_SHORTENERS = {
    "bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "t.co",
    "short.gy", "tiny.cc", "tinyurl.com",
}
_LINK_POINTS = {
    "link_text_mismatch": 30,
    "link_ip": 20,
    "link_userinfo": 25,
    "link_unsafe_scheme": 30,
    "link_shortener": 8,
    "link_http": 3,
    "link_idn": 20,
    "link_deep_subdomain": 5,
    "tracking_pixel": 0,
}


@dataclass
class _Candidate:
    value: str
    anchor_text: str = ""
    tracking_pixel: bool = False


class _HTMLLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.candidates: list[_Candidate] = []
        self.text: list[str] = []
        self._anchor_href: Optional[str] = None
        self._anchor_text: list[str] = []
        self._candidate_values: dict[str, _Candidate] = {}

    def _add_candidate(self, candidate: _Candidate) -> None:
        value = _trim_url(candidate.value)
        if not value or len(value) > MAX_URL_LENGTH or not _is_supported_url(value):
            return
        key = value.casefold()
        existing = self._candidate_values.get(key)
        if existing:
            if candidate.anchor_text and not existing.anchor_text:
                existing.anchor_text = candidate.anchor_text
            existing.tracking_pixel = existing.tracking_pixel or candidate.tracking_pixel
            return
        if len(self._candidate_values) >= MAX_URLS:
            return
        candidate.value = value
        self._candidate_values[key] = candidate
        self.candidates.append(candidate)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "a" and attributes.get("href"):
            self._anchor_href = attributes["href"]
            self._anchor_text = []
        elif tag.lower() == "img" and attributes.get("src"):
            width = attributes.get("width", "").strip().lower()
            height = attributes.get("height", "").strip().lower()
            style = attributes.get("style", "")
            pixel_width = bool(re.search(r"\bwidth\s*:\s*1px\b", style, re.IGNORECASE))
            pixel_height = bool(re.search(r"\bheight\s*:\s*1px\b", style, re.IGNORECASE))
            one_pixel = (
                width in {"1", "1px"} and height in {"1", "1px"}
            ) or (pixel_width and pixel_height)
            self._add_candidate(_Candidate(attributes["src"], tracking_pixel=one_pixel))
        elif tag.lower() == "form" and attributes.get("action"):
            self._add_candidate(_Candidate(attributes["action"]))

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._anchor_href is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._anchor_href is not None:
            self._add_candidate(
                _Candidate(self._anchor_href, " ".join(self._anchor_text))
            )
            self._anchor_href = None
            self._anchor_text = []

    def close(self) -> None:
        super().close()
        if self._anchor_href is not None:
            self._add_candidate(
                _Candidate(self._anchor_href, " ".join(self._anchor_text))
            )
            self._anchor_href = None


def _decode_text_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        text = part.get_payload()
        return text if isinstance(text, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _normalize_scheme(value: str) -> str:
    return re.sub(r"(?i)^hxxps(?=://)", "https", re.sub(r"(?i)^hxxp(?=://)", "http", value))


def _trim_url(value: str) -> str:
    return value.strip().rstrip(".,;:!?)]}")


def _is_supported_url(value: str) -> bool:
    normalized = _normalize_scheme(value)
    try:
        scheme = urlsplit(normalized).scheme.lower()
    except ValueError:
        return False
    return scheme in {"http", "https", "javascript", "data"} or value.lower().startswith("www.")


def _extract_candidates(message: Message) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    by_value: dict[str, _Candidate] = {}

    def add(candidate: _Candidate) -> None:
        value = _trim_url(candidate.value)
        if not value or len(value) > MAX_URL_LENGTH or not _is_supported_url(value):
            return
        key = value.casefold()
        existing = by_value.get(key)
        if existing:
            if candidate.anchor_text and not existing.anchor_text:
                existing.anchor_text = candidate.anchor_text[:MAX_URL_LENGTH]
            existing.tracking_pixel = existing.tracking_pixel or candidate.tracking_pixel
            return
        if len(candidates) >= MAX_URLS:
            return
        candidate.value = value
        candidate.anchor_text = candidate.anchor_text[:MAX_URL_LENGTH]
        by_value[key] = candidate
        candidates.append(candidate)

    for part in message.walk():
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue

        text = _decode_text_part(part)
        if part.get_content_type() == "text/html":
            parser = _HTMLLinkParser()
            parser.feed(text)
            parser.close()
            for candidate in parser.candidates:
                add(candidate)
            text = " ".join(parser.text)
        for match in _URL_RE.finditer(text):
            add(_Candidate(match.group(0)))

    return candidates


def _host_for(value: str) -> tuple[str, str, object]:
    normalized = _normalize_scheme(value)
    if normalized.lower().startswith("www."):
        normalized = "https://" + normalized
    try:
        parsed = urlsplit(normalized)
        return parsed.scheme.lower(), parsed.hostname or "", parsed
    except ValueError:
        return "", "", urlsplit("")


def _defang(value: str) -> str:
    value = re.sub(r"(?i)^https://", "hxxps://", value)
    value = re.sub(r"(?i)^http://", "hxxp://", value)
    return value.replace(".", "[.]")


def _display_domain_mismatch(anchor_text: str, target_host: str) -> Optional[str]:
    for match in _DISPLAY_DOMAIN_RE.finditer(anchor_text):
        shown_host = match.group(1).lower()
        if registrable(shown_host) != registrable(target_host):
            return shown_host
    return None


def _classify(
    candidate: _Candidate,
    brands: Iterable[str],
) -> tuple[str, list[tuple[str, str, int, str]]]:
    scheme, host, parsed = _host_for(candidate.value)
    key = host.lower() or candidate.value.casefold()
    findings: list[tuple[str, str, int, str]] = []

    def add(code: str, severity: str, message: str, points: Optional[int] = None) -> None:
        findings.append((code, severity, _LINK_POINTS[code] if points is None else points, message))

    if scheme in {"javascript", "data"}:
        add(
            "link_unsafe_scheme",
            "high",
            f"Le lien utilise le schéma « {scheme}: », qui peut exécuter ou intégrer du contenu actif.",
        )
    if getattr(parsed, "username", None) is not None or getattr(parsed, "password", None) is not None:
        add(
            "link_userinfo",
            "high",
            f"Le lien contient des identifiants avant « @ » : l'hôte réel est « {host or 'inconnu'} ».",
        )
    if host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            add("link_ip", "high", f"Le lien utilise une adresse IP brute (« {host} ») au lieu d'un nom de domaine.")

        for finding in check_lookalike(host, brands):
            if finding.code in {"subdomain_trick", "homoglyph", "typosquat", "brand_keyword"}:
                add("link_lookalike", finding.severity, f"Le domaine du lien est trompeur : {finding.message}", finding.points)
                break

        if any(host == shortener or host.endswith("." + shortener) for shortener in _SHORTENERS):
            add("link_shortener", "low", f"Le lien utilise un raccourcisseur connu (« {host} »).")
        if scheme == "http":
            add("link_http", "low", "Le lien utilise HTTP sans chiffrement HTTPS.")
        if host.lower().startswith("xn--") or ".xn--" in host.lower() or not host.isascii():
            add("link_idn", "medium", f"Le domaine du lien contient du punycode ou des caractères internationaux (« {host} »).")
        if len(host) > 100 or len(host.split(".")) > 5:
            add("link_deep_subdomain", "low", f"Le domaine du lien est très long ou comporte de nombreux sous-domaines (« {host} »).")
        if candidate.anchor_text:
            shown_domain = _display_domain_mismatch(candidate.anchor_text, host)
            if shown_domain:
                add(
                    "link_text_mismatch",
                    "high",
                    f"Le texte visible annonce « {shown_domain} », mais la destination réelle est « {host} ».",
                )
    if candidate.tracking_pixel:
        findings.append(
            (
                "tracking_pixel",
                "info",
                0,
                "Une image de suivi de 1 × 1 pixel est présente ; cet indice seul n'augmente pas le score.",
            )
        )
    return key, findings


def analyze_links(
    message: Message,
    brands: Iterable[str],
) -> tuple[list[dict], list[Finding]]:
    urls: dict[str, dict] = {}
    findings: list[Finding] = []
    seen_findings: set[tuple[str, str]] = set()
    remaining_points = 40

    for candidate in _extract_candidates(message):
        key, candidate_findings = _classify(candidate, brands)
        record = urls.setdefault(
            key,
            {
                "defanged": _defang(candidate.value),
                "domain": _host_for(candidate.value)[1],
                "flagged": False,
                "reasons": [],
            },
        )
        for code, severity, requested_points, message_text in candidate_findings:
            record["flagged"] = record["flagged"] or requested_points > 0
            if message_text not in record["reasons"]:
                record["reasons"].append(message_text)
            finding_key = (key, code)
            if finding_key in seen_findings:
                continue
            seen_findings.add(finding_key)
            points = min(requested_points, remaining_points) if requested_points else 0
            remaining_points -= points
            findings.append(
                Finding(severity, code, message_text, points, category="links")
            )

    return list(urls.values()), findings
