"""Analyse des en-têtes d'un email (.eml) pour repérer des signes de phishing.

Aucune dépendance externe : uniquement la bibliothèque standard.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from email.header import decode_header, make_header
from email.message import Message
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Iterable, Literal, Optional

# Marques souvent usurpées (domaine officiel). Extensible via --brand.
DEFAULT_BRANDS = (
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "instagram.com", "netflix.com", "linkedin.com",
    "github.com", "dhl.com", "ups.com", "fedex.com", "dropbox.com",
    "docusign.com", "outlook.com", "whatsapp.com", "binance.com",
)

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me",
    "protonmail.com", "gmx.com", "mail.com", "yandex.com", "aol.com",
}

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}

# Caractères qui ressemblent à d'autres (chiffres et alphabet cyrillique).
CONFUSABLES = {
    "0": "o", "3": "e", "5": "s", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s",
}
MULTI_CHAR = (("rn", "m"), ("vv", "w"), ("cl", "d"))

URGENCY = re.compile(
    r"urgent|immediately|verify your|suspended|action required|confirm your"
    r"|vérifi|suspendu|immédiat|dernier avertissement|compte (bloqu|limit)",
    re.I,
)
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)

POINTS = {
    "spf_fail": 20, "spf_softfail": 10, "dkim_fail": 15, "dmarc_fail": 25,
    "no_auth": 8, "alignment": 10, "reply_to": 15, "return_path": 5,
    "homoglyph": 35, "subdomain_trick": 35, "typosquat": 25, "brand_keyword": 20,
    "idn": 30, "display_email": 25, "display_brand": 20, "urgency": 5,
    "message_id": 5, "received_missing": 5, "received_private_ip": 20,
    "received_time_reversed": 10, "received_delay": 10, "received_helo_mismatch": 5,
    "received_long_chain": 5,
}

FindingCategory = Literal["auth", "domain", "headers", "routing", "links", "dns"]


@dataclass
class Finding:
    severity: str  # info | low | medium | high
    code: str
    message: str
    points: int = 0
    category: FindingCategory = "headers"


@dataclass
class Report:
    display_name: str = ""
    sender: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    auth: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    hops: list[dict] = field(default_factory=list)
    urls: list[dict] = field(default_factory=list)
    dns: Optional[dict] = None
    score: int = 0
    verdict: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Utilitaires
# --------------------------------------------------------------------------- #
def _decode(value) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def domain_of(address: str) -> str:
    return address.rpartition("@")[2].strip(" <>\t\r\n.").lower()


def registrable(domain: str) -> str:
    """Domaine « racine » (heuristique simple, sans Public Suffix List)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalized_variants(label: str) -> set[str]:
    """Versions « dé-obfusquées » d'un label (paypa1 -> paypal / paypai)."""
    base = "".join(CONFUSABLES.get(c, c) for c in label)
    for src, dst in MULTI_CHAR:
        base = base.replace(src, dst)
    variants = {base}
    if "1" in base:
        variants |= {base.replace("1", "l"), base.replace("1", "i")}
    return variants


# --------------------------------------------------------------------------- #
# Contrôles
# --------------------------------------------------------------------------- #
def parse_auth_results(msg: Message) -> dict:
    """Extrait SPF / DKIM / DMARC depuis Authentication-Results (ou Received-SPF)."""
    found: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
    details: dict[str, str] = {}
    for raw in msg.get_all("Authentication-Results", []):
        text = str(raw)
        for mech, res in AUTH_RE.findall(text):
            found[mech.lower()].append(res.lower())
        if m := re.search(r"header\.d=([^\s;]+)", text, re.I):
            details.setdefault("dkim_domain", m.group(1).lower())
        if m := re.search(r"smtp\.mailfrom=([^\s;]+)", text, re.I):
            details.setdefault("spf_domain", domain_of(m.group(1)))
    if not found["spf"] and msg.get("Received-SPF"):
        found["spf"].append(str(msg["Received-SPF"]).split()[0].lower())

    result = {
        "spf": found["spf"][0] if found["spf"] else None,
        # plusieurs signatures DKIM possibles : une seule valide suffit
        "dkim": ("pass" if "pass" in found["dkim"] else found["dkim"][0]) if found["dkim"] else None,
        "dmarc": found["dmarc"][0] if found["dmarc"] else None,
    }
    result.update(details)
    return result


def check_authentication(auth: dict, from_domain: str) -> list[Finding]:
    out: list[Finding] = []
    if not any(auth.get(k) for k in ("spf", "dkim", "dmarc")):
        out.append(Finding("low", "no_auth",
                           "Aucun résultat SPF/DKIM/DMARC dans les en-têtes : impossible de vérifier l'expéditeur.",
                           POINTS["no_auth"], category="auth"))
        return out

    spf, dkim, dmarc = auth.get("spf"), auth.get("dkim"), auth.get("dmarc")
    if spf in ("fail", "permerror"):
        out.append(Finding("high", "spf_fail", f"SPF en échec ({spf}) : le serveur d'envoi n'est pas autorisé pour ce domaine.", POINTS["spf_fail"], category="auth"))
    elif spf == "softfail":
        out.append(Finding("medium", "spf_softfail", "SPF en softfail : serveur d'envoi probablement non autorisé.", POINTS["spf_softfail"], category="auth"))
    if dkim in ("fail", "permerror", "policy"):
        out.append(Finding("high", "dkim_fail", f"DKIM en échec ({dkim}) : la signature est invalide ou le message a été modifié.", POINTS["dkim_fail"], category="auth"))
    if dmarc in ("fail", "permerror"):
        out.append(Finding("high", "dmarc_fail", f"DMARC en échec ({dmarc}) : ni SPF ni DKIM ne sont alignés avec le domaine du From.", POINTS["dmarc_fail"], category="auth"))

    # Alignement (utile quand DMARC n'est pas là pour trancher)
    if dmarc != "pass" and from_domain:
        for mech, key in (("SPF", "spf_domain"), ("DKIM", "dkim_domain")):
            dom = auth.get(key)
            passed = auth.get("spf" if mech == "SPF" else "dkim") == "pass"
            if dom and passed and registrable(dom) != registrable(from_domain):
                out.append(Finding("medium", "alignment",
                                   f"{mech} valide mais pour « {dom} », différent du domaine affiché « {from_domain} » (non aligné).",
                                   POINTS["alignment"], category="auth"))
    return out


def check_lookalike(domain: str, brands: Iterable[str]) -> list[Finding]:
    if not domain:
        return []
    brands = [registrable(b) for b in brands]
    reg = registrable(domain)
    if reg in brands:
        return []  # vrai domaine d'une marque connue

    out: list[Finding] = []
    if domain.startswith("xn--") or ".xn--" in domain or any(ord(c) > 127 for c in domain):
        out.append(Finding("high", "idn", f"Domaine IDN/punycode « {domain} » : peut cacher des caractères trompeurs (homoglyphes).", POINTS["idn"], category="domain"))

    label = reg.split(".")[0]
    parts = {label, *label.split("-")}  # « paypa1-secure » -> paypa1, secure
    for brand in brands:
        b_label = brand.split(".")[0]
        if f".{brand}." in f".{domain}.":  # paypal.com.evil.ru
            out.append(Finding("high", "subdomain_trick",
                               f"« {brand} » apparaît dans le domaine mais le vrai domaine est « {reg} » (astuce du sous-domaine).",
                               POINTS["subdomain_trick"], category="domain"))
        elif any(p != b_label and b_label in _normalized_variants(p) for p in parts):
            out.append(Finding("high", "homoglyph",
                               f"« {reg} » imite « {brand} » avec des caractères qui se ressemblent (ex. 1/l, 0/o, rn/m).",
                               POINTS["homoglyph"], category="domain"))
        elif len(b_label) >= 5 and any(
                p != b_label and levenshtein(p, b_label) <= (1 if len(b_label) < 8 else 2) for p in parts):
            out.append(Finding("high", "typosquat",
                               f"« {reg} » est très proche de « {brand} » (faute de frappe volontaire possible).",
                               POINTS["typosquat"], category="domain"))
        elif len(b_label) >= 5 and b_label in label.split("-"):
            out.append(Finding("medium", "brand_keyword",
                               f"« {reg} » contient le nom de la marque « {b_label} » sans être son domaine officiel.",
                               POINTS["brand_keyword"], category="domain"))
        else:
            continue
        break  # une seule marque ciblée suffit
    return out


def check_headers(msg: Message, display_name: str, sender: str, brands: Iterable[str]) -> list[Finding]:
    out: list[Finding] = []
    from_dom = domain_of(sender)
    brands = list(brands)

    # Reply-To différent du From
    _, reply = parseaddr(_decode(msg.get("Reply-To")))
    if reply and registrable(domain_of(reply)) != registrable(from_dom):
        extra = " (webmail gratuit)" if domain_of(reply) in FREE_MAIL else ""
        out.append(Finding("medium", "reply_to",
                           f"Reply-To « {reply} »{extra} différent de l'expéditeur « {sender} » : les réponses partent ailleurs.",
                           POINTS["reply_to"]))

    # Return-Path (enveloppe) différent du From
    _, rpath = parseaddr(_decode(msg.get("Return-Path")))
    if rpath and registrable(domain_of(rpath)) != registrable(from_dom):
        out.append(Finding("low", "return_path",
                           f"Return-Path « {rpath} » différent du From (peut être légitime : service d'envoi de newsletters).",
                           POINTS["return_path"]))

    # Nom affiché trompeur
    if "@" in display_name:
        shown = re.search(r"[\w.+-]+@[\w.-]+", display_name)
        if shown and registrable(domain_of(shown.group())) != registrable(from_dom):
            out.append(Finding("high", "display_email",
                               f"Le nom affiché contient une adresse (« {shown.group()} ») différente de la vraie (« {sender} »).",
                               POINTS["display_email"]))
    else:
        for brand in brands:
            b_label = registrable(brand).split(".")[0]
            if (
                len(b_label) >= 4
                and re.search(rf"\b{re.escape(b_label)}\b", display_name, re.IGNORECASE)
                and registrable(from_dom) != registrable(brand)
            ):
                out.append(Finding("medium", "display_brand",
                                   f"Le nom affiché évoque « {b_label} » mais l'adresse vient de « {from_dom} ».",
                                   POINTS["display_brand"]))
                break

    # Message-ID incohérent
    mid = domain_of(str(msg.get("Message-ID", "")))
    if mid and from_dom and registrable(mid) != registrable(from_dom):
        out.append(Finding("low", "message_id",
                           f"Message-ID généré par « {mid} », pas par « {from_dom} ».", POINTS["message_id"]))

    # Ton d'urgence
    subject = _decode(msg.get("Subject"))
    if URGENCY.search(subject):
        out.append(Finding("low", "urgency", "Sujet au ton d'urgence / menace (technique classique d'ingénierie sociale).", POINTS["urgency"]))
    return out


# --------------------------------------------------------------------------- #
# Point d'entrée
# --------------------------------------------------------------------------- #
def verdict_for(score: int) -> str:
    if score < 20:
        return "Aucun signal fort détecté"
    if score < 45:
        return "Suspect"
    return "Très probablement du phishing"


def analyze(
    raw: bytes,
    brands: Optional[Iterable[str]] = None,
    *,
    dns_records: Optional[dict[str, Optional[list[str]]]] = None,
    dns_status: Optional[dict[str, str]] = None,
) -> Report:
    from .links import MAX_MESSAGE_BYTES, analyze_links

    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("Le fichier dépasse la limite d'analyse de 25 Mo.")
    brands = tuple(brands) if brands else DEFAULT_BRANDS
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    name, sender = parseaddr(_decode(msg.get("From")))
    from_dom = domain_of(sender)
    auth = parse_auth_results(msg)
    from .received import analyze_received
    hops, received_findings = analyze_received(msg.get_all("Received", []), from_dom)
    urls, link_findings = analyze_links(msg, brands)
    dns = None
    dns_findings: list[Finding] = []
    if dns_records is not None:
        from .dns_checks import analyze_dns_records
        dns, dns_findings = analyze_dns_records(raw, from_dom, dns_records, dns_status)

    findings: list[Finding] = []
    findings += check_authentication(auth, from_dom)
    findings += check_lookalike(from_dom, brands)
    findings += check_headers(msg, name, sender, brands)
    findings += received_findings
    findings += link_findings
    findings += dns_findings

    score = min(100, sum(f.points for f in findings))
    _, reply = parseaddr(_decode(msg.get("Reply-To")))
    _, rpath = parseaddr(_decode(msg.get("Return-Path")))
    return Report(
        display_name=name, sender=sender, reply_to=reply, return_path=rpath,
        subject=_decode(msg.get("Subject")), auth=auth,
        findings=[asdict(f) for f in findings], hops=hops, urls=urls, dns=dns,
        score=score, verdict=verdict_for(score),
    )
