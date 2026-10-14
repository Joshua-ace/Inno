"""
URL threat analysis engine.
Uses tldextract for Public Suffix List-aware domain parsing,
and applies weighted indicators to detect phishing patterns.
"""

import re
from urllib.parse import urlparse, unquote
from typing import Optional
import tldextract

from scoring.indicators import (
    URL_WEIGHTS, SUSPICIOUS_TLDS, URL_SHORTENERS, PHISHING_KEYWORDS,
    BRAND_NAMES,
)
from models import Indicator, Severity


def analyze_url(raw_url: str) -> dict:
    """
    Analyze a URL for phishing and threat indicators.

    Returns a dict with:
        score: int (0-100)
        indicators: list[Indicator]
        metadata: dict (parsed hostname, domain, etc.)
        error: Optional[str]
    """
    url = raw_url.strip()

    # Normalize: add scheme if missing
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "Could not parse this URL. Check the format and try again."}

    if not parsed.hostname:
        return {"error": "Could not extract a hostname from the URL."}

    hostname = parsed.hostname.lower()
    protocol = parsed.scheme
    pathname = parsed.path
    port = parsed.port
    full_url = parsed.geturl().lower()
    query = parsed.query

    # Use tldextract for accurate domain decomposition
    extracted = tldextract.extract(url)
    registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    subdomain = extracted.subdomain

    score = 0
    indicators: list[Indicator] = []
    seen_categories: set[str] = set()  # prevent duplicate scoring

    metadata = {
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": subdomain or None,
        "protocol": protocol,
        "port": port,
        "path": pathname,
        "tld": f".{extracted.suffix}" if extracted.suffix else None,
    }

    def add_indicator(category: str, severity: Severity, name: str, detail: str, points: int):
        nonlocal score
        if category in seen_categories:
            return
        seen_categories.add(category)
        capped_points = min(points, 100 - score)  # never exceed 100
        score += capped_points
        indicators.append(Indicator(
            severity=severity,
            name=name,
            detail=detail,
            points=capped_points,
            source="local",
        ))

    # ── Check 1: No HTTPS ──────────────────────────────
    if protocol == "http":
        add_indicator(
            "http",
            Severity.WARNING,
            "No Encryption (HTTP)",
            "The connection is unencrypted. Credentials or data submitted on "
            "this page can be intercepted by anyone on the same network.",
            URL_WEIGHTS["http_no_encryption"],
        )

    # ── Check 2: IP address as hostname ────────────────
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        add_indicator(
            "ip_host",
            Severity.CRITICAL,
            "Raw IP Address Used Instead of Domain",
            "Legitimate websites use registered domain names. Hosting on a raw "
            "IP address avoids domain-based reputation checks and is a documented "
            "phishing technique.",
            URL_WEIGHTS["ip_address_host"],
        )

    # ── Check 3: URL shortener ─────────────────────────
    if hostname in URL_SHORTENERS or any(hostname.endswith('.' + s) for s in URL_SHORTENERS):
        add_indicator(
            "shortener",
            Severity.WARNING,
            "URL Shortener Detected",
            "URL shorteners mask the actual destination. They are commonly used "
            "in phishing campaigns to bypass email and browser filters.",
            URL_WEIGHTS["url_shortener"],
        )

    # ── Check 4: Suspicious TLD ────────────────────────
    tld = f".{extracted.suffix}" if extracted.suffix else ""
    if tld in SUSPICIOUS_TLDS:
        add_indicator(
            "tld",
            Severity.WARNING,
            f"Suspicious Domain Extension: {tld}",
            f"\"{tld}\" is frequently used for malicious sites because it is "
            "free or cheap to register. Established businesses rarely use it.",
            URL_WEIGHTS["suspicious_tld"],
        )

    # ── Check 5: @ symbol injection ────────────────────
    if '@' in raw_url:
        add_indicator(
            "at_symbol",
            Severity.CRITICAL,
            "Credential Injection via @ Symbol",
            "Browsers ignore everything before @ in a URL, treating it as "
            "credentials. Attackers use this to make a URL appear to belong to "
            "a trusted site while routing to a malicious server.",
            URL_WEIGHTS["at_symbol_injection"],
        )

    # ── Check 6: Punycode / IDN ────────────────────────
    if hostname.startswith("xn--") or any(part.startswith("xn--") for part in hostname.split(".")):
        add_indicator(
            "punycode",
            Severity.WARNING,
            "Internationalized Domain Name (Punycode)",
            "This domain uses non-ASCII characters encoded as Punycode. "
            "Attackers use homograph attacks to create domains visually "
            "identical to trusted brands (e.g., using Cyrillic 'a' for Latin 'a').",
            URL_WEIGHTS["punycode_domain"],
        )

    # ── Check 7: Phishing keywords ─────────────────────
    found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]

    if len(found_keywords) >= 3:
        points = min(len(found_keywords) * URL_WEIGHTS["phishing_keywords_low"],
                     URL_WEIGHTS["phishing_keywords_high"] + 8)
        add_indicator(
            "phishing_keywords",
            Severity.CRITICAL,
            f"High-Density Phishing Keywords ({len(found_keywords)} found)",
            f"URL contains multiple terms used to impersonate legitimate services: "
            f"{', '.join(found_keywords[:5])}.",
            points,
        )
    elif len(found_keywords) >= 1:
        points = len(found_keywords) * URL_WEIGHTS["phishing_keywords_low"]
        add_indicator(
            "phishing_keywords",
            Severity.WARNING,
            "Phishing Keywords in URL",
            f"Contains: \"{'\", \"'.join(found_keywords[:3])}\". These terms appear "
            "frequently in URLs designed to impersonate account login pages.",
            points,
        )

    # ── Check 8: Deep subdomain structure ──────────────
    parts = hostname.split('.')
    if len(parts) > 4:
        add_indicator(
            "deep_subdomains",
            Severity.WARNING,
            f"Deep Subdomain Structure ({len(parts)} levels)",
            "Attackers add legitimate-looking subdomains to make a fake domain "
            "appear trustworthy, e.g., \"paypal.com.secure-login.attacker.xyz\". "
            "Most real sites use 2-3 hostname parts.",
            URL_WEIGHTS["deep_subdomains"],
        )

    # ── Check 9: Brand name in subdomain but not registered domain ──
    if subdomain:
        subdomain_lower = subdomain.lower()
        domain_lower = extracted.domain.lower()
        for brand in BRAND_NAMES:
            brand_clean = brand.replace(" ", "")
            if brand_clean in subdomain_lower and brand_clean not in domain_lower:
                add_indicator(
                    "brand_subdomain",
                    Severity.CRITICAL,
                    f"Brand Impersonation: \"{brand}\" in Subdomain",
                    f"The subdomain contains \"{brand}\" but the registered domain "
                    f"is \"{registered_domain}\". This is a deceptive lookalike "
                    "technique. The brand does not own this domain.",
                    URL_WEIGHTS["brand_in_subdomain"],
                )
                break

    # ── Check 10: Excessive URL length ─────────────────
    if len(raw_url) > 120:
        add_indicator(
            "long_url",
            Severity.INFO,
            f"Long URL ({len(raw_url)} characters)",
            "Long URLs can obscure the actual domain and add noise to make "
            "inspection harder. They may also carry encoded payloads.",
            URL_WEIGHTS["excessive_length"],
        )

    # ── Check 11: Hyphen-heavy domain ──────────────────
    label_before_tld = '.'.join(parts[:-1]) if len(parts) > 1 else hostname
    hyphen_count = label_before_tld.count('-')
    if hyphen_count >= 3:
        add_indicator(
            "hyphens",
            Severity.WARNING,
            f"{hyphen_count} Hyphens in Domain",
            "Multiple hyphens are a lookalike-domain technique: "
            "\"paypal-secure-account-verify.com\" looks plausible but is "
            "fraudulent. Legitimate brands rarely hyphenate their primary domain.",
            URL_WEIGHTS["hyphen_heavy_domain"],
        )

    # ── Check 12: Many digits in hostname ──────────────
    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count > 4 and "ip_host" not in seen_categories:
        add_indicator(
            "digits",
            Severity.INFO,
            f"{digit_count} Digits in Hostname",
            "A high number of digits often indicates a programmatically "
            "generated or disposable domain used for short-lived campaigns.",
            URL_WEIGHTS["digit_heavy_hostname"],
        )

    # ── Check 13: Non-standard port ────────────────────
    if port and str(port) not in ('80', '443', '8080', '8443'):
        add_indicator(
            "port",
            Severity.WARNING,
            f"Non-Standard Port: {port}",
            "Public websites serve traffic on ports 80 and 443. An unusual port "
            "suggests a server not set up as a legitimate web service.",
            URL_WEIGHTS["non_standard_port"],
        )

    # ── Check 14: Double slash in path ─────────────────
    if '//' in pathname:
        add_indicator(
            "double_slash",
            Severity.INFO,
            "Malformed URL Path",
            "Consecutive slashes in the path are uncommon on legitimate sites "
            "and may indicate URL manipulation or redirect abuse.",
            URL_WEIGHTS["double_slash_path"],
        )

    # ── Check 15: Excessive percent-encoding ───────────
    decoded = unquote(full_url)
    encoding_ratio = 1 - (len(decoded) / max(len(full_url), 1))
    if encoding_ratio > 0.15 and len(full_url) > 40:
        add_indicator(
            "encoding",
            Severity.WARNING,
            "Excessive URL Encoding",
            "This URL contains a high proportion of percent-encoded characters. "
            "Attackers encode characters to obfuscate the actual destination "
            "and bypass security filters.",
            URL_WEIGHTS["encoded_characters"],
        )

    # ── Check 16: Suspicious path keywords ─────────────
    path_lower = pathname.lower()
    suspicious_paths = ["/login", "/signin", "/verify", "/account", "/secure",
                        "/update", "/confirm", "/auth", "/password", "/banking"]
    found_paths = [p for p in suspicious_paths if p in path_lower]
    if found_paths and "phishing_keywords" not in seen_categories:
        add_indicator(
            "suspicious_path",
            Severity.WARNING,
            "Suspicious Path Structure",
            f"Path contains sensitive action keywords: {', '.join(found_paths)}. "
            "Combined with other domain indicators, this suggests a credential "
            "harvesting page.",
            URL_WEIGHTS["suspicious_path_keywords"],
        )

    final_score = min(score, 100)

    return {
        "score": final_score,
        "indicators": indicators,
        "metadata": metadata,
        "error": None,
    }
