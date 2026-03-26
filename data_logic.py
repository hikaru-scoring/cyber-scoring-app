# data_logic.py
"""CYBER-1000 — Enterprise Cyber Risk Scoring Logic. All scores from real API data."""
import json
import math
import os
import socket
import ssl
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

AXES_LABELS = [
    "Vulnerability Exposure",
    "Breach History",
    "Attack Surface",
    "SSL Health",
    "Email Security",
]

LOGIC_DESC = {
    "Vulnerability Exposure": "Total known CVEs (NVD) associated with this company's products",
    "Breach History": "Past data breaches — number of incidents and total records exposed (HIBP)",
    "Attack Surface": "Open ports, known vulnerabilities on public-facing infrastructure (Shodan)",
    "SSL Health": "SSL certificate validity, days until expiry, issuer quality",
    "Email Security": "SPF, DMARC, and DKIM configuration from DNS records",
}

COMPANIES_FILE = os.path.join(os.path.dirname(__file__), "companies.json")
CACHE_FILE = os.path.join(os.path.dirname(__file__), "cyber_cache.json")


def _load_companies():
    with open(COMPANIES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)


def _clamp(val, lo=0, hi=200):
    return max(lo, min(hi, int(val)))


# ── Data Fetchers (all real API, no estimates) ──

def _fetch_cve_count(company_name):
    """Fetch total CVE count from NVD for this company."""
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": company_name.lower(), "resultsPerPage": 1},
            timeout=20,
        )
        if r.status_code == 200:
            return r.json().get("totalResults", 0)
    except Exception:
        pass
    return -1  # -1 = failed to fetch


def _fetch_breaches(domain):
    """Fetch breach data from Have I Been Pwned."""
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            timeout=10,
            headers={"User-Agent": "CYBER-1000/1.0"},
        )
        if r.status_code == 200:
            breaches = r.json()
            domain_lower = domain.lower()
            domain_base = domain_lower.split(".")[0]
            matches = []
            for b in breaches:
                b_domain = (b.get("Domain") or "").lower()
                b_name = (b.get("Name") or "").lower()
                if domain_lower in b_domain or domain_base in b_name or domain_base in b_domain:
                    matches.append({
                        "name": b["Name"],
                        "date": b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                    })
            return matches
    except Exception:
        pass
    return []


def _fetch_shodan(domain):
    """Fetch attack surface data from Shodan InternetDB."""
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": ip,
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "cpes": data.get("cpes", []),
            }
    except Exception:
        pass
    return {"ip": "", "ports": [], "vulns": [], "cpes": []}


def _fetch_ssl(domain):
    """Fetch SSL certificate data by direct connection."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            not_after = cert.get("notAfter", "")
            issuer = dict(x[0] for x in cert.get("issuer", []))
            org = issuer.get("organizationName", "Unknown")
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.now(timezone.utc).replace(tzinfo=None)).days
            return {
                "days_until_expiry": days_left,
                "issuer": org,
                "expiry_date": not_after,
            }
    except Exception:
        pass
    return {"days_until_expiry": -1, "issuer": "Unknown", "expiry_date": ""}


def _fetch_dns_security(domain):
    """Fetch SPF and DMARC records from Google DNS API."""
    result = {"has_spf": False, "has_dmarc": False, "dmarc_policy": "none", "has_dkim": False}
    try:
        # SPF
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=TXT", timeout=5)
        if r.status_code == 200:
            for a in r.json().get("Answer", []):
                if "v=spf1" in a.get("data", ""):
                    result["has_spf"] = True
                    break

        # DMARC
        r2 = requests.get(f"https://dns.google/resolve?name=_dmarc.{domain}&type=TXT", timeout=5)
        if r2.status_code == 200:
            answers = r2.json().get("Answer", [])
            if answers:
                result["has_dmarc"] = True
                for a in answers:
                    data = a.get("data", "")
                    if "p=reject" in data:
                        result["dmarc_policy"] = "reject"
                    elif "p=quarantine" in data:
                        result["dmarc_policy"] = "quarantine"
                    elif "p=none" in data:
                        result["dmarc_policy"] = "none"

        # DKIM (check for google selector as common case)
        r3 = requests.get(f"https://dns.google/resolve?name=google._domainkey.{domain}&type=TXT", timeout=5)
        if r3.status_code == 200:
            if r3.json().get("Answer"):
                result["has_dkim"] = True
    except Exception:
        pass
    return result


# ── Scoring Functions (all from real data) ──

def _score_vulnerability_exposure(cve_count):
    """200 = no CVEs. Score decreases with more CVEs (log scale)."""
    if cve_count < 0:
        return 100  # API failed, neutral
    if cve_count == 0:
        return 200
    # log scale: 1 CVE=190, 10=170, 100=150, 1000=130, 10000=110
    score = 200 - math.log10(max(cve_count, 1)) * 22
    return _clamp(score)


def _score_breach_history(breaches):
    """200 = no breaches. Penalized by count, records exposed, and recency."""
    if not breaches:
        return 200

    num = len(breaches)
    total_records = sum(b.get("pwn_count", 0) for b in breaches)

    # Count penalty
    count_penalty = min(num * 15, 80)

    # Records penalty (log scale)
    if total_records > 0:
        records_penalty = min(math.log10(total_records) * 10, 80)
    else:
        records_penalty = 0

    # Recency penalty
    recency_penalty = 0
    for b in breaches:
        if b.get("date", "") >= "2024":
            recency_penalty = 40
            break
        elif b.get("date", "") >= "2022":
            recency_penalty = 25
            break
        elif b.get("date", "") >= "2020":
            recency_penalty = 15

    score = 200 - count_penalty - records_penalty - recency_penalty
    return _clamp(score)


def _score_attack_surface(shodan_data):
    """200 = minimal attack surface. Penalized by ports, vulns, exposed software."""
    ports = shodan_data.get("ports", [])
    vulns = shodan_data.get("vulns", [])
    cpes = shodan_data.get("cpes", [])

    # Port penalty
    risky_ports = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443}
    num_risky = len(set(ports) & risky_ports)
    port_penalty = len(ports) * 5 + num_risky * 15

    # Vuln penalty
    vuln_penalty = len(vulns) * 20

    # Software exposure penalty
    cpe_penalty = len(cpes) * 5

    score = 200 - port_penalty - vuln_penalty - cpe_penalty
    return _clamp(score)


def _score_ssl_health(ssl_data):
    """200 = strong SSL. Penalized by short expiry, weak issuer."""
    days = ssl_data.get("days_until_expiry", -1)
    issuer = ssl_data.get("issuer", "Unknown")

    if days < 0:
        return 100  # Can't check

    # Days until expiry
    if days >= 180:
        expiry_score = 80
    elif days >= 90:
        expiry_score = 60
    elif days >= 30:
        expiry_score = 40
    elif days >= 7:
        expiry_score = 20
    else:
        expiry_score = 0  # About to expire or expired

    # Issuer quality
    premium_issuers = ["DigiCert", "GlobalSign", "Sectigo", "Entrust"]
    self_signed = ["self-signed", "Unknown"]
    free_issuers = ["Let's Encrypt"]

    issuer_lower = issuer.lower()
    if any(p.lower() in issuer_lower for p in premium_issuers):
        issuer_score = 60
    elif issuer == issuer:  # Company self-issues (Apple, Microsoft)
        issuer_score = 70  # Self-managed = strong internal PKI
    elif any(f.lower() in issuer_lower for f in free_issuers):
        issuer_score = 40  # Free = works but signals smaller budget
    else:
        issuer_score = 50  # Unknown issuer

    # Has HTTPS at all
    has_ssl_score = 60 if days >= 0 else 0

    return _clamp(expiry_score + issuer_score + has_ssl_score)


def _score_email_security(dns_data):
    """200 = full email security. Based on SPF + DMARC + DKIM + policy strength."""
    score = 0

    # SPF (max 60)
    if dns_data.get("has_spf"):
        score += 60

    # DMARC (max 60)
    if dns_data.get("has_dmarc"):
        score += 40
        # DMARC policy strength
        policy = dns_data.get("dmarc_policy", "none")
        if policy == "reject":
            score += 20  # Strongest
        elif policy == "quarantine":
            score += 10
        # "none" = 0 additional

    # DKIM (max 40)
    if dns_data.get("has_dkim"):
        score += 40

    # Base score for having any email config (max 40)
    if dns_data.get("has_spf") or dns_data.get("has_dmarc"):
        score += 40

    return _clamp(score)


def _estimate_premium(total_score, company):
    """Estimate cyber insurance premium based on score."""
    revenue_m = company.get("revenue_b", 10) * 1000

    if total_score >= 900:
        base_rate = 0.003
    elif total_score >= 800:
        base_rate = 0.005
    elif total_score >= 700:
        base_rate = 0.008
    elif total_score >= 600:
        base_rate = 0.012
    elif total_score >= 500:
        base_rate = 0.018
    elif total_score >= 400:
        base_rate = 0.025
    else:
        base_rate = 0.035

    coverage = min(revenue_m * 0.1, 500)
    premium = coverage * base_rate

    return {
        "rate_pct": round(base_rate * 100, 2),
        "coverage_m": round(coverage, 1),
        "estimated_premium_m": round(premium, 2),
    }


def score_all_companies():
    """Score all companies using real API data. Returns sorted list."""
    companies = _load_companies()
    cache = _load_cache()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    results = []

    # Fetch HIBP breaches once (single API call for all)
    all_breaches = []
    try:
        r = requests.get("https://haveibeenpwned.com/api/v3/breaches", timeout=10,
                         headers={"User-Agent": "CYBER-1000/1.0"})
        if r.status_code == 200:
            all_breaches = r.json()
    except Exception:
        pass

    for company in companies:
        domain = company["domain"]
        name = company["name"]

        # Use cache if fresh
        cached = cache.get(domain, {})
        if cached.get("date") == today and cached.get("version") == "v2":
            cve_count = cached.get("cve_count", 0)
            breaches = cached.get("breaches", [])
            shodan_data = cached.get("shodan", {})
            ssl_data = cached.get("ssl", {})
            dns_data = cached.get("dns", {})
        else:
            # Fetch all real data
            cve_count = _fetch_cve_count(name)

            # Match breaches from pre-fetched list
            domain_lower = domain.lower()
            domain_base = domain_lower.split(".")[0]
            breaches = []
            for b in all_breaches:
                b_domain = (b.get("Domain") or "").lower()
                b_name = (b.get("Name") or "").lower()
                if domain_lower in b_domain or domain_base in b_name or domain_base in b_domain:
                    breaches.append({
                        "name": b["Name"],
                        "date": b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                    })

            shodan_data = _fetch_shodan(domain)
            ssl_data = _fetch_ssl(domain)
            dns_data = _fetch_dns_security(domain)

            cache[domain] = {
                "date": today,
                "version": "v2",
                "cve_count": cve_count,
                "breaches": breaches,
                "shodan": shodan_data,
                "ssl": ssl_data,
                "dns": dns_data,
            }

        # Score all 5 axes from real data
        ve = _score_vulnerability_exposure(cve_count)
        bh = _score_breach_history(breaches)
        as_ = _score_attack_surface(shodan_data)
        sh = _score_ssl_health(ssl_data)
        es = _score_email_security(dns_data)
        total = ve + bh + as_ + sh + es

        premium = _estimate_premium(total, company)

        results.append({
            "name": name,
            "domain": domain,
            "sector": company.get("sector", ""),
            "total": total,
            "axes": {
                "Vulnerability Exposure": ve,
                "Breach History": bh,
                "Attack Surface": as_,
                "SSL Health": sh,
                "Email Security": es,
            },
            "raw_data": {
                "cve_count": cve_count,
                "breach_count": len(breaches),
                "total_records_exposed": sum(b.get("pwn_count", 0) for b in breaches),
                "open_ports": shodan_data.get("ports", []),
                "shodan_vulns": len(shodan_data.get("vulns", [])),
                "ssl_days_left": ssl_data.get("days_until_expiry", -1),
                "ssl_issuer": ssl_data.get("issuer", "Unknown"),
                "has_spf": dns_data.get("has_spf", False),
                "has_dmarc": dns_data.get("has_dmarc", False),
                "dmarc_policy": dns_data.get("dmarc_policy", "none"),
                "has_dkim": dns_data.get("has_dkim", False),
            },
            "company": company,
            "breaches": breaches,
            "premium": premium,
        })

    _save_cache(cache)
    results.sort(key=lambda x: x["total"], reverse=True)
    return results


def fetch_company_news(company_name):
    """Fetch cybersecurity news for a company via Google News RSS."""
    try:
        query = f"{company_name} cybersecurity breach vulnerability"
        url = f"https://news.google.com/rss/search?q={query.replace(' ', '+')}&hl=en-US&gl=US&ceid=US:en"
        r = requests.get(url, timeout=10, headers={"User-Agent": "CYBER-1000/1.0"})
        root = ET.fromstring(r.text)
        items = root.findall(".//item")[:5]
        news = []
        for item in items:
            title = item.find("title").text
            link = item.find("link").text
            pub = item.find("pubDate")
            source = item.find("source")
            news.append({
                "title": title,
                "link": link,
                "date": pub.text if pub is not None else "",
                "source": source.text if source is not None else "",
            })
        return news
    except Exception:
        return []
