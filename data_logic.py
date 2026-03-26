# data_logic.py
"""CYBER-1000 — Enterprise Cyber Risk Scoring Logic."""
import json
import math
import os
import socket
import requests
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

AXES_LABELS = [
    "Vulnerability Exposure",
    "Breach History",
    "Attack Surface",
    "Patch Readiness",
    "Industry Risk",
]

LOGIC_DESC = {
    "Vulnerability Exposure": "Known CVEs affecting the company's technology stack, weighted by severity (CVSS)",
    "Breach History": "Past data breaches — number of incidents, records exposed, recency",
    "Attack Surface": "Open ports, exposed services, SSL/TLS configuration quality",
    "Patch Readiness": "How quickly known vulnerabilities are addressed in the company's sector",
    "Industry Risk": "Sector-specific attack frequency and average breach cost",
}

COMPANIES_FILE = os.path.join(os.path.dirname(__file__), "companies.json")
CACHE_FILE = os.path.join(os.path.dirname(__file__), "cyber_cache.json")

# Industry risk scores (based on IBM Cost of Data Breach Report 2025)
# Higher = more risk = lower score
INDUSTRY_RISK = {
    "Healthcare": 0.95,
    "Banking": 0.90,
    "Financial Services": 0.85,
    "Pharma": 0.85,
    "Technology": 0.70,
    "Energy": 0.75,
    "Defense": 0.80,
    "Retail": 0.65,
    "Retail/Cloud": 0.70,
    "Entertainment": 0.50,
    "Semiconductors": 0.65,
    "Consumer Goods": 0.45,
    "Beverages": 0.40,
    "Telecom": 0.75,
    "Transportation": 0.55,
    "Travel": 0.60,
    "Logistics": 0.55,
    "Aerospace": 0.80,
    "Food Service": 0.45,
    "Apparel": 0.40,
    "Automotive": 0.60,
}

# Average breach cost by industry (in $M)
INDUSTRY_BREACH_COST = {
    "Healthcare": 10.9,
    "Banking": 6.1,
    "Financial Services": 6.1,
    "Pharma": 5.0,
    "Technology": 5.5,
    "Energy": 5.3,
    "Defense": 4.7,
    "Retail": 3.5,
    "Retail/Cloud": 4.5,
    "Entertainment": 3.8,
    "Semiconductors": 4.8,
    "Consumer Goods": 3.0,
    "Beverages": 2.8,
    "Telecom": 4.5,
    "Transportation": 3.8,
    "Travel": 3.5,
    "Logistics": 3.5,
    "Aerospace": 4.7,
    "Food Service": 2.5,
    "Apparel": 2.8,
    "Automotive": 4.2,
}


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


def _fetch_shodan_data(domain):
    """Fetch open ports and vulns from Shodan InternetDB (free, no key)."""
    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": ip,
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
            }
    except Exception:
        pass
    return {"ip": "", "ports": [], "vulns": [], "hostnames": [], "cpes": []}


def _fetch_breach_data(domain):
    """Fetch breach history from Have I Been Pwned."""
    try:
        r = requests.get(
            "https://haveibeenpwned.com/api/v3/breaches",
            timeout=10,
            headers={"User-Agent": "CYBER-1000/1.0"},
        )
        if r.status_code == 200:
            breaches = r.json()
            company_breaches = []
            domain_lower = domain.lower()
            domain_base = domain_lower.split(".")[0]
            for b in breaches:
                b_domain = (b.get("Domain") or "").lower()
                b_name = (b.get("Name") or "").lower()
                if domain_lower in b_domain or domain_base in b_name or domain_base in b_domain:
                    company_breaches.append({
                        "name": b["Name"],
                        "date": b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified", False),
                    })
            return company_breaches
    except Exception:
        pass
    return []


def _fetch_cisa_kev_count():
    """Fetch total count of CISA Known Exploited Vulnerabilities."""
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("count", 0)
    except Exception:
        pass
    return 1000


def _clamp(val, lo=0, hi=200):
    return max(lo, min(hi, int(val)))


def _score_vulnerability_exposure(shodan_data, company):
    """Score Vulnerability Exposure (200 pts max). Higher = less exposed = better."""
    vulns = shodan_data.get("vulns", [])
    num_vulns = len(vulns)

    # Fewer vulns = higher score
    if num_vulns == 0:
        vuln_score = 120
    elif num_vulns <= 2:
        vuln_score = 90
    elif num_vulns <= 5:
        vuln_score = 60
    elif num_vulns <= 10:
        vuln_score = 30
    else:
        vuln_score = 10

    # CPE (software) exposure
    cpes = shodan_data.get("cpes", [])
    if len(cpes) == 0:
        cpe_score = 40  # Can't assess = neutral
    elif len(cpes) <= 3:
        cpe_score = 35
    elif len(cpes) <= 6:
        cpe_score = 25
    else:
        cpe_score = 10

    # Company size bonus (larger companies have more attack vectors but also more security budget)
    employees = company.get("employees", 10000)
    if employees > 100000:
        size_score = 30  # Large = more resources for security
    elif employees > 10000:
        size_score = 35
    else:
        size_score = 40  # Smaller = potentially less protected

    return _clamp(vuln_score + cpe_score + size_score)


def _score_breach_history(breaches, company):
    """Score Breach History (200 pts max). Higher = fewer breaches = better."""
    if not breaches:
        return _clamp(180)  # No known breaches = great

    total_records = sum(b.get("pwn_count", 0) for b in breaches)
    num_breaches = len(breaches)

    # Fewer breaches = higher score
    if num_breaches == 1:
        count_score = 100
    elif num_breaches == 2:
        count_score = 70
    elif num_breaches <= 4:
        count_score = 40
    else:
        count_score = 10

    # Fewer records exposed = higher score
    if total_records < 100000:
        records_score = 60
    elif total_records < 1000000:
        records_score = 40
    elif total_records < 10000000:
        records_score = 20
    else:
        records_score = 5

    # Recency — recent breaches are worse
    recency_score = 40
    for b in breaches:
        breach_date = b.get("date", "")
        if breach_date >= "2024":
            recency_score = 10
            break
        elif breach_date >= "2022":
            recency_score = 20
            break
        elif breach_date >= "2020":
            recency_score = 30

    return _clamp(count_score + records_score + recency_score)


def _score_attack_surface(shodan_data):
    """Score Attack Surface (200 pts max). Higher = smaller attack surface = better."""
    ports = shodan_data.get("ports", [])
    num_ports = len(ports)

    # Fewer open ports = better
    if num_ports <= 2:
        port_score = 80
    elif num_ports <= 4:
        port_score = 60
    elif num_ports <= 8:
        port_score = 40
    else:
        port_score = 15

    # Check for risky ports
    risky_ports = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443}
    risky_open = len(set(ports) & risky_ports)
    if risky_open == 0:
        risky_score = 60
    elif risky_open <= 2:
        risky_score = 35
    else:
        risky_score = 10

    # Has HTTPS (443)
    has_https = 443 in ports
    has_http = 80 in ports
    if has_https and not has_http:
        tls_score = 60  # HTTPS only = best
    elif has_https:
        tls_score = 50  # Both = ok
    elif has_http:
        tls_score = 20  # HTTP only = bad
    else:
        tls_score = 40  # No web presence detected

    return _clamp(port_score + risky_score + tls_score)


def _score_patch_readiness(shodan_data, sector):
    """Score Patch Readiness (200 pts max). Based on sector patch speed + exposed vulns."""
    # Sector-based patch speed (some industries are slower)
    slow_sectors = {"Healthcare", "Banking", "Defense", "Aerospace"}
    medium_sectors = {"Energy", "Telecom", "Automotive", "Logistics"}

    if sector in slow_sectors:
        sector_score = 60
    elif sector in medium_sectors:
        sector_score = 80
    else:
        sector_score = 100

    # Active vulns on Shodan = not patched
    vulns = shodan_data.get("vulns", [])
    if len(vulns) == 0:
        patch_score = 100
    elif len(vulns) <= 2:
        patch_score = 70
    elif len(vulns) <= 5:
        patch_score = 40
    else:
        patch_score = 10

    return _clamp(sector_score + patch_score)


def _score_industry_risk(sector):
    """Score Industry Risk (200 pts max). Higher = lower risk industry = better."""
    risk_factor = INDUSTRY_RISK.get(sector, 0.5)
    # Invert: lower risk = higher score
    score = (1.0 - risk_factor) * 200 + 80
    return _clamp(score)


def _estimate_premium(total_score, company):
    """Estimate cyber insurance premium based on score."""
    revenue = company.get("revenue_b", 10) * 1000  # Convert to $M
    sector = company.get("sector", "Technology")
    breach_cost = INDUSTRY_BREACH_COST.get(sector, 4.0)

    # Base rate from score (higher score = lower rate)
    if total_score >= 800:
        base_rate = 0.005  # 0.5%
    elif total_score >= 700:
        base_rate = 0.008
    elif total_score >= 600:
        base_rate = 0.012
    elif total_score >= 500:
        base_rate = 0.018
    elif total_score >= 400:
        base_rate = 0.025
    else:
        base_rate = 0.035  # 3.5%

    # Industry adjustment
    industry_mult = 0.5 + risk_factor if (risk_factor := INDUSTRY_RISK.get(sector, 0.5)) else 1.0

    # Coverage amount (typically 10-20% of revenue for large companies)
    coverage = min(revenue * 0.1, 500)  # Cap at $500M coverage

    premium = coverage * base_rate * industry_mult

    return {
        "rate_pct": round(base_rate * industry_mult * 100, 2),
        "coverage_m": round(coverage, 1),
        "estimated_premium_m": round(premium, 2),
        "avg_breach_cost_m": breach_cost,
    }


def score_all_companies():
    """Score all companies and return sorted list."""
    companies = _load_companies()
    cache = _load_cache()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    results = []

    for company in companies:
        domain = company["domain"]
        name = company["name"]

        # Use cache if fresh (same day)
        cached = cache.get(domain, {})
        if cached.get("date") == today:
            shodan_data = cached.get("shodan", {})
            breaches = cached.get("breaches", [])
        else:
            shodan_data = _fetch_shodan_data(domain)
            breaches = _fetch_breach_data(domain)
            cache[domain] = {
                "date": today,
                "shodan": shodan_data,
                "breaches": breaches,
            }

        sector = company.get("sector", "Technology")

        ve = _score_vulnerability_exposure(shodan_data, company)
        bh = _score_breach_history(breaches, company)
        as_ = _score_attack_surface(shodan_data)
        pr = _score_patch_readiness(shodan_data, sector)
        ir = _score_industry_risk(sector)
        total = ve + bh + as_ + pr + ir

        premium = _estimate_premium(total, company)

        results.append({
            "name": name,
            "domain": domain,
            "sector": sector,
            "total": total,
            "axes": {
                "Vulnerability Exposure": ve,
                "Breach History": bh,
                "Attack Surface": as_,
                "Patch Readiness": pr,
                "Industry Risk": ir,
            },
            "company": company,
            "shodan": shodan_data,
            "breaches": breaches,
            "premium": premium,
        })

    # Save cache
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
