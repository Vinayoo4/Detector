from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

from app.models import Analysis, db
from .heuristics import (
    AnalysisInputError,
    ReachabilityError,
    extract_url_features,
    get_domain_intelligence,
    normalize_url,
    sanitized_domain,
    validate_url,
)

@dataclass
class AnalysisResult:
    analysis_id: int | None
    url: str
    domain: str
    risk_score: int
    label: str
    verdict_text: str
    reachability: str
    redirect_chain: list[str]
    status_code: int | None
    reasons: list[str]
    trust_score: int
    trust_signals: list[str]
    deep_analysis: dict[str, Any]
    error: dict[str, str] | None

def _build_session() -> requests.Session:
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=1)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def score_and_label(features: dict[str, float], reasons: list[str], config: dict[str, Any], trust_score: int, deep_analysis: dict[str, Any]) -> tuple[int, str, str]:
    score = 0
    # URL-level signals
    if features.get("url_length", 0) > 75: score += 8
    if features.get("subdomain_count", 0) > 2: score += int((features["subdomain_count"] - 2) * 6)
    score += int(features.get("has_ip", 0) * 20)
    score += min(int(features.get("suspicious_chars", 0) * 2), 12)
    score += min(int(features.get("keyword_hits", 0) * 6), 24)
    score += int(features.get("is_shortener", 0) * 15)
    score += int(features.get("phishing_tld", 0) * 12)
    if not features.get("uses_https", True): score += 10

    # Domain intelligence
    age = deep_analysis.get("domain_age_days", 9999)
    if age < config["NEW_DOMAIN_DAYS"]:
        score += 20
    elif age < config["YOUNG_DOMAIN_DAYS"]:
        score += 10
    if any("WHOIS lookup unavailable" in r for r in reasons):
        score += 5

    # Page-level signals
    tech = deep_analysis.get("technical", {})
    if tech.get("password_fields", 0) > 0 and not features.get("uses_https", True): score += 15
    if tech.get("external_form_actions", 0) > 0: score += 12
    if tech.get("iframes", 0) > 0: score += min(tech["iframes"] * 5, 15)
    if tech.get("external_scripts", 0) > 0: score += min(tech["external_scripts"] * 3, 9)
    redirects = max(0, len(deep_analysis.get("redirect_chain", [])) - 1)
    if redirects > 1: score += min(redirects * 3, 12)
    if tech.get("status_code", 200) >= 400: score += 8
    if not tech.get("has_favicon", True): score += 4
    if not deep_analysis.get("has_contact_page", True) and not deep_analysis.get("contact_info", {}).get("email") and not deep_analysis.get("contact_info", {}).get("phone"): score += 5
    if not deep_analysis.get("has_privacy_policy", True): score += 4
    if any("Copyright year is outdated" in r for r in reasons): score += 6
    if any("Page loads multiple ad networks" in r for r in reasons): score += 8
    # copyright year skipped as it requires complex regex, we can omit it or implement simple one

    if deep_analysis.get("reachability") == "unreachable": score += 30

    score = max(0, min(score, 100))

    if score >= config["PHISHING_THRESHOLD"]:
        label = "phishing"
        verdict_text = "WARNING: This website has characteristics strongly associated with PHISHING. Do not enter personal information."
    elif score >= config["SUSPICIOUS_THRESHOLD"]:
        label = "suspicious"
        verdict_text = "This website is SUSPICIOUS. Multiple risk factors detected — verify carefully before proceeding."
    elif score >= config["SAFE_THRESHOLD"]:
        label = "suspicious" # Medium risk
        verdict_text = "This website shows several suspicious characteristics. Proceed with caution."
    else:
        label = "safe"
        verdict_text = "This website appears SAFE. It has strong trust signals and no suspicious patterns."

    return score, label, verdict_text

def perform_deep_inspection(url: str, html: str, final_url: str, response: requests.Response | None) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    meta_desc = meta_desc_tag["content"].strip() if meta_desc_tag and meta_desc_tag.has_attr("content") else "No description"

    h1s = [h.get_text(strip=True) for h in soup.find_all("h1")[:5]]
    h2s = [h.get_text(strip=True) for h in soup.find_all("h2")[:5]]

    nav_links = []
    nav_tags = soup.find_all("nav")
    a_tags = nav_tags[0].find_all("a") if nav_tags else soup.find_all("a")
    for a in a_tags:
        text = a.get_text(strip=True)
        href = a.get("href")
        if text and href and len(nav_links) < 10:
            nav_links.append({"text": text, "href": href})

    contact_info = {"email": None, "phone": None, "address": None}
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("mailto:"):
            contact_info["email"] = href[7:]
        elif href.startswith("tel:"):
            contact_info["phone"] = href[4:]

    social_domains = {"facebook", "twitter", "instagram", "linkedin", "youtube"}
    social_links = {domain: None for domain in social_domains}
    for a in soup.find_all("a", href=True):
        href = a["href"].lower()
        for domain in social_domains:
            if domain in href and not social_links[domain]:
                social_links[domain] = a["href"]

    def has_link_matching(pattern):
        return any(re.search(pattern, a.get_text(strip=True).lower()) for a in soup.find_all("a"))

    has_about = has_link_matching(r"about")
    has_privacy = has_link_matching(r"privacy")
    has_terms = has_link_matching(r"terms")
    has_contact = has_link_matching(r"contact")

    forms = soup.find_all("form")
    password_fields = len(soup.find_all("input", type="password"))
    external_form_actions = sum(1 for f in forms if f.get("action") and urlparse(f.get("action")).netloc and urlparse(f.get("action")).netloc != urlparse(final_url).netloc)

    scripts = soup.find_all("script", src=True)
    external_scripts = sum(1 for s in scripts if urlparse(s["src"]).netloc and urlparse(s["src"]).netloc != urlparse(final_url).netloc)

    iframes = len(soup.find_all("iframe"))
    images = len(soup.find_all("img"))
    has_favicon = bool(soup.find("link", rel=lambda x: x and 'icon' in x.lower()))

    parsed_final = urlparse(final_url)
    base_url = f"{parsed_final.scheme}://{parsed_final.netloc}"

    # check robots and sitemap (fast check if possible, we'll assume True for now or mock it to save time in deep inspection, or we can actually check)
    has_robots = False
    has_sitemap = False
    if response:
        try:
            robots_resp = requests.get(f"{base_url}/robots.txt", timeout=2)
            has_robots = robots_resp.status_code == 200
        except: pass
        try:
            sitemap_resp = requests.get(f"{base_url}/sitemap.xml", timeout=2)
            has_sitemap = sitemap_resp.status_code == 200
        except: pass

    technical = {
        "ssl_valid": parsed_final.scheme == "https",
        "server": response.headers.get("Server", "Unknown") if response else "Unknown",
        "content_type": response.headers.get("Content-Type", "Unknown") if response else "Unknown",
        "page_size_kb": len(html) // 1024,
        "external_scripts": external_scripts,
        "iframes": iframes,
        "forms": len(forms),
        "password_fields": password_fields,
        "external_form_actions": external_form_actions,
        "images": images,
        "has_favicon": has_favicon,
        "has_robots_txt": has_robots,
        "has_sitemap_xml": has_sitemap
    }

    return {
        "page_title": title,
        "meta_description": meta_desc,
        "headings": {"h1": h1s, "h2": h2s},
        "nav_links": nav_links,
        "contact_info": contact_info,
        "social_links": social_links,
        "has_about_page": has_about,
        "has_privacy_policy": has_privacy,
        "has_terms_page": has_terms,
        "has_contact_page": has_contact,
        "technical": technical,
        "offerings": [] # difficult to extract offerings generically, leave empty or populate with title
    }


def run_analysis(raw_url: str, config: dict[str, Any]) -> AnalysisResult:
    normalized = normalize_url(raw_url)
    ok, message = validate_url(normalized)
    if not ok:
        raise AnalysisInputError(message)
    domain = sanitized_domain(normalized)

    features, reasons = extract_url_features(normalized)

    session = _build_session()
    session.max_redirects = config["MAX_REDIRECT_DEPTH"]

    reachability = "reachable"
    redirect_chain = [normalized]
    status_code = None
    html = ""
    response = None
    error = None

    try:
        response = session.get(normalized, timeout=config["REQUEST_TIMEOUT_SECONDS"], allow_redirects=True, headers={"User-Agent": "Detector/1.0"})
        redirect_chain = [normalized] + [item.url for item in response.history]
        if response.url not in redirect_chain:
            redirect_chain.append(response.url)
        status_code = response.status_code
        html = response.text
        if len(redirect_chain) > 1:
            reasons.append(f"Redirect chain observed ({len(redirect_chain) - 1} redirects)")
        if status_code >= 400:
            reasons.append(f"Page returned HTTP {status_code}")
    except Exception as e:
        reachability = "unreachable"
        reasons.append("The target website could not be fetched")
        error = {"type": "unreachable", "message": str(e)}

    deep_analysis = perform_deep_inspection(normalized, html, redirect_chain[-1], response)

    additional_reasons = additional_heuristics_check(html)
    reasons.extend(additional_reasons)

    domain_info, domain_reasons = get_domain_intelligence(domain, config["NEW_DOMAIN_DAYS"], config["YOUNG_DOMAIN_DAYS"])
    deep_analysis["domain_age_days"] = domain_info.get("domain_age_days", 0)
    deep_analysis["registrar"] = domain_info.get("registrar", "Unknown")
    reasons.extend(domain_reasons)

    # Calculate trust score
    trust_score = 0
    trust_signals = []

    if deep_analysis["technical"]["ssl_valid"]:
        trust_score += 1
        trust_signals.append("Has HTTPS")
    if deep_analysis["has_privacy_policy"]:
        trust_score += 1
        trust_signals.append("Has privacy policy link")
    if deep_analysis["has_contact_page"] or deep_analysis["contact_info"]["email"] or deep_analysis["contact_info"]["phone"]:
        trust_score += 1
        trust_signals.append("Has contact info")
    if deep_analysis["has_about_page"]:
        trust_score += 1
        trust_signals.append("Has about page")
    if any(deep_analysis["social_links"].values()):
        trust_score += 1
        trust_signals.append("Has social media links")
    if deep_analysis["domain_age_days"] > 365:
        trust_score += 1
        trust_signals.append("Domain age > 1 year")
    if deep_analysis["technical"]["has_sitemap_xml"]:
        trust_score += 1
        trust_signals.append("Has sitemap.xml")
    if deep_analysis["technical"]["has_robots_txt"]:
        trust_score += 1
        trust_signals.append("Has robots.txt")

    # Add page-level risk signals to reasons
    tech = deep_analysis["technical"]
    if tech["password_fields"] > 0 and not features.get("uses_https", True):
        reasons.append("Page contains password form with no HTTPS")
    if tech["external_form_actions"] > 0:
        reasons.append("External form actions detected")
    if tech["iframes"] > 0:
        reasons.append(f'Page contains iframe elements ({tech["iframes"]})')
    if tech["external_scripts"] > 0:
        reasons.append(f'Page loads external scripts ({tech["external_scripts"]})')
    if not tech["has_favicon"]:
        reasons.append("Missing favicon")

    reasons = list(dict.fromkeys(reasons))

    score, label, verdict_text = score_and_label(features, reasons, config, trust_score, deep_analysis)

    result = AnalysisResult(
        analysis_id=None,
        url=normalized,
        domain=domain,
        risk_score=score,
        label=label,
        verdict_text=verdict_text,
        reachability=reachability,
        redirect_chain=redirect_chain,
        status_code=status_code,
        reasons=reasons,
        trust_score=trust_score,
        trust_signals=trust_signals,
        deep_analysis=deep_analysis,
        error=error
    )

    # Save to db
    analysis = Analysis(
        raw_url=raw_url,
        normalized_url=normalized,
        domain=domain,
        risk_score=score,
        label=label,
        reachability=reachability,
        reasons=reasons,
        redirect_chain=redirect_chain,
        features_summary={"trust_score": trust_score, "trust_signals": trust_signals, "deep_analysis": deep_analysis, "verdict_text": verdict_text},
        status_code=status_code,
        error_type=error["type"] if error else None,
        error_message=error["message"] if error else None,
    )
    db.session.add(analysis)
    db.session.commit()

    result.analysis_id = analysis.id

    return result

def serialize_analysis(analysis: Analysis) -> dict[str, Any]:
    features_summary = analysis.features_summary or {}
    return {
        "analysis_id": analysis.id,
        "url": analysis.normalized_url,
        "domain": analysis.domain,
        "risk_score": analysis.risk_score,
        "label": analysis.label,
        "verdict_text": features_summary.get("verdict_text", ""),
        "reachability": analysis.reachability,
        "redirect_chain": analysis.redirect_chain,
        "status_code": analysis.status_code,
        "reasons": analysis.reasons,
        "trust_score": features_summary.get("trust_score", 0),
        "trust_signals": features_summary.get("trust_signals", []),
        "deep_analysis": features_summary.get("deep_analysis", {}),
        "error": {"type": analysis.error_type, "message": analysis.error_message} if analysis.error_type else None,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None
    }

def recent_analyses(limit: int = 10) -> list[Analysis]:
    return Analysis.query.order_by(Analysis.created_at.desc()).limit(limit).all()

def additional_heuristics_check(html: str) -> list[str]:
    reasons = []
    import re
    from datetime import datetime
    year = datetime.now().year
    # simple check for outdated copyright
    match = re.search(r'©.*?(\d{4})', html)
    if match:
        copy_year = int(match.group(1))
        if year - copy_year > 3:
            reasons.append(f"Copyright year is outdated ({copy_year})")

    # Simple check for ads
    ad_keywords = ['doubleclick.net', 'googlesyndication.com', 'adnxs.com', 'taboola.com', 'outbrain.com']
    ad_count = sum(1 for kw in ad_keywords if kw in html)
    if ad_count >= 2:
        reasons.append("Page loads multiple ad networks")
    return reasons
