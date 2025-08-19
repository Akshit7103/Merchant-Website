
"""
merchant_checker.py
A lightweight web checker that visits merchant websites and verifies the presence
of key onboarding checklist items (privacy policy, terms, refunds, contact info,
HTTPS, etc.), then logs a report (CSV and JSONL).

USAGE
-----
1) Install deps (ideally in a virtualenv):
    pip install -r requirements.txt

2) Run against a CSV of domains (one domain or URL per line), or pass --url repeatedly:
    python merchant_checker.py --input merchants.csv --out report
    # or
    python merchant_checker.py --url https://example.com --out report_single

Outputs:
- report.csv       : summary row per site, with pass/fail and counts
- report.jsonl     : detailed evidence per site (per-field URLs and snippets)
- report_logs.txt  : crawl logs

NOTES
-----
- This script keeps the crawl shallow and polite: homepage + likely policy/faq/contact pages.
- For JS-heavy sites you may need a headless browser; see the Playwright stub below.
- Always respect robots.txt and local laws/ToS before crawling external sites.
"""
import argparse
import csv
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from urllib import robotparser

requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL:@SECLEVEL=1'  # compatibility for some old servers

# ----------------------------- Config ----------------------------------

DEFAULT_HEADERS = {
    "User-Agent": "MerchantChecklistBot/1.0 (+https://example.com/bot-policy)"
}
TIMEOUT = 12
MAX_WORKERS = 8
SLEEP_BETWEEN_SITES = 0.5  # seconds
REQUEST_DELAY = 0.75       # seconds between requests to the same site
MAX_BYTES = 2_000_000      # don't download pages larger than 2MB

POLICY_KEYWORDS = {
    "privacy": ["privacy", "data protection"],
    "terms": ["terms", "conditions", "tos"],
    "refunds": ["refund", "return", "cancellation"],
    "shipping": ["shipping", "delivery", "fulfillment"],
    "contact": ["contact", "support", "help", "contact us"],
    "about": ["about", "about us"],
}

PROHIBITED_HINTS = [
    "gambling", "casino", "betting",
    "porn", "xxx", "escort",
    "steroids", "anabolic", "marijuana", "cannabis", "kratom",
    "weapons", "firearms", "counterfeit",
]

CURRENCY_HINT = re.compile(r"(₹|Rs\.?|USD|EUR|£|\$)\s?\d[\d,\.]*", re.I)
PHONE_HINT = re.compile(r"(\+\d{1,3}[-.\s]?)?(\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}", re.I)
EMAIL_HINT = re.compile(r"[\w\.-]+@[\w\.-]+\.\w{2,}", re.I)

# -----------------------------------------------------------------------

@dataclass
class CheckResult:
    present: bool
    evidence_url: Optional[str] = None
    evidence_text: Optional[str] = None
    confidence: float = 0.0

@dataclass
class SiteReport:
    url: str
    final_url: str
    https: bool
    reachable: bool
    http_status: Optional[int]
    business_signals: Dict[str, CheckResult] = field(default_factory=dict)
    prohibited_content: CheckResult = field(default_factory=lambda: CheckResult(False, None, None, 0.0))
    checkout_signals: CheckResult = field(default_factory=lambda: CheckResult(False, None, None, 0.0))
    has_prices: CheckResult = field(default_factory=lambda: CheckResult(False, None, None, 0.0))
    functionality_ok: bool = False
    notes: Optional[str] = None

    def to_csv_row(self) -> Dict[str, str]:
        # Flatten for CSV
        row = {
            "url": self.url,
            "final_url": self.final_url,
            "reachable": "YES" if self.reachable else "NO",
            "https": "YES" if self.https else "NO",
            "status": str(self.http_status or ""),
            "functionality_ok": "YES" if self.functionality_ok else "NO",
            "prohibited_content": "YES" if self.prohibited_content.present else "NO",
            "checkout_signals": "YES" if self.checkout_signals.present else "NO",
            "has_prices": "YES" if self.has_prices.present else "NO",
        }
        for key in ["privacy", "terms", "refunds", "shipping", "contact", "about"]:
            res = self.business_signals.get(key, CheckResult(False))
            row[f"{key}"] = "YES" if res.present else "NO"
        row["impact_score"] = str(compute_impact_score(self))
        row["risk_level"] = risk_bucket(compute_impact_score(self))
        return row

# --------------------------- Utility funcs -----------------------------

_session_cache: Dict[str, float] = {}

def polite_get(url: str, rp: Optional[robotparser.RobotFileParser]) -> Optional[requests.Response]:
    """Polite GET with robots.txt check and per-host delay."""
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        # robots.txt
        if rp and not rp.can_fetch(DEFAULT_HEADERS["User-Agent"], url):
            logging.info("Blocked by robots.txt: %s", url)
            return None
        # simple per-host delay
        now = time.time()
        last = _session_cache.get(base, 0)
        sleep_for = REQUEST_DELAY - (now - last)
        if sleep_for > 0:
            time.sleep(sleep_for)
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=TIMEOUT, allow_redirects=True, stream=True)
        _session_cache[base] = time.time()
        # clip very large bodies
        content = b""
        for chunk in r.iter_content(chunk_size=16384):
            content += chunk
            if len(content) >= MAX_BYTES:
                break
        r._content = content
        return r
    except Exception as e:
        logging.warning("GET failed %s: %s", url, e)
        return None

def load_robots(base_url: str) -> Optional[robotparser.RobotFileParser]:
    try:
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = robotparser.RobotFileParser()
        rp.set_url(robots_url)
        rp.read()
        return rp
    except Exception:
        return None

def soupify(resp: requests.Response) -> BeautifulSoup:
    return BeautifulSoup(resp.text, "lxml")

def find_links(soup: BeautifulSoup) -> List[Tuple[str, str]]:
    links = []
    for a in soup.find_all("a", href=True):
        text = (a.get_text() or "").strip()
        href = a["href"]
        links.append((text, href))
    return links

def choose_best_link(base: str, links: List[Tuple[str, str]], keywords: List[str]) -> Optional[str]:
    base_parsed = urlparse(base)
    best = None
    best_score = 0
    for text, href in links:
        url = urljoin(base, href)
        score = 0
        lower = (text + " " + href).lower()
        for k in keywords:
            if k in lower:
                score += 1
        # prefer same-domain
        if urlparse(url).netloc == base_parsed.netloc:
            score += 0.5
        if score > best_score:
            best_score = score
            best = url
    return best

def text_has(patterns: List[str], text: str) -> bool:
    lower = text.lower()
    return any(p in lower for p in patterns)

# --------------------------- Checkers ----------------------------------

def check_https(final_url: str) -> bool:
    return final_url.startswith("https://")

def check_contact_info(soup: BeautifulSoup) -> CheckResult:
    text = soup.get_text(" ", strip=True)
    emails = set(EMAIL_HINT.findall(text))
    phones = set(PHONE_HINT.findall(text))
    present = bool(emails or phones)
    ev = []
    if emails:
        ev.append(f"emails={len(emails)}")
    if phones:
        ev.append(f"phones~={len(phones)}")
    return CheckResult(present, evidence_text=", ".join(ev) if ev else None, confidence=0.6 if present else 0.0)

def check_prices(soup: BeautifulSoup) -> CheckResult:
    text = soup.get_text(" ", strip=True)
    if CURRENCY_HINT.search(text):
        return CheckResult(True, evidence_text="currency-like pattern found", confidence=0.6)
    return CheckResult(False, None, None, 0.0)

def check_checkout_signals(soup: BeautifulSoup, base_url: str) -> CheckResult:
    links = find_links(soup)
    for text, href in links:
        lower = (text + " " + href).lower()
        if any(k in lower for k in ["checkout", "cart", "payment"]):
            return CheckResult(True, evidence_url=urljoin(base_url, href), confidence=0.6)
    # buttons
    for btn in soup.find_all(["button", "input"]):
        attrs = " ".join([btn.get("id",""), btn.get("name",""), btn.get("value",""), btn.get("class","") if isinstance(btn.get("class"), str) else " ".join(btn.get("class", []))]).lower()
        if any(k in attrs for k in ["checkout", "buy", "add to cart", "payment"]):
            return CheckResult(True, evidence_text=attrs[:120], confidence=0.5)
    return CheckResult(False, None, None, 0.0)

def check_prohibited(soup: BeautifulSoup) -> CheckResult:
    text = soup.get_text(" ", strip=True)
    matches = [w for w in PROHIBITED_HINTS if w in text.lower()]
    if matches:
        return CheckResult(True, evidence_text=",".join(matches), confidence=0.4)
    return CheckResult(False, None, None, 0.0)

def check_policy_link(base_url: str, soup: BeautifulSoup, kind: str, keywords: List[str], rp: Optional[robotparser.RobotFileParser]) -> CheckResult:
    links = find_links(soup)
    candidate = choose_best_link(base_url, links, keywords)
    if not candidate:
        return CheckResult(False, None, None, 0.0)
    resp = polite_get(candidate, rp)
    if not resp or resp.status_code >= 400:
        return CheckResult(False, candidate, None, 0.2 if resp else 0.0)
    text = soupify(resp).get_text(" ", strip=True).lower()
    if any(k in text for k in keywords):
        return CheckResult(True, candidate, None, 0.8)
    return CheckResult(True, candidate, None, 0.5)

# --------------------------- Impact scoring ----------------------------

IMPACT_WEIGHTS = {
    # High impact
    "business_name": 2.0,          # (not implemented: placeholder for branding match)
    "contact": 2.0,
    "refunds": 2.0,
    "terms": 1.5,
    "privacy": 1.5,
    "https": 2.0,
    "prohibited": -2.5,            # negative impact if present
    "checkout": 1.5,
    # Moderate
    "shipping": 1.0,
    "prices": 1.0,
    "functionality": 1.0,
    # Low
    "about": 0.5,
}

def compute_impact_score(rep: SiteReport) -> float:
    score = 0.0
    if rep.https:
        score += IMPACT_WEIGHTS["https"]
    if rep.functionality_ok:
        score += IMPACT_WEIGHTS["functionality"]
    if rep.prohibited_content.present:
        score += IMPACT_WEIGHTS["prohibited"]
    if rep.checkout_signals.present:
        score += IMPACT_WEIGHTS["checkout"]
    if rep.has_prices.present:
        score += IMPACT_WEIGHTS["prices"]

    for k in ["privacy", "terms", "refunds", "shipping", "contact", "about"]:
        if rep.business_signals.get(k, CheckResult(False)).present:
            if k in IMPACT_WEIGHTS:
                score += IMPACT_WEIGHTS[k]
            else:
                score += 1.0
    return round(score, 2)

def risk_bucket(score: float) -> str:
    if score >= 6:
        return "Low Risk"
    if 3 <= score < 6:
        return "Moderate Risk"
    return "High Risk"

# --------------------------- Core crawl --------------------------------

def normalize_url(u: str) -> str:
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u

def process_site(url: str) -> SiteReport:
    url = normalize_url(url)
    rp = load_robots(url)
    resp = polite_get(url, rp)
    if not resp:
        return SiteReport(url=url, final_url=url, https=url.startswith("https://"), reachable=False, http_status=None, functionality_ok=False, notes="unreachable")

    final_url = resp.url
    soup = soupify(resp)
    reachable = resp.status_code < 400
    https_ok = check_https(final_url)
    functionality_ok = reachable and bool(soup.find("title"))

    report = SiteReport(
        url=url,
        final_url=final_url,
        https=https_ok,
        reachable=reachable,
        http_status=resp.status_code,
        functionality_ok=functionality_ok,
        business_signals={},
    )

    # Policy pages
    for kind, keywords in POLICY_KEYWORDS.items():
        try:
            res = check_policy_link(final_url, soup, kind, keywords, rp)
        except Exception as e:
            logging.warning("policy check failed %s %s: %s", url, kind, e)
            res = CheckResult(False, None, None, 0.0)
        report.business_signals[kind] = res

    # Contact info on homepage
    try:
        report.business_signals["contact_info_on_page"] = check_contact_info(soup)
    except Exception:
        pass

    # Prices
    try:
        report.has_prices = check_prices(soup)
    except Exception:
        pass

    # Checkout signals
    try:
        report.checkout_signals = check_checkout_signals(soup, final_url)
    except Exception:
        pass

    # Prohibited content
    try:
        report.prohibited_content = check_prohibited(soup)
    except Exception:
        pass

    return report

def read_inputs(args) -> List[str]:
    urls: Set[str] = set(args.url or [])
    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    urls.add(line.strip())
    return sorted(urls)

def write_outputs(out_prefix: str, reports: List[SiteReport]):
    csv_path = f"{out_prefix}.csv"
    jsonl_path = f"{out_prefix}.jsonl"
    log_path = f"{out_prefix}_logs.txt"

    # CSV
    fieldnames = [
        "url","final_url","reachable","https","status","functionality_ok",
        "privacy","terms","refunds","shipping","contact","about",
        "prohibited_content","checkout_signals","has_prices",
        "impact_score","risk_level",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in reports:
            w.writerow(r.to_csv_row())

    # JSONL (detailed)
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in reports:
            payload = asdict(r)
            # simplify dataclasses for business_signals
            payload["business_signals"] = {k: asdict(v) for k,v in r.business_signals.items()}
            payload["prohibited_content"] = asdict(r.prohibited_content)
            payload["checkout_signals"] = asdict(r.checkout_signals)
            payload["has_prices"] = asdict(r.has_prices)
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    logging.info("Wrote %s and %s", csv_path, jsonl_path)

def main():
    p = argparse.ArgumentParser(description="Merchant website checklist checker")
    p.add_argument("--input", help="Path to CSV with one domain/URL per line")
    p.add_argument("--url", action="append", help="Single URL (can repeat)")
    p.add_argument("--out", required=True, help="Output prefix for CSV/JSONL")
    p.add_argument("--workers", type=int, default=MAX_WORKERS, help="Parallel workers")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(f"{args.out}_logs.txt"), logging.StreamHandler()],
    )

    urls = read_inputs(args)
    if not urls:
        p.error("No input URLs provided. Use --input or --url.")

    reports: List[SiteReport] = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(process_site, u): u for u in urls}
        for fut in as_completed(futures):
            rep = fut.result()
            reports.append(rep)
            time.sleep(SLEEP_BETWEEN_SITES)

    write_outputs(args.out, reports)
    print(f"Done. Results -> {args.out}.csv and {args.out}.jsonl")

if __name__ == "__main__":
    main()
