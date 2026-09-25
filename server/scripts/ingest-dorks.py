#!/usr/bin/env python3
"""Ingest four community Shodan dork sources → server/data/dorks.json"""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "dorks.json"

FILTER_RE = re.compile(
    r"\b(city|country|geo|hostname|net|org|asn|os|port|product|title|html|http\.title|"
    r"http\.html|server|ssl|device|has_screenshot|vuln|after|before|tag)\s*:",
    re.I,
)
BACKTICK_RE = re.compile(r"`([^`]+)`")

def normalize_query(q: str) -> str:
    return re.sub(r"\s+", " ", q.strip().strip("`").strip())

def is_queryish(s: str) -> bool:
    s = s.strip()
    if not s or len(s) < 3 or s.startswith("#"):
        return False
    if FILTER_RE.search(s) or (s.startswith('"') and len(s) > 4):
        return True
    if re.search(r'["\'].+["\']', s) and len(s.split()) <= 12:
        return True
    if re.match(r"^[A-Za-z0-9_\-\.\*\+/ :\"']{3,80}$", s) and len(s.split()) <= 8:
        if s.endswith(":") or (s[0].isupper() and s.endswith(".") and ":" not in s and '"' not in s):
            return False
        return True
    return False

def norm_category(cat: str) -> str:
    c = re.sub(r"\s+", " ", (cat or "miscellaneous").strip().lower())
    aliases = {
        "misc": "miscellaneous", "general": "miscellaneous", "random stuff": "miscellaneous",
        "ics": "ics-scada", "industrial control systems": "ics-scada", "scada and ics": "ics-scada",
        "webcam": "webcams", "web": "web-servers", "web server": "web-servers", "web servers": "web-servers",
        "database": "databases", "network infrastructure": "network",
        "basic shodan filters": "filters", "remote desktop": "remote-access",
        "c2 infrastructure": "c2", "network attached storage (nas)": "nas",
        "outlook web access:": "owa", "outlook web access": "owa",
        "printers & copiers:": "printers", "printers & copiers": "printers", "printer": "printers",
        "home devices": "iot-home", "television": "media", "operating system": "os",
        "router": "routers", "default credentials": "default-creds", "firewall": "network",
        "cms": "cms", "dns server": "dns", "server modules": "web-servers",
        "windows": "os", "common files": "web-servers", "languages": "miscellaneous",
        "zenworks": "administration",
    }
    return aliases.get(c, c.replace(" ", "-")[:40])

def make_id(source, category, title, query):
    return "dork_" + hashlib.sha1(f"{source}|{category}|{title}|{query}".encode()).hexdigest()[:12]

def add(entries, *, source, category, title, query, description="", tags=None):
    query = normalize_query(query)
    if not query or not is_queryish(query) or re.fullmatch(r"[a-zA-Z0-9_.]+:", query):
        return
    title = (title or query[:60]).strip().rstrip(":")
    category = norm_category(category)
    hay = f"{title} {query} {description}".lower()
    entries.append({
        "id": make_id(source, category, title, query),
        "source": source,
        "category": category,
        "title": title,
        "query": query,
        "description": (description or "").strip(),
        "tags": tags or [],
        "keywords": sorted(set(re.findall(r"[a-z0-9]{3,}", hay))),
    })

def parse_basic(path: Path):
    lines = [l.strip() for l in path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")]
    entries, category, i = [], "filters", 0
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1; continue
        if line.endswith(":"):
            title, desc, query = line[:-1].strip(), "", ""
            j = i + 1
            while j < len(lines) and not lines[j]: j += 1
            if j < len(lines):
                nxt = lines[j]
                if is_queryish(nxt) and not nxt.endswith(":"):
                    query, i = nxt, j + 1
                else:
                    desc, k = nxt, j + 1
                    while k < len(lines) and not lines[k]: k += 1
                    if k < len(lines) and is_queryish(lines[k]):
                        query, i = lines[k], k + 1
                    else:
                        i = j + 1
            else:
                i += 1
            tl = title.lower()
            if any(x in tl for x in ("cam", "webcam", "cctv", "dvr", "nvr", "surveillance")): category = "webcams"
            elif any(x in tl for x in ("scada", "ics", "plc", "modbus", "industrial", "fuel pump", "atm")): category = "ics-scada"
            elif any(x in tl for x in ("db", "mongo", "mysql", "elastic", "redis", "postgres")): category = "databases"
            elif any(x in tl for x in ("router", "cisco", "firewall", "vpn", "switch")): category = "network"
            elif any(x in tl for x in ("rdp", "vnc", "ssh", "telnet", "remote")): category = "remote-access"
            elif tl in {"city", "country", "geo", "hostname", "net", "os", "port", "org", "asn"}: category = "filters"
            else: category = "miscellaneous"
            if query:
                add(entries, source="lothos-basic", category=category, title=title, query=query, description=desc)
            continue
        if is_queryish(line):
            add(entries, source="lothos-basic", category=category, title=line[:50], query=line)
        i += 1
    return entries

def parse_md(path: Path):
    lines = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")
    entries, section, title, desc = [], "miscellaneous", "", []
    for raw in lines:
        line = raw.strip()
        if line.startswith("# ") and not line.startswith("##"):
            section, title, desc = line[2:].strip().rstrip(":"), "", []; continue
        if line.startswith("### "):
            title, desc = line[4:].strip().rstrip(":"), []; continue
        ticks = BACKTICK_RE.findall(line)
        if ticks:
            for q in ticks:
                add(entries, source="lothos-extended", category=section, title=title or q[:50], query=q, description=" ".join(desc))
            desc = []; continue
        if line and not line.startswith("#"):
            if title and not is_queryish(line):
                desc.append(line)
            elif is_queryish(line):
                add(entries, source="lothos-extended", category=section, title=title or line[:50], query=line, description=" ".join(desc))
                desc = []
    return entries

def parse_csv(path: Path):
    entries = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")):
        line = line.strip()
        if not line or (i == 0 and line.lower().startswith("vendor")): continue
        parts = line.split(";")
        if len(parts) < 4: continue
        vendor, product, comment, dork = [p.strip() for p in parts[:4]]
        add(entries, source="ics-scada-csv", category="ics-scada", title=f"{vendor} {product}".strip(),
            query=dork, description=comment, tags=[vendor.lower(), "ics", "scada"])
    return entries

def parse_admin(path: Path):
    entries = []
    for line in path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if not line: continue
        parts = line.split(";;")
        if len(parts) < 3: continue
        add(entries, source="admin-catalog", category=parts[0], title=parts[1].strip(),
            query=parts[2].strip(), tags=[parts[0].lower()])
    return entries

def dedupe(entries):
    seen, out = set(), []
    for e in entries:
        k = e["query"].lower()
        if k in seen: continue
        seen.add(k); out.append(e)
    return out

def main():
    all_e = dedupe(
        parse_basic(RAW / "01-lothos-basic.txt")
        + parse_md(RAW / "02-lothos-extended.md")
        + parse_csv(RAW / "03-ics-scada.csv")
        + parse_admin(RAW / "04-admin-catalog.txt")
    )
    cats = {}
    for e in all_e:
        cats[e["category"]] = cats.get(e["category"], 0) + 1
    payload = {
        "version": 1,
        "generated_from": ["01-lothos-basic.txt", "02-lothos-extended.md", "03-ics-scada.csv", "04-admin-catalog.txt"],
        "count": len(all_e),
        "categories": dict(sorted(cats.items(), key=lambda kv: (-kv[1], kv[0]))),
        "dorks": sorted(all_e, key=lambda e: (e["category"], e["title"].lower())),
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} ({payload['count']} dorks, {len(cats)} categories)")

if __name__ == "__main__":
    main()
