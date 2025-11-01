#!/usr/bin/env python3
"""
ai_driven_threat_intel.py

Terminal-based Threat Intelligence assistant:
- Queries VirusTotal, AbuseIPDB, AlienVault OTX based on indicator type
- Sends aggregated context to Together AI (Gemma model) for analysis
- Parses AI JSON response and prints it
- Optionally sends email report when requested

Environment variables (e.g. in a .env file read by your shell or via python-dotenv):
TOGETHER_API_KEY
VIRUSTOTAL_API_KEY
OTX_API_KEY
ABUSEIPDB_API_KEY

# Optional email settings
EMAIL_FROM
EMAIL_TO
SMTP_SERVER (e.g. smtp.gmail.com)
SMTP_PORT (e.g. 587)
SMTP_USE_TLS (True/False)
SMTP_USER (usually same as EMAIL_FROM)
SMTP_PASS (app password or SMTP password)
"""

import os
import re
import json
import requests
import smtplib
from email.mime.text import MIMEText
from typing import Dict, Any, Optional

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Using system environment variables only.")
    print("Install with: pip install python-dotenv")

# === Configuration from environment ===
TOGETHER_API_KEY = os.getenv("TOGETHER_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

EMAIL_FROM = os.getenv("EMAIL_FROM")
EMAIL_TO = os.getenv("EMAIL_TO")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "True").lower() in ("1", "true", "yes")
SMTP_USER = os.getenv("SMTP_USER", EMAIL_FROM)
SMTP_PASS = os.getenv("SMTP_PASS")

# === Constants ===
TIMEOUT = 15  # seconds for HTTP requests
HEADERS_VT = {"x-apikey": VIRUSTOTAL_API_KEY} if VIRUSTOTAL_API_KEY else {}
HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
HEADERS_ABUSE = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"} if ABUSEIPDB_API_KEY else {}

# === Helpers: API queries ===

def query_virustotal(indicator: str) -> Dict[str, Any]:
    """Query VirusTotal for a hash, domain or IP. Returns JSON or error info."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    # guess type
    if re.fullmatch(r"[A-Fa-f0-9]{32,64}", indicator):  # MD5/SHA1/SHA256-like
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", indicator):  # IPv4
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    try:
        r = requests.get(url, headers=HEADERS_VT, timeout=TIMEOUT)
        r.raise_for_status()
        return {"status_code": r.status_code, "raw": r.json() if r.content else {}}
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}

def extract_vt_file_details(vt_data: Dict[str, Any]) -> str:
    """Extract detailed file information from VirusTotal response for display."""
    if "error" in vt_data:
        return ""
    
    raw = vt_data.get("raw", {})
    if "data" not in raw:
        return ""
    
    attrs = raw["data"].get("attributes", {})
    details = []
    
    # Detection stats
    stats = attrs.get("last_analysis_stats", {})
    if stats:
        mal = stats.get('malicious', 0)
        sus = stats.get('suspicious', 0)
        total = mal + sus + stats.get('harmless', 0) + stats.get('undetected', 0)
        details.append(f"🚨 Detection: {mal}/{total} vendors flagged as malicious")
        if sus > 0:
            details.append(f"⚠️  Suspicious: {sus} vendors flagged as suspicious")
    
    # File type and size
    file_type = attrs.get('type_description', 'Unknown')
    size = attrs.get('size', 0)
    details.append(f"📄 File Type: {file_type}")
    details.append(f"💾 Size: {size:,} bytes ({size/1024/1024:.2f} MB)")
    
    # Hashes
    md5 = attrs.get('md5', 'N/A')
    sha1 = attrs.get('sha1', 'N/A')
    details.append(f"🔑 MD5: {md5}")
    details.append(f"🔑 SHA1: {sha1}")
    
    # File names
    names = attrs.get("names", [])
    if names:
        details.append(f"📝 Known Names: {', '.join(names[:3])}")
        if len(names) > 3:
            details.append(f"   (+{len(names)-3} more names)")
    
    # Threat classification
    popular_threat = attrs.get("popular_threat_classification", {})
    if popular_threat:
        label = popular_threat.get('suggested_threat_label', '')
        if label:
            details.append(f"🦠 Threat Label: {label}")
    
    # Signature info
    signature_info = attrs.get("signature_info", {})
    if signature_info:
        product = signature_info.get('product', '')
        description = signature_info.get('description', '')
        if product or description:
            details.append(f"✍️  Signed As: {product} - {description}")
    
    # Creation time
    creation_date = attrs.get("creation_date")
    if creation_date:
        from datetime import datetime
        dt = datetime.fromtimestamp(creation_date)
        details.append(f"📅 First Seen: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Last analysis date
    last_analysis = attrs.get("last_analysis_date")
    if last_analysis:
        from datetime import datetime
        dt = datetime.fromtimestamp(last_analysis)
        details.append(f"🔄 Last Analyzed: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return "\n   ".join(details) if details else ""

def query_abuseipdb(ip: str) -> Dict[str, Any]:
    """Check IP reputation at AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
    try:
        r = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return {"status_code": r.status_code, "raw": r.json() if r.content else {}}
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {e}"}

def extract_abuseipdb_details(abuse_data: Dict[str, Any]) -> str:
    """Extract detailed information from AbuseIPDB response for display."""
    if "error" in abuse_data:
        return ""
    
    raw = abuse_data.get("raw", {})
    if not raw:
        return ""
    
    data = raw.get("data", {})
    if not data:
        return ""
    
    details = []
    
    # Abuse Confidence Score
    confidence = data.get("abuseConfidenceScore", 0)
    if confidence >= 75:
        details.append(f"🚨 Abuse Confidence: {confidence}% (HIGH RISK)")
    elif confidence >= 50:
        details.append(f"⚠️  Abuse Confidence: {confidence}% (MEDIUM RISK)")
    elif confidence > 0:
        details.append(f"⚠️  Abuse Confidence: {confidence}% (LOW RISK)")
    else:
        details.append(f"✅ Abuse Confidence: {confidence}% (CLEAN)")
    
    # Report counts
    total_reports = data.get("totalReports", 0)
    num_distinct_users = data.get("numDistinctUsers", 0)
    details.append(f"📊 Total Reports: {total_reports} (from {num_distinct_users} distinct users)")
    
    # Last reported
    last_reported = data.get("lastReportedAt")
    if last_reported:
        details.append(f"🕐 Last Reported: {last_reported}")
    
    # IP Information
    ip_address = data.get("ipAddress", "")
    is_public = data.get("isPublic", False)
    ip_version = data.get("ipVersion", "")
    details.append(f"🌐 IP: {ip_address} (IPv{ip_version}, {'Public' if is_public else 'Private'})")
    
    # ISP and Network Info
    isp = data.get("isp", "")
    usage_type = data.get("usageType", "")
    domain = data.get("domain", "")
    if isp:
        details.append(f"🏢 ISP: {isp}")
    if usage_type:
        details.append(f"📡 Usage Type: {usage_type}")
    if domain:
        details.append(f"🔗 Domain: {domain}")
    
    # Geolocation
    country_code = data.get("countryCode", "")
    country_name = data.get("countryName", "")
    if country_name:
        details.append(f"🌍 Location: {country_name} ({country_code})")
    
    # Tor/Proxy Detection
    is_tor = data.get("isTor", False)
    is_whitelisted = data.get("isWhitelisted", False)
    if is_tor:
        details.append(f"🔴 Tor Exit Node: YES")
    if is_whitelisted:
        details.append(f"✅ Whitelisted: YES")
    
    # Hostnames
    hostnames = data.get("hostnames", [])
    if hostnames:
        details.append(f"🖥️  Hostnames: {', '.join(hostnames[:3])}")
        if len(hostnames) > 3:
            details.append(f"   ... and {len(hostnames) - 3} more")
    
    # Recent reports with categories
    reports = data.get("reports", [])
    if reports:
        details.append(f"\n📋 Recent Abuse Reports ({len(reports)} shown):")
        
        # Category mapping
        category_names = {
            3: "Fraud Orders",
            4: "DDoS Attack",
            5: "FTP Brute-Force",
            6: "Ping of Death",
            7: "Phishing",
            8: "Fraud VoIP",
            9: "Open Proxy",
            10: "Web Spam",
            11: "Email Spam",
            12: "Blog Spam",
            13: "VPN IP",
            14: "Port Scan",
            15: "Hacking",
            16: "SQL Injection",
            17: "Spoofing",
            18: "Brute-Force",
            19: "Bad Web Bot",
            20: "Exploited Host",
            21: "Web App Attack",
            22: "SSH",
            23: "IoT Targeted"
        }
        
        for i, report in enumerate(reports[:5], 1):
            reported_at = report.get("reportedAt", "")[:10]
            categories = report.get("categories", [])
            comment = report.get("comment", "")
            
            cat_names = [category_names.get(cat, f"Category {cat}") for cat in categories]
            details.append(f"   {i}. {reported_at} - {', '.join(cat_names)}")
            if comment:
                details.append(f"      Comment: {comment[:80]}...")
        
        if len(reports) > 5:
            details.append(f"   ... and {len(reports) - 5} more reports")
    
    return "\n   ".join(details) if details else ""

def query_otx(indicator: str) -> Dict[str, Any]:
    """Query AlienVault OTX for domain or IP (general info)."""
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}
    # choose endpoint: IPv4 or domain general
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", indicator):
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
    else:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
    try:
        r = requests.get(url, headers=HEADERS_OTX, timeout=TIMEOUT)
        r.raise_for_status()
        return {"status_code": r.status_code, "raw": r.json() if r.content else {}}
    except requests.exceptions.RequestException as e:
        return {"error": f"OTX request failed: {e}"}

def query_otx_detailed(indicator: str, indicator_type: str) -> Dict[str, Any]:
    """Query multiple OTX endpoints for comprehensive information."""
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}
    
    results = {}
    
    # Determine indicator type for OTX
    if indicator_type == "ip":
        base_type = "IPv4"
    elif indicator_type == "domain":
        base_type = "domain"
    elif indicator_type == "hash":
        base_type = "file"
    else:
        base_type = "domain"  # default
    
    # Query multiple endpoints
    endpoints = {
        "general": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/general",
        "reputation": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/reputation",
        "geo": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/geo",
        "malware": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/malware",
        "url_list": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/url_list",
        "passive_dns": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/passive_dns",
        "whois": f"https://otx.alienvault.com/api/v1/indicators/{base_type}/{indicator}/whois",
    }
    
    for name, url in endpoints.items():
        try:
            r = requests.get(url, headers=HEADERS_OTX, timeout=TIMEOUT)
            if r.status_code == 200:
                results[name] = r.json() if r.content else {}
            else:
                results[name] = {"error": f"Status {r.status_code}"}
        except requests.exceptions.RequestException as e:
            results[name] = {"error": str(e)}
    
    return {"status_code": 200, "raw": results}

def extract_otx_details(otx_data: Dict[str, Any]) -> str:
    """Extract detailed information from OTX response for display."""
    if "error" in otx_data:
        return ""
    
    raw = otx_data.get("raw", {})
    if not raw:
        return ""
    
    details = []
    
    # General information
    general = raw.get("general", {})
    if general and not isinstance(general, dict):
        general = {}
    
    # Pulse information
    pulse_info = general.get("pulse_info", {})
    pulses = pulse_info.get("pulses", [])
    pulse_count = len(pulses)
    
    if pulse_count > 0:
        details.append(f"🚨 Found in {pulse_count} threat pulse(s)")
        
        # Show top 3 pulses
        for i, pulse in enumerate(pulses[:3], 1):
            pulse_name = pulse.get("name", "Unknown")
            pulse_created = pulse.get("created", "")[:10]  # Date only
            pulse_tags = pulse.get("tags", [])
            details.append(f"   {i}. '{pulse_name}' (Created: {pulse_created})")
            if pulse_tags:
                details.append(f"      Tags: {', '.join(pulse_tags[:5])}")
        
        if pulse_count > 3:
            details.append(f"   ... and {pulse_count - 3} more pulses")
    else:
        details.append("✅ No threat pulses found")
    
    # Reputation data
    reputation = raw.get("reputation", {})
    if reputation and isinstance(reputation, dict):
        rep_score = reputation.get("reputation", 0)
        threat_score = reputation.get("threat_score", 0)
        if rep_score or threat_score:
            details.append(f"📊 Reputation Score: {rep_score}")
            details.append(f"⚠️  Threat Score: {threat_score}")
    
    # Geo information
    geo = raw.get("geo", {})
    if geo and isinstance(geo, dict):
        country = geo.get("country_name", "")
        city = geo.get("city", "")
        asn = geo.get("asn", "")
        if country or city:
            location = f"{city}, {country}" if city else country
            details.append(f"🌍 Location: {location}")
        if asn:
            details.append(f"🏢 ASN: {asn}")
    
    # Malware samples
    malware = raw.get("malware", {})
    if malware and isinstance(malware, dict):
        malware_data = malware.get("data", [])
        if malware_data:
            details.append(f"🦠 Associated Malware: {len(malware_data)} sample(s)")
            for i, sample in enumerate(malware_data[:3], 1):
                hash_val = sample.get("hash", "")[:16]
                detections = sample.get("detections", {})
                avast = detections.get("avast", "Unknown")
                details.append(f"   {i}. {hash_val}... - {avast}")
    
    # URL list
    url_list = raw.get("url_list", {})
    if url_list and isinstance(url_list, dict):
        urls = url_list.get("url_list", [])
        if urls:
            details.append(f"🔗 Associated URLs: {len(urls)} URL(s)")
            for i, url_data in enumerate(urls[:3], 1):
                url = url_data.get("url", "")
                details.append(f"   {i}. {url[:60]}...")
    
    # Passive DNS
    passive_dns = raw.get("passive_dns", {})
    if passive_dns and isinstance(passive_dns, dict):
        dns_records = passive_dns.get("passive_dns", [])
        if dns_records:
            details.append(f"🔍 Passive DNS: {len(dns_records)} record(s)")
            # Group by record type
            record_types = {}
            for record in dns_records:
                rec_type = record.get("record_type", "Unknown")
                record_types[rec_type] = record_types.get(rec_type, 0) + 1
            for rec_type, count in record_types.items():
                details.append(f"   • {rec_type}: {count} record(s)")
    
    # Validation info
    validation = general.get("validation", [])
    if validation:
        details.append(f"✓ Validation: {', '.join([v.get('name', '') for v in validation[:3]])}")
    
    # WHOIS information
    whois = raw.get("whois", {})
    if whois and isinstance(whois, dict):
        whois_data = whois.get("data", [])
        if whois_data:
            details.append(f"📋 WHOIS: {len(whois_data)} field(s) found")
            # Extract key WHOIS fields
            for record in whois_data:
                if isinstance(record, dict):
                    key = record.get("key", "")
                    name = record.get("name", "")
                    value = record.get("value", "")
                    if key and value:
                        # Show important fields
                        if any(field in key.lower() for field in ["email", "registrar", "creation", "expiration", "name", "org"]):
                            details.append(f"   • {name}: {value}")
    
    return "\n   ".join(details) if details else ""

def extract_all_otx_iocs(otx_data: Dict[str, Any]) -> Dict[str, list]:
    """Extract ALL IOCs from OTX data including emails, IPs, domains, hashes, URLs."""
    iocs = {
        "emails": [],
        "ips": [],
        "domains": [],
        "subdomains": [],
        "hashes": [],
        "urls": [],
        "file_paths": [],
        "registry_keys": [],
        "mutexes": []
    }
    
    if "error" in otx_data:
        return iocs
    
    raw = otx_data.get("raw", {})
    if not raw:
        return iocs
    
    # Extract from WHOIS data (emails are here!)
    whois = raw.get("whois", {})
    if isinstance(whois, dict):
        # Check for emails in WHOIS data array
        whois_data = whois.get("data", [])
        for record in whois_data:
            if isinstance(record, dict):
                key = record.get("key", "")
                value = record.get("value", "")
                
                # Extract emails from WHOIS
                if key and "email" in key.lower():
                    if value and "@" in value and value not in iocs["emails"]:
                        iocs["emails"].append(value)
                # Also check value field for email patterns
                elif value and "@" in value and "." in value:
                    # Simple email validation
                    if re.match(r"[^@]+@[^@]+\.[^@]+", value):
                        if value not in iocs["emails"]:
                            iocs["emails"].append(value)
    
    # Extract from general section
    general = raw.get("general", {})
    if isinstance(general, dict):
        # Get pulse indicators
        pulse_info = general.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        
        for pulse in pulses:
            indicators = pulse.get("indicators", [])
            for indicator in indicators:
                ind_type = indicator.get("type", "")
                ind_value = indicator.get("indicator", "")
                
                if ind_type == "email":
                    if ind_value and ind_value not in iocs["emails"]:
                        iocs["emails"].append(ind_value)
                elif ind_type in ["IPv4", "IPv6"]:
                    if ind_value and ind_value not in iocs["ips"]:
                        iocs["ips"].append(ind_value)
                elif ind_type == "domain":
                    if ind_value and ind_value not in iocs["domains"]:
                        iocs["domains"].append(ind_value)
                elif ind_type == "hostname":
                    if ind_value and ind_value not in iocs["subdomains"]:
                        iocs["subdomains"].append(ind_value)
                elif ind_type in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]:
                    if ind_value and ind_value not in iocs["hashes"]:
                        iocs["hashes"].append(ind_value)
                elif ind_type in ["URL", "URI"]:
                    if ind_value and ind_value not in iocs["urls"]:
                        iocs["urls"].append(ind_value)
                elif ind_type == "FilePath":
                    if ind_value and ind_value not in iocs["file_paths"]:
                        iocs["file_paths"].append(ind_value)
                elif ind_type == "RegistryKey":
                    if ind_value and ind_value not in iocs["registry_keys"]:
                        iocs["registry_keys"].append(ind_value)
                elif ind_type == "Mutex":
                    if ind_value and ind_value not in iocs["mutexes"]:
                        iocs["mutexes"].append(ind_value)
    
    # Extract from passive DNS
    passive_dns = raw.get("passive_dns", {})
    if isinstance(passive_dns, dict):
        dns_records = passive_dns.get("passive_dns", [])
        for record in dns_records:
            address = record.get("address", "")
            hostname = record.get("hostname", "")
            
            # Check if address is an IP
            if address and re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", address):
                if address not in iocs["ips"]:
                    iocs["ips"].append(address)
            
            # Add hostname as subdomain
            if hostname and hostname not in iocs["subdomains"]:
                iocs["subdomains"].append(hostname)
    
    # Extract from URL list
    url_list = raw.get("url_list", {})
    if isinstance(url_list, dict):
        urls = url_list.get("url_list", [])
        for url_data in urls:
            url = url_data.get("url", "")
            if url and url not in iocs["urls"]:
                iocs["urls"].append(url)
    
    # Extract from malware samples
    malware = raw.get("malware", {})
    if isinstance(malware, dict):
        malware_data = malware.get("data", [])
        for sample in malware_data:
            hash_val = sample.get("hash", "")
            if hash_val and hash_val not in iocs["hashes"]:
                iocs["hashes"].append(hash_val)
    
    return iocs

# === Together AI call + JSON-extraction logic (mirrors your Apps Script) ===

def call_together_ai_with_context(prompt: str) -> Dict[str, Any]:
    """
    Calls Together AI chat/completions with model google/gemma-3n-E4B-it.
    Attempts to extract a JSON block (```json ... ``` or array/object) from the reply
    and returns parsed JSON plus raw reply.
    """
    if not TOGETHER_API_KEY:
        return {"error": "TOGETHER_API_KEY not set", "vulns": [], "raw": ""}

    url = "https://api.together.xyz/v1/chat/completions"
    headers = {"Authorization": f"Bearer {TOGETHER_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "google/gemma-3n-E4B-it",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0
    }
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        resp = r.json()
        reply = resp.get("choices", [{}])[0].get("message", {}).get("content", "")
        print("\n--- Together AI Raw Reply ---\n", reply)

        # Try to extract JSON inside ```json ... ``` first
        m = re.search(r"```json\s*([\s\S]*?)```", reply, re.IGNORECASE)
        if not m:
            # fallback: any JSON object or array in the reply
            m = re.search(r"({[\s\S]*?}|\[\s*{[\s\S]*}\s*\])", reply)

        if not m:
            return {"error": "No JSON found in Together AI reply", "raw": reply, "vulns": []}

        json_text = m.group(1)
        parsed = json.loads(json_text)
        # normalize: if parsed is array of vuln objects, keep; otherwise wrap/listify
        vulnerabilities = []
        if isinstance(parsed, list):
            for v in parsed:
                if isinstance(v, dict):
                    vulnerabilities.append({
                        "severity": v.get("Severity") or v.get("severity") or "",
                        "description": v.get("Description") or v.get("description") or "",
                        "mitigation": v.get("Mitigation") or v.get("mitigation") or "",
                        "cvss": v.get("CVSS Score") or v.get("cvss") or "",
                        "affected": v.get("Affected Version Range") or v.get("affected") or "",
                        "source": "Together AI"
                    })
        elif isinstance(parsed, dict):
            # accept dict summary -> place into a single-item list
            vulnerabilities.append(parsed)
        else:
            # unexpected structure
            return {"error": "Parsed JSON has unexpected structure", "raw": reply, "vulns": []}

        return {"vulns": vulnerabilities, "raw": reply}

    except requests.exceptions.RequestException as e:
        return {"error": f"Together AI request failed: {e}", "vulns": [], "raw": ""}
    except json.JSONDecodeError as e:
        return {"error": f"Together AI JSON parse failed: {e}", "vulns": [], "raw": reply if 'reply' in locals() else ""}

# === Email function ===

def send_email(subject: str, html_body: str) -> bool:
    """Send an HTML email using SMTP settings from env. Returns True on success."""
    if not (SMTP_USER and SMTP_PASS and EMAIL_FROM and EMAIL_TO):
        print("Email settings not fully configured in environment.")
        return False
    try:
        msg = MIMEText(html_body, "html")
        msg["Subject"] = subject
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as server:
            if SMTP_USE_TLS:
                server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        return True
    except smtplib.SMTPException as e:
        print("Failed to send email (SMTP error):", e)
        return False
    except Exception as e:
        print("Failed to send email:", e)
        return False

# === Utility: build prompt for Together AI from gathered intel ===

def build_context_prompt(indicator: str, gathered: Dict[str, Any]) -> str:
    """
    Construct a prompt for Together AI that includes the gathered raw API outputs
    and asks for a JSON-formatted assessment. We request a JSON array of objects
    (or a JSON object) with fields: Verdict, Score (0-100), Summary, RecommendedActions, References.
    """
    lines = [
        f"You are a cybersecurity analyst. Analyze the following indicator: {indicator}",
        "",
        "Here are raw intelligence results from multiple sources (JSON).",
        ""
    ]
    for name, payload in gathered.items():
        try:
            # Limit payload size to prevent token overflow
            pretty = json.dumps(payload, indent=2, default=str)
            # Truncate if too large (keep first 3000 chars)
            if len(pretty) > 3000:
                pretty = pretty[:3000] + "\n... [truncated for brevity]"
        except Exception:
            pretty = str(payload)[:3000]
        lines.append(f"--- {name} ---\n{pretty}\n")

    # Extract IOCs from OTX if available
    otx_iocs_summary = ""
    if "OTX" in gathered:
        all_iocs = extract_all_otx_iocs(gathered["OTX"])
        ioc_counts = []
        if all_iocs["emails"]:
            ioc_counts.append(f"{len(all_iocs['emails'])} emails")
        if all_iocs["ips"]:
            ioc_counts.append(f"{len(all_iocs['ips'])} IPs")
        if all_iocs["subdomains"]:
            ioc_counts.append(f"{len(all_iocs['subdomains'])} subdomains")
        if all_iocs["hashes"]:
            ioc_counts.append(f"{len(all_iocs['hashes'])} hashes")
        if all_iocs["urls"]:
            ioc_counts.append(f"{len(all_iocs['urls'])} URLs")
        
        if ioc_counts:
            otx_iocs_summary = f"\n\nOTX IOCs Found: {', '.join(ioc_counts)}\n"
            otx_iocs_summary += f"Sample IOCs:\n"
            if all_iocs["emails"]:
                otx_iocs_summary += f"- Emails: {', '.join(all_iocs['emails'][:3])}\n"
            if all_iocs["ips"]:
                otx_iocs_summary += f"- IPs: {', '.join(all_iocs['ips'][:3])}\n"
            if all_iocs["subdomains"]:
                otx_iocs_summary += f"- Subdomains: {', '.join(all_iocs['subdomains'][:3])}\n"
    
    lines.append(otx_iocs_summary)
    
    lines.append(
        "Based on these results, provide a detailed JSON object (or a JSON array with one object) with keys:\n"
        '  "Verdict": one of ["Malicious","Suspicious","Benign"],\n'
        '  "Score": integer 0-100 (higher = more malicious, 0 = completely safe),\n'
        '  "Summary": detailed explanation (2-3 sentences) about the threat level and why,\n'
        '  "RecommendedActions": list of specific, actionable mitigation steps. For malicious findings, include:\n'
        '    - Immediate containment actions (e.g., "Block IP at firewall", "Quarantine file immediately")\n'
        '    - Investigation steps (e.g., "Check for lateral movement", "Review access logs")\n'
        '    - Remediation steps (e.g., "Run full antivirus scan", "Reset compromised credentials")\n'
        '    - Prevention measures (e.g., "Update security policies", "Enable EDR monitoring")\n'
        '  "ThreatType": if malicious/suspicious, specify the type (e.g., "Malware", "Phishing", "C2 Server", "Botnet"),\n'
        '  "IOCs": list ALL related indicators including emails, IPs, domains, subdomains, hashes, URLs found in the data,\n'
        '  "References": list of specific source URLs or citations (e.g., "VirusTotal: https://...", "AbuseIPDB Report", "OTX Pulse: [name]").\n\n'
        "IMPORTANT: For malicious or suspicious verdicts, provide comprehensive mitigation steps with specific technical actions.\n"
        "IMPORTANT: Include ALL IOCs found in the data, especially emails, subdomains, and related infrastructure.\n"
        "Return ONLY JSON. If you include code fences, ensure it's ```json <...> ```."
    )
    return "\n".join(lines)

# === Main CLI ===

def detect_type(ind: str) -> str:
    """Return 'hash' | 'ip' | 'domain' based on simple heuristics."""
    ind = ind.strip()
    if re.fullmatch(r"[A-Fa-f0-9]{32,64}", ind):
        return "hash"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ind):
        return "ip"
    # crude domain detection
    if "." in ind:
        return "domain"
    return "unknown"

def extract_indicators_from_query(query: str) -> list:
    """Extract IPs, domains, and hashes from natural language query."""
    indicators = []
    
    # Extract IPs
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ips = re.findall(ip_pattern, query)
    indicators.extend([{"value": ip, "type": "ip"} for ip in ips])
    
    # Extract hashes (MD5, SHA1, SHA256)
    hash_pattern = r'\b[A-Fa-f0-9]{32,64}\b'
    hashes = re.findall(hash_pattern, query)
    indicators.extend([{"value": h, "type": "hash"} for h in hashes])
    
    # Extract domains (basic pattern)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, query)
    # Filter out already found IPs
    domains = [d for d in domains if d not in ips]
    indicators.extend([{"value": d, "type": "domain"} for d in domains])
    
    return indicators

def parse_user_intent(query: str) -> Dict[str, Any]:
    """Parse user query to understand intent and which services to use."""
    query_lower = query.lower()
    
    intent = {
        "use_virustotal": True,
        "use_abuseipdb": True,
        "use_otx": True,
        "query_type": "general"
    }
    
    # Check for specific service mentions
    if "virustotal" in query_lower or "vt" in query_lower:
        intent["use_virustotal"] = True
        intent["use_abuseipdb"] = False
        intent["use_otx"] = False
        intent["query_type"] = "virustotal_only"
    
    if "abuseipdb" in query_lower or "abuse" in query_lower:
        intent["use_abuseipdb"] = True
        if intent["query_type"] == "general":
            intent["use_virustotal"] = False
            intent["use_otx"] = False
            intent["query_type"] = "abuseipdb_only"
    
    if "otx" in query_lower or "alienvault" in query_lower:
        intent["use_otx"] = True
        if intent["query_type"] == "general":
            intent["use_virustotal"] = False
            intent["use_abuseipdb"] = False
            intent["query_type"] = "otx_only"
    
    # Check for email-related queries
    if "email" in query_lower or "contact" in query_lower or "whois" in query_lower:
        intent["include_whois"] = True
    else:
        intent["include_whois"] = False
    
    return intent

def query_whois_info(domain: str) -> Dict[str, Any]:
    """Query basic WHOIS-like information from OTX for a domain."""
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}
    
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/whois"
    try:
        r = requests.get(url, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=TIMEOUT)
        r.raise_for_status()
        return {"status_code": r.status_code, "raw": r.json() if r.content else {}}
    except requests.exceptions.RequestException as e:
        return {"error": f"OTX WHOIS request failed: {e}"}

def format_whois_response(whois_data: Dict[str, Any]) -> str:
    """Format WHOIS data into readable text."""
    if "error" in whois_data:
        return f"WHOIS Error: {whois_data['error']}"
    
    raw = whois_data.get("raw", {})
    if not raw:
        return "No WHOIS data available"
    
    result = []
    if "registrant_email" in raw:
        result.append(f"Registrant Email: {raw['registrant_email']}")
    if "admin_email" in raw:
        result.append(f"Admin Email: {raw['admin_email']}")
    if "tech_email" in raw:
        result.append(f"Tech Email: {raw['tech_email']}")
    if "registrar" in raw:
        result.append(f"Registrar: {raw['registrar']}")
    if "creation_date" in raw:
        result.append(f"Created: {raw['creation_date']}")
    if "expiration_date" in raw:
        result.append(f"Expires: {raw['expiration_date']}")
    
    return "\n".join(result) if result else "Limited WHOIS information available"

def pretty_print_vulns(vulns):
    if not vulns:
        print("⚠️ No structured assessment available from AI.")
        return
    
    try:
        if isinstance(vulns, list) and len(vulns) > 0:
            assessment = vulns[0]
            
            # Extract key fields
            verdict = assessment.get("Verdict") or assessment.get("verdict", "Unknown")
            score = assessment.get("Score") or assessment.get("score", 0)
            summary = assessment.get("Summary") or assessment.get("summary", "No summary available")
            actions = assessment.get("RecommendedActions") or assessment.get("recommendedActions", [])
            references = assessment.get("References") or assessment.get("references", [])
            threat_type = assessment.get("ThreatType") or assessment.get("threatType", None)
            iocs = assessment.get("IOCs") or assessment.get("iocs", [])
            
            # Verdict with emoji and color coding
            verdict_emoji = "🚨" if verdict.lower() == "malicious" else "⚠️" if verdict.lower() == "suspicious" else "✅"
            
            # Risk level description
            if score >= 80:
                risk_level = "CRITICAL"
            elif score >= 60:
                risk_level = "HIGH"
            elif score >= 40:
                risk_level = "MEDIUM"
            elif score >= 20:
                risk_level = "LOW"
            else:
                risk_level = "MINIMAL"
            
            print(f"\n{verdict_emoji} Verdict: {verdict.upper()}")
            print(f"📊 Risk Score: {score}/100 ({risk_level} RISK)")
            
            if threat_type:
                print(f"🔍 Threat Type: {threat_type}")
            
            print(f"\n📝 Summary:")
            print(f"   {summary}")
            
            if iocs:
                print(f"\n🔴 Related Indicators of Compromise (IOCs):")
                if isinstance(iocs, list):
                    for ioc in iocs:
                        print(f"   • {ioc}")
                else:
                    print(f"   • {iocs}")
            
            if actions:
                print(f"\n🎯 Recommended Mitigation Actions:")
                if isinstance(actions, list):
                    for i, action in enumerate(actions, 1):
                        print(f"   {i}. {action}")
                else:
                    print(f"   • {actions}")
                
                # Add urgency note for high-risk findings
                if score >= 60:
                    print(f"\n   ⚠️  URGENT: Immediate action required due to {risk_level} risk level!")
            
            if references:
                print(f"\n📚 References & Citations:")
                if isinstance(references, list):
                    for ref in references:
                        print(f"   • {ref}")
                else:
                    print(f"   • {references}")
        else:
            # Fallback to JSON
            print("\n📄 Full Assessment:")
            print(json.dumps(vulns, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"\n⚠️ Error formatting assessment: {e}")
        print(json.dumps(vulns, indent=2, ensure_ascii=False))

def generate_beautiful_email(indicator: str, indicator_type: str, gathered: Dict[str, Any], ai_output: Dict[str, Any]) -> str:
    """Generate a beautiful, professional HTML email report."""
    from datetime import datetime
    
    # Determine verdict color and icon
    verdict = "Unknown"
    verdict_color = "#6c757d"
    verdict_icon = "⚠️"
    score = 0
    
    if ai_output.get("vulns"):
        vulns = ai_output["vulns"]
        if isinstance(vulns, list) and len(vulns) > 0:
            first = vulns[0]
            verdict = first.get("Verdict") or first.get("verdict", "Unknown")
            score = first.get("Score") or first.get("score", 0)
    
    if verdict.lower() == "malicious":
        verdict_color = "#dc3545"
        verdict_icon = "🚨"
    elif verdict.lower() == "suspicious":
        verdict_color = "#ffc107"
        verdict_icon = "⚠️"
    elif verdict.lower() == "benign":
        verdict_color = "#28a745"
        verdict_icon = "✅"
    
    # Extract detailed info from each source
    vt_stats = {}
    abuse_score = "N/A"
    otx_pulses = 0
    
    if "VirusTotal" in gathered and "raw" in gathered["VirusTotal"]:
        vt_raw = gathered["VirusTotal"]["raw"]
        if isinstance(vt_raw, dict) and "data" in vt_raw:
            attrs = vt_raw.get("data", {}).get("attributes", {})
            vt_stats = attrs.get("last_analysis_stats", {})
    
    if "AbuseIPDB" in gathered and "raw" in gathered["AbuseIPDB"]:
        abuse_raw = gathered["AbuseIPDB"]["raw"]
        if isinstance(abuse_raw, dict) and "data" in abuse_raw:
            abuse_score = abuse_raw["data"].get("abuseConfidenceScore", "N/A")
    
    if "OTX" in gathered and "raw" in gathered["OTX"]:
        otx_raw = gathered["OTX"]["raw"]
        if isinstance(otx_raw, dict):
            otx_pulses = len(otx_raw.get("pulse_info", {}).get("pulses", []))
    
    # Build HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: 600;
            }}
            .header p {{
                margin: 10px 0 0 0;
                opacity: 0.9;
                font-size: 14px;
            }}
            .verdict-section {{
                background-color: {verdict_color};
                color: white;
                padding: 25px;
                text-align: center;
                font-size: 24px;
                font-weight: bold;
            }}
            .indicator-box {{
                background-color: #f8f9fa;
                border-left: 4px solid #667eea;
                padding: 20px;
                margin: 20px;
                border-radius: 4px;
            }}
            .indicator-box h2 {{
                margin: 0 0 10px 0;
                color: #667eea;
                font-size: 18px;
            }}
            .indicator-value {{
                font-family: 'Courier New', monospace;
                font-size: 20px;
                color: #333;
                word-break: break-all;
                background-color: white;
                padding: 10px;
                border-radius: 4px;
                margin-top: 10px;
            }}
            .section {{
                padding: 20px;
                border-bottom: 1px solid #e9ecef;
            }}
            .section:last-child {{
                border-bottom: none;
            }}
            .section h3 {{
                color: #495057;
                margin: 0 0 15px 0;
                font-size: 18px;
                display: flex;
                align-items: center;
            }}
            .section h3::before {{
                content: '▶';
                color: #667eea;
                margin-right: 10px;
                font-size: 14px;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }}
            .stat-card {{
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 6px;
                border-left: 3px solid #667eea;
            }}
            .stat-label {{
                font-size: 12px;
                color: #6c757d;
                text-transform: uppercase;
                font-weight: 600;
                margin-bottom: 5px;
            }}
            .stat-value {{
                font-size: 24px;
                font-weight: bold;
                color: #333;
            }}
            .stat-value.danger {{
                color: #dc3545;
            }}
            .stat-value.warning {{
                color: #ffc107;
            }}
            .stat-value.success {{
                color: #28a745;
            }}
            .detail-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            .detail-table th {{
                background-color: #f8f9fa;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #495057;
                border-bottom: 2px solid #dee2e6;
            }}
            .detail-table td {{
                padding: 12px;
                border-bottom: 1px solid #dee2e6;
            }}
            .detail-table tr:last-child td {{
                border-bottom: none;
            }}
            .badge {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .badge-danger {{
                background-color: #dc3545;
                color: white;
            }}
            .badge-warning {{
                background-color: #ffc107;
                color: #333;
            }}
            .badge-success {{
                background-color: #28a745;
                color: white;
            }}
            .badge-info {{
                background-color: #17a2b8;
                color: white;
            }}
            .ai-summary {{
                background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
                padding: 20px;
                border-radius: 6px;
                margin-top: 15px;
            }}
            .ai-summary p {{
                margin: 10px 0;
                line-height: 1.8;
            }}
            .recommendations {{
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin-top: 15px;
                border-radius: 4px;
            }}
            .recommendations ul {{
                margin: 10px 0;
                padding-left: 20px;
            }}
            .recommendations li {{
                margin: 8px 0;
            }}
            .footer {{
                background-color: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                font-size: 12px;
            }}
            .json-data {{
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 15px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                overflow-x: auto;
                max-height: 400px;
                overflow-y: auto;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Threat Intelligence Report</h1>
                <p>Generated on {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
            </div>
            
            <div class="verdict-section">
                {verdict_icon} {verdict.upper()} - Risk Score: {score}/100
            </div>
            
            <div class="indicator-box">
                <h2>Analyzed Indicator</h2>
                <div class="stat-label">Type: <span class="badge badge-info">{indicator_type.upper()}</span></div>
                <div class="indicator-value">{indicator}</div>
            </div>
    """
    
    # VirusTotal Section
    if vt_stats:
        html += f"""
            <div class="section">
                <h3>VirusTotal Analysis</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Malicious</div>
                        <div class="stat-value danger">{vt_stats.get('malicious', 0)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Suspicious</div>
                        <div class="stat-value warning">{vt_stats.get('suspicious', 0)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Harmless</div>
                        <div class="stat-value success">{vt_stats.get('harmless', 0)}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Undetected</div>
                        <div class="stat-value">{vt_stats.get('undetected', 0)}</div>
                    </div>
                </div>
            </div>
        """
    
    # AbuseIPDB Section
    if indicator_type == "ip":
        html += f"""
            <div class="section">
                <h3>AbuseIPDB Reputation</h3>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Abuse Confidence Score</div>
                        <div class="stat-value {'danger' if isinstance(abuse_score, (int, float)) and abuse_score > 50 else 'warning' if isinstance(abuse_score, (int, float)) and abuse_score > 0 else 'success'}">{abuse_score}%</div>
                    </div>
                </div>
            </div>
        """
    
    # OTX Section
    html += f"""
        <div class="section">
            <h3>AlienVault OTX Intelligence</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-label">Threat Pulses</div>
                    <div class="stat-value {'danger' if otx_pulses > 5 else 'warning' if otx_pulses > 0 else 'success'}">{otx_pulses}</div>
                </div>
            </div>
        </div>
    """
    
    # AI Assessment Section
    if ai_output.get("vulns"):
        vulns = ai_output["vulns"]
        if isinstance(vulns, list) and len(vulns) > 0:
            first = vulns[0]
            summary = first.get("Summary") or first.get("summary", "No summary available")
            actions = first.get("RecommendedActions") or first.get("recommendedActions", [])
            references = first.get("References") or first.get("references", [])
            
            html += f"""
            <div class="section">
                <h3>AI-Powered Assessment</h3>
                <div class="ai-summary">
                    <strong>Summary:</strong>
                    <p>{summary}</p>
                </div>
            """
            
            if actions:
                html += """
                <div class="recommendations">
                    <strong>🎯 Recommended Actions:</strong>
                    <ul>
                """
                if isinstance(actions, list):
                    for action in actions:
                        html += f"<li>{action}</li>"
                else:
                    html += f"<li>{actions}</li>"
                html += """
                    </ul>
                </div>
                """
            
            if references:
                html += """
                <div style="margin-top: 15px;">
                    <strong>📚 References:</strong>
                    <ul>
                """
                if isinstance(references, list):
                    for ref in references:
                        html += f"<li>{ref}</li>"
                else:
                    html += f"<li>{references}</li>"
                html += """
                    </ul>
                </div>
                """
            
            html += "</div>"
    
    # Raw Data Section (collapsible)
    html += f"""
        <div class="section">
            <h3>Raw Intelligence Data</h3>
            <details>
                <summary style="cursor: pointer; color: #667eea; font-weight: 600;">Click to view raw JSON data</summary>
                <div class="json-data">
                    <strong>Gathered Data:</strong>
                    <pre>{json.dumps(gathered, indent=2, default=str)}</pre>
                    <br>
                    <strong>AI Output:</strong>
                    <pre>{json.dumps(ai_output, indent=2, default=str)}</pre>
                </div>
            </details>
        </div>
    """
    
    # Footer
    html += f"""
            <div class="footer">
                <p>This report was automatically generated by AI Threat Intelligence CLI</p>
                <p>Powered by VirusTotal, AbuseIPDB, AlienVault OTX, and Together AI</p>
                <p style="margin-top: 10px; font-size: 10px;">
                    ⚠️ This analysis is provided for informational purposes only. 
                    Always verify findings with additional sources before taking action.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html

def main():
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║   🔒 AI Threat Intelligence Assistant                         ║")
    print("║   Powered by VirusTotal, AbuseIPDB, AlienVault OTX & AI      ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print("\n👋 Hello! I'm your AI-powered threat intelligence assistant.")
    print("💬 Ask me anything about IPs, domains, or file hashes!\n")
    print("Examples:")
    print("  • 'Check if 8.8.8.8 is malicious'")
    print("  • 'Analyze domain google.com with VirusTotal'")
    print("  • 'Show me email for domain valeo.com using OTX'")
    print("  • 'Is this hash safe: 44d88612fea8a8f36de82e1278abb02f'")
    print("\nType 'exit' or 'quit' to leave.\n")
    print("─" * 64)

    while True:
        try:
            query = input("\n🔍 Your query: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Goodbye! Stay safe out there!")
            break
        
        if not query:
            continue
        
        if query.lower() in ("exit", "quit", "bye", "goodbye"):
            print("\n👋 Goodbye! Stay safe out there!")
            break
        
        # Parse user intent
        intent = parse_user_intent(query)
        
        # Extract indicators from query
        indicators = extract_indicators_from_query(query)
        
        if not indicators:
            print("\n❌ I couldn't find any indicators (IP, domain, or hash) in your query.")
            print("💡 Try including an IP address, domain name, or file hash.")
            continue
        
        # Process each indicator found
        for idx, indicator_info in enumerate(indicators):
            if len(indicators) > 1:
                print(f"\n{'='*64}")
                print(f"📊 Analyzing indicator {idx + 1} of {len(indicators)}")
                print(f"{'='*64}")
            
            indicator = indicator_info["value"]
            typ = indicator_info["type"]
            
            print(f"\n🎯 Indicator: {indicator}")
            print(f"📋 Type: {typ.upper()}")

            gathered = {}
            
            # Check if user wants WHOIS/email info
            if intent.get("include_whois") and typ == "domain":
                print("\n📧 Fetching WHOIS/contact information...")
                whois_data = query_whois_info(indicator)
                whois_text = format_whois_response(whois_data)
                print(f"\n📬 Contact Information:\n{whois_text}\n")
                gathered["WHOIS"] = whois_data

            print(f"\n🔄 Gathering threat intelligence...")
            
            # Query sources based on user intent and indicator type
            if typ == "hash":
                if intent["use_virustotal"]:
                    print("  ↳ Querying VirusTotal...")
                    gathered["VirusTotal"] = query_virustotal(indicator)
                if intent["use_otx"]:
                    print("  ↳ Querying AlienVault OTX...")
                    gathered["OTX"] = query_otx(indicator)
                    
            elif typ == "ip":
                if intent["use_abuseipdb"]:
                    print("  ↳ Querying AbuseIPDB...")
                    gathered["AbuseIPDB"] = query_abuseipdb(indicator)
                if intent["use_otx"]:
                    print("  ↳ Querying AlienVault OTX (detailed)...")
                    gathered["OTX"] = query_otx_detailed(indicator, typ)
                if intent["use_virustotal"]:
                    print("  ↳ Querying VirusTotal...")
                    gathered["VirusTotal"] = query_virustotal(indicator)
                    
            elif typ == "domain":
                if intent["use_otx"]:
                    print("  ↳ Querying AlienVault OTX (detailed)...")
                    gathered["OTX"] = query_otx_detailed(indicator, typ)
                if intent["use_virustotal"]:
                    print("  ↳ Querying VirusTotal...")
                    gathered["VirusTotal"] = query_virustotal(indicator)
            else:
                # If unknown, try all available
                if intent["use_otx"]:
                    gathered["OTX"] = query_otx(indicator)
                if intent["use_virustotal"]:
                    gathered["VirusTotal"] = query_virustotal(indicator)

            print("\n📊 Summary from sources:")
            for k, v in gathered.items():
                if k == "WHOIS":
                    continue  # Already displayed
                    
                if isinstance(v, dict) and "error" in v:
                    print(f"  ❌ {k}: {v['error']}")
                else:
                    # show short summary counts when available
                    summary = ""
                    if isinstance(v, dict):
                        if "raw" in v:
                            raw = v["raw"]
                            # try to summarize common keys
                            if isinstance(raw, dict):
                                if "data" in raw and isinstance(raw["data"], dict):
                                    # VT style
                                    stats = raw["data"].get("attributes", {}).get("last_analysis_stats") if raw["data"].get("attributes") else None
                                    if stats:
                                        mal = stats.get('malicious', 0)
                                        sus = stats.get('suspicious', 0)
                                        harm = stats.get('harmless', 0)
                                        if mal > 0:
                                            summary = f"🚨 {mal} malicious, {sus} suspicious, {harm} harmless"
                                        elif sus > 0:
                                            summary = f"⚠️ {sus} suspicious, {harm} harmless"
                                        else:
                                            summary = f"✅ {harm} harmless, no threats detected"
                                elif "data" in raw and isinstance(raw["data"], list):
                                    summary = f"{len(raw['data'])} items found"
                                elif "pulse_info" in raw:
                                    pcount = len(raw.get("pulse_info", {}).get("pulses", []))
                                    if pcount > 0:
                                        summary = f"⚠️ Found in {pcount} threat pulse(s)"
                                    else:
                                        summary = f"✅ No threat pulses found"
                                else:
                                    summary = "Data retrieved"
                    print(f"  ✓ {k}: {summary}")
            
            # Show detailed VT file information if it's a hash
            if typ == "hash" and "VirusTotal" in gathered:
                vt_details = extract_vt_file_details(gathered["VirusTotal"])
                if vt_details:
                    print(f"\n📋 Detailed VirusTotal File Analysis:")
                    print(f"   {vt_details}")
            
            # Show detailed AbuseIPDB information for IPs
            if typ == "ip" and "AbuseIPDB" in gathered:
                abuse_details = extract_abuseipdb_details(gathered["AbuseIPDB"])
                if abuse_details:
                    print(f"\n📋 Detailed AbuseIPDB Analysis:")
                    print(f"   {abuse_details}")
            
            # Show detailed OTX information
            if "OTX" in gathered:
                otx_details = extract_otx_details(gathered["OTX"])
                if otx_details:
                    print(f"\n📋 Detailed AlienVault OTX Analysis:")
                    print(f"   {otx_details}")
                
                # Show all extracted IOCs
                all_iocs = extract_all_otx_iocs(gathered["OTX"])
                ioc_found = False
                ioc_lines = []
                
                if all_iocs["emails"]:
                    ioc_found = True
                    ioc_lines.append(f"📧 Emails: {len(all_iocs['emails'])} found")
                    for email in all_iocs["emails"][:5]:
                        ioc_lines.append(f"   • {email}")
                    if len(all_iocs["emails"]) > 5:
                        ioc_lines.append(f"   ... and {len(all_iocs['emails']) - 5} more")
                
                if all_iocs["ips"]:
                    ioc_found = True
                    ioc_lines.append(f"🌐 IP Addresses: {len(all_iocs['ips'])} found")
                    for ip in all_iocs["ips"][:5]:
                        ioc_lines.append(f"   • {ip}")
                    if len(all_iocs["ips"]) > 5:
                        ioc_lines.append(f"   ... and {len(all_iocs['ips']) - 5} more")
                
                if all_iocs["subdomains"]:
                    ioc_found = True
                    ioc_lines.append(f"🔗 Subdomains/Hostnames: {len(all_iocs['subdomains'])} found")
                    for subdomain in all_iocs["subdomains"][:5]:
                        ioc_lines.append(f"   • {subdomain}")
                    if len(all_iocs["subdomains"]) > 5:
                        ioc_lines.append(f"   ... and {len(all_iocs['subdomains']) - 5} more")
                
                if all_iocs["hashes"]:
                    ioc_found = True
                    ioc_lines.append(f"🔑 File Hashes: {len(all_iocs['hashes'])} found")
                    for hash_val in all_iocs["hashes"][:3]:
                        ioc_lines.append(f"   • {hash_val[:32]}...")
                    if len(all_iocs["hashes"]) > 3:
                        ioc_lines.append(f"   ... and {len(all_iocs['hashes']) - 3} more")
                
                if all_iocs["urls"]:
                    ioc_found = True
                    ioc_lines.append(f"🌍 URLs: {len(all_iocs['urls'])} found")
                    for url in all_iocs["urls"][:3]:
                        ioc_lines.append(f"   • {url[:60]}...")
                    if len(all_iocs["urls"]) > 3:
                        ioc_lines.append(f"   ... and {len(all_iocs['urls']) - 3} more")
                
                if all_iocs["file_paths"]:
                    ioc_found = True
                    ioc_lines.append(f"📁 File Paths: {len(all_iocs['file_paths'])} found")
                    for path in all_iocs["file_paths"][:3]:
                        ioc_lines.append(f"   • {path}")
                
                if all_iocs["registry_keys"]:
                    ioc_found = True
                    ioc_lines.append(f"🔧 Registry Keys: {len(all_iocs['registry_keys'])} found")
                    for key in all_iocs["registry_keys"][:3]:
                        ioc_lines.append(f"   • {key}")
                
                if all_iocs["mutexes"]:
                    ioc_found = True
                    ioc_lines.append(f"🔒 Mutexes: {len(all_iocs['mutexes'])} found")
                    for mutex in all_iocs["mutexes"][:3]:
                        ioc_lines.append(f"   • {mutex}")
                
                if ioc_found:
                    print(f"\n🔴 All IOCs Extracted from OTX:")
                    print("   " + "\n   ".join(ioc_lines))

            # Build prompt and call Together AI
            print("\n🤖 Analyzing with AI...")
            prompt = build_context_prompt(indicator, gathered)
            ai_output = call_together_ai_with_context(prompt)

            if ai_output.get("error"):
                print(f"\n❌ AI Analysis Error: {ai_output['error']}")
                if ai_output.get("raw"):
                    print(f"Raw response: {ai_output.get('raw', '')[:200]}...")
            else:
                print("\n" + "="*64)
                print("🎯 AI THREAT ASSESSMENT")
                print("="*64)
                pretty_print_vulns(ai_output["vulns"])

            # Ask if user wants to email the report (only if email config present)
            if SMTP_PASS and EMAIL_TO:
                print("\n" + "─"*64)
                send_q = input("📧 Would you like me to email this report? (yes/no): ").strip().lower()
                if send_q in ("y", "yes"):
                    print("📤 Sending email report...")
                    subject = f"🔒 Threat Intel Report: {indicator}"
                    body = generate_beautiful_email(indicator, typ, gathered, ai_output)
                    ok = send_email(subject, body)
                    if ok:
                        print("✅ Email sent successfully!")
                    else:
                        print("❌ Failed to send email. Check your SMTP settings.")
            else:
                print("\n💡 Tip: Configure email settings in .env to receive reports via email.")

        print("\n" + "─"*64)
        print("✨ Analysis complete! Ask me another question or type 'exit' to quit.")
        print("─"*64)

if __name__ == "__main__":
    main()
