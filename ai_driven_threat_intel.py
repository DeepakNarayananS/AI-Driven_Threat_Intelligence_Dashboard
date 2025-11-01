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

def query_abuseipdb(ip: str) -> Dict[str, Any]:
    """Check IP reputation at AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        return {"status_code": r.status_code, "raw": r.json() if r.content else {}}
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {e}"}

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
            pretty = json.dumps(payload, indent=2, default=str)
        except Exception:
            pretty = str(payload)
        lines.append(f"--- {name} ---\n{pretty}\n")

    lines.append(
        "Based on these results, provide a concise JSON object (or a JSON array with one object) with keys:\n"
        '  "Verdict": one of ["Malicious","Suspicious","Benign"],\n'
        '  "Score": integer 0-100 (higher = more malicious),\n'
        '  "Summary": short explanation (1-2 sentences),\n'
        '  "RecommendedActions": list of short actionable items (e.g., "Quarantine file", "Block IP"),\n'
        '  "References": list of source strings or links.\n\n'
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

def pretty_print_vulns(vulns):
    if not vulns:
        print("No structured results returned by AI.")
        return
    print("\n=== AI Structured Assessment ===")
    try:
        print(json.dumps(vulns, indent=2, ensure_ascii=False))
    except Exception:
        print(vulns)

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
    print("=== AI Threat Intel CLI (Together AI + VT/OTX/AbuseIPDB) ===")
    print("Type 'exit' or Ctrl+C to quit.\n")

    while True:
        try:
            indicator = input("Enter indicator (hash, domain, or IP): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if not indicator:
            continue
        if indicator.lower() in ("exit", "quit"):
            break

        typ = detect_type(indicator)
        print(f"Detected type: {typ}")

        gathered = {}

        # Query sources depending on type (prioritized)
        if typ == "hash":
            gathered["VirusTotal"] = query_virustotal(indicator)
            # optionally we could query OTX for related artifacts if desired
            gathered["OTX (domain lookup)"] = query_otx(indicator)
        elif typ == "ip":
            gathered["AbuseIPDB"] = query_abuseipdb(indicator)
            gathered["OTX"] = query_otx(indicator)
            gathered["VirusTotal"] = query_virustotal(indicator)
        elif typ == "domain":
            gathered["OTX"] = query_otx(indicator)
            gathered["VirusTotal"] = query_virustotal(indicator)
        else:
            # If unknown, still try a broad set
            gathered["OTX"] = query_otx(indicator)
            gathered["VirusTotal"] = query_virustotal(indicator)

        print("\nGathered data from sources (summary):")
        for k, v in gathered.items():
            if isinstance(v, dict) and "error" in v:
                print(f" - {k}: ERROR -> {v['error']}")
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
                                    summary = f"VT analysis stats: {stats}"
                            elif "data" in raw and isinstance(raw["data"], list):
                                summary = f"{len(raw['data'])} items"
                            elif "pulse_info" in raw:
                                pcount = len(raw.get("pulse_info", {}).get("pulses", []))
                                summary = f"OTX pulse count: {pcount}"
                            else:
                                summary = ", ".join(list(raw.keys())[:3])
                print(f" - {k}: {summary or str(v)[:200]}")

        # Build prompt and call Together AI
        prompt = build_context_prompt(indicator, gathered)
        ai_output = call_together_ai_with_context(prompt)

        if ai_output.get("error"):
            print("AI error:", ai_output["error"])
            print("Raw AI reply (if any):", ai_output.get("raw", ""))
        else:
            pretty_print_vulns(ai_output["vulns"])

        # Ask if user wants to email the report (only if email config present)
        if SMTP_PASS and EMAIL_TO:
            send_q = input("\nSend this report via email? (yes/no): ").strip().lower()
            if send_q in ("y", "yes"):
                subject = f"🔒 Threat Intel Report: {indicator}"
                body = generate_beautiful_email(indicator, typ, gathered, ai_output)
                ok = send_email(subject, body)
                if ok:
                    print("Email sent.")
                else:
                    print("Failed to send email.")
        else:
            print("\nEmail send skipped: SMTP or email settings not configured in environment.")

        print("\n--- Done. Next query ---\n")

if __name__ == "__main__":
    main()
