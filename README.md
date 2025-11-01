# 🧠 AI-Driven Threat Intelligence Dashboard

This project is a **Streamlit-based dashboard** leveraging **AI and threat intelligence APIs** to analyze IPs, domains, and file hashes. It automatically enriches results, provides geolocation maps, displays threat summary cards, and sends email alerts for malicious indicators.

---

## Features

* **AI-driven source recommendation:** Uses Together AI to determine the best threat intelligence source.
* **Threat intelligence integration:** Queries:

  * VirusTotal (file hashes/domains)
  * AlienVault OTX (domains & IPs, related emails)
  * AbuseIPDB (malicious IP checks)
  * IPInfo (geolocation & ASN enrichment)
* **Automatic enrichment:** Sequentially queries IPInfo after AbuseIPDB, fetches related emails via OTX.
* **Colored summary cards:** Red/Yellow/Green threat levels in Streamlit.
* **Geolocation maps:** Shows malicious IP locations on an interactive map.
* **Email alerts:** Sends notification for critical indicators.
* **Caching:** Prevents duplicate lookups for faster performance.

---

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/yourusername/threat-intel-dashboard.git
cd threat-intel-dashboard
```

2. **Create a virtual environment (optional but recommended)**:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. **Install required Python packages**:

```bash
pip install streamlit requests folium streamlit-folium
```

---

## Configuration

1. Rename `config.example.py` to `config.py` (if applicable) or directly edit variables in the script:

```python
# Together AI
TOGETHER_API_KEY = "your_together_api_key"

# Threat Intelligence APIs
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
IPINFO_TOKEN = "your_ipinfo_token"
OTX_API_KEY = "your_otx_api_key"

# Email Alerts
EMAIL_ALERT_TO = "you@example.com"
EMAIL_FROM = "you@example.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_USER = "you@example.com"
SMTP_PASS = "YOUR_APP_PASSWORD"
```

> **Note:** For Gmail, generate an **App Password** for secure SMTP login.

---

## Usage

1. **Run the Streamlit app**:

```bash
streamlit run threat_intel_ai_dashboard_enriched.py
```

2. **Enter an indicator** in the text box:

   * **IP address** → AbuseIPDB, IPInfo, OTX
   * **Domain name** → VirusTotal, OTX
   * **File hash** → VirusTotal

3. **View results**:

   * AI suggestions for sources
   * Colored threat summary cards
   * Raw JSON results
   * Related emails (if found)
   * Geolocation map for IPs

4. **Receive email alerts** automatically if indicator is critical.

---

## License
MIT License – feel free to use, modify, and share.
