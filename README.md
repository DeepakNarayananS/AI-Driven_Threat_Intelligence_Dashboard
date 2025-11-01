# AI-Powered Threat Intelligence Dashboard (FastAPI)
AI-powered FastAPI dashboard for analyzing IPs, domains, and file hashes with multiple threat intel APIs, colored dashboards, geolocation, and alerts.

---

## Features
* Analyze **IP addresses, domains, and file hashes** for malicious activity.
* Integrates **VirusTotal, AbuseIPDB, IPInfo, AlienVault OTX**.
* AI-driven insights using **Together AI (Gemma model)**.
* **Colored threat levels** (Red/Yellow/Green) for quick visualization.
* **Geolocation maps** for IP analysis.
* **Automatic email alerts** for malicious indicators.
* **Caching** to avoid duplicate API lookups.
* Additional **enrichment**: related domains/emails via OTX.

---

## Installation
### 1. Clone the repository
```bash
git clone https://github.com/DeepakNarayananS/your-repo.git
cd your-repo
```

### 2. Create a virtual environment
```bash
python -m venv venv
```

### 3. Activate the virtual environment

* **Windows**
```bash
venv\Scripts\activate
```

* **macOS/Linux**
```bash
source venv/bin/activate
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

**Dependencies include:**
```text
fastapi
uvicorn
requests
python-dotenv
jinja2
geopy
pandas
openai  # Together AI integration
```

---

## Environment Configuration
Create a `.env` file in the root directory with the following:

```ini
# ===== Threat Intel API Keys =====
VIRUSTOTAL_API=your_virustotal_api_key
ABUSEIPDB_API=your_abuseipdb_api_key
IPINFO_API=your_ipinfo_api_key
OTX_API=your_alienvault_otx_api_key

# ===== Together AI Gemma API Key =====
TOGETHER_API_KEY=your_together_ai_api_key

# ===== Email Alert Settings =====
EMAIL_ALERT_TO=recipient@example.com
EMAIL_FROM=alert-bot@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=True
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_email_password_or_app_password
```

**Note:**
* Use **App Password** for Gmail SMTP.
* Keep `.env` **excluded from GitHub** (`.gitignore`).

---

## Running the Dashboard
```bash
uvicorn main:app --reload
```

Then open your browser at:

```
http://127.0.0.1:8000
```

---

## Usage
1. Enter an **IP address, domain, or file hash** in the input form.
2. AI (Together Gemma) suggests which APIs to query based on input type.

   * Hash → VirusTotal
   * IP → AbuseIPDB + IPInfo
   * Domain → OTX + related emails/domains
3. Results are displayed with:

   * **Colored threat status** (Red/Yellow/Green)
   * **Geolocation map** for IPs
   * **Enriched metadata** for domains/hashes
4. **Email alerts** are triggered for malicious indicators automatically.

---

## Contributing
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-name`.
3. Commit changes: `git commit -m "Add feature"`.
4. Push to the branch: `git push origin feature-name`.
5. Open a Pull Request.

---

## License
This project is licensed under **MIT License**.

---

## Notes
* Make sure all API keys are active and valid.
* FastAPI + Uvicorn is used for backend serving; Jinja2 for HTML templates.
* Together AI integration allows **AI-driven recommendations** on which API to query and how to enrich the data.
