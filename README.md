# AI-Driven Threat Intelligence Dashboard (FastAPI)

This project is an **AI-powered threat intelligence dashboard** built with **FastAPI**, designed to analyze IPs, domains, and file hashes for potential malicious activity. It integrates multiple threat intelligence APIs and provides an enriched, color-coded dashboard with geolocation maps, automated alerts, and actionable insights.

---

## **Features**

* Query **IP addresses, domains, or file hashes** to detect malicious activity.
* Integrates with **four threat intelligence sources**:

  1. **VirusTotal** – file hash scanning.
  2. **AbuseIPDB** – IP threat scoring.
  3. **IPInfo** – IP geolocation and enrichment.
  4. **AlienVault OTX** – domain/IP threat intelligence, passive DNS, related emails.
* **AI-driven decision logic** determines which API to use for each query type.
* **Colored threat status**:

  * **Red**: High threat
  * **Yellow**: Medium threat
  * **Green**: Low threat
* **Geolocation maps** for malicious IPs using Folium.
* **Automatic email alerts** for detected threats.
* Optional **automatic enrichment** for related domains, emails, and IP info.

---

## **Demo Screenshot**

*(Insert screenshot here if available)*

---

## **Installation Guide**

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ai-threat-intel-dashboard.git
cd ai-threat-intel-dashboard
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

### 3. Activate Virtual Environment

* **Windows**

```bash
venv\Scripts\activate
```

* **Linux/Mac**

```bash
source venv/bin/activate
```

### 4. Upgrade pip

```bash
python -m pip install --upgrade pip
```

### 5. Install Dependencies

```bash
pip install fastapi uvicorn requests folium
```

---

## **Configuration**

1. Open `fastapi_threatintel.py`.
2. Replace the placeholders with your **API keys**:

```python
# API KEYS
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
IPINFO_API_KEY = "YOUR_IPINFO_API_KEY"
OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"

# EMAIL ALERT CONFIG
EMAIL_ALERT_TO = "you@example.com"
EMAIL_FROM = "alert-bot@example.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_USER = "you@example.com"
SMTP_PASS = "YOUR_EMAIL_PASSWORD"
```

> Ensure your Gmail account allows **less secure apps** or use an **App Password**.

---

## **Running the Dashboard**

```bash
uvicorn fastapi_threatintel:app --reload
```

* Open your browser: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* Enter **IP, domain, or hash** in the input field.
* View **threat status**, **API enrichment**, and **geolocation map**.

---

## **How It Works**

1. **Input Detection**

   * If input is a **file hash**, queries **VirusTotal**.
   * If input is a **domain or IP**:

     * Queries **AbuseIPDB** for IP risk score.
     * Queries **IPInfo** for geolocation.
     * Queries **OTX** for domain/IP-related intelligence (emails, passive DNS).
2. **Threat Evaluation**

   * AI logic evaluates API results to assign a **threat color** (Red/Yellow/Green).
3. **Automatic Enrichment**

   * IPInfo after AbuseIPDB for detailed geolocation.
   * OTX for related domains/emails.
4. **Alerts**

   * Sends **email alerts** for high-risk indicators.

---

## **Colored Threat Status**

| Color  | Meaning                 |
| ------ | ----------------------- |
| Red    | High threat detected    |
| Yellow | Medium threat detected  |
| Green  | Low threat/no issues    |
| Gray   | Unknown / not evaluated |

---

## **IP Geolocation Map**

* Malicious IPs display an interactive map using **Folium**.
* Hover over the marker to see **city or location** info.

---

## **Dependencies**

* **fastapi** – Web framework.
* **uvicorn** – ASGI server.
* **requests** – API requests.
* **folium** – Interactive maps.
* **smtplib/email** – Email alerts (built-in).

Install via pip:

```bash
pip install fastapi uvicorn requests folium
```

---

## **Folder Structure**

```
ai-threat-intel-dashboard/
│
├─ fastapi_threatintel.py  # Main script
├─ README.md
└─ requirements.txt        # Optional: list of pip modules
```

---

## **Security Notes**

* Keep **API keys** private.
* Use **app passwords** for Gmail instead of your main password.
* Do not expose the dashboard publicly without authentication.

---

## **Contributing**

* Fork the repo, create a branch, and submit PRs for bug fixes or features.
* Open an issue if you face problems with API integration or dashboard behavior.

---

## **License**

MIT License – feel free to use and modify for personal or research purposes.

---

Do you want me to do that?
