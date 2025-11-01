# 🔒 AI Threat Intelligence CLI

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

**A powerful terminal-based threat intelligence assistant powered by AI**

Analyze suspicious IPs, domains, and file hashes with real-time threat intelligence from multiple sources, enhanced by AI-powered analysis.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Configuration](#-configuration) • [Screenshots](#-screenshots)

</div>

---

## ✨ Features

🔍 **Multi-Source Intelligence**
- **VirusTotal** - Comprehensive malware and URL scanning
- **AbuseIPDB** - IP reputation and abuse reports
- **AlienVault OTX** - Open threat intelligence pulses

🤖 **AI-Powered Analysis**
- Aggregates data from all sources
- Provides intelligent risk assessment
- Generates actionable recommendations
- Powered by Together AI (Gemma model)

📧 **Beautiful Email Reports**
- Professional HTML email templates
- Color-coded threat levels
- Detailed statistics and visualizations
- Optional email delivery on demand

🎯 **Supported Indicators**
- 🌐 IP Addresses (IPv4)
- 🔗 Domain Names
- 📄 File Hashes (MD5, SHA1, SHA256)

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Step 1: Clone or Download

```bash
# Clone the repository or download the files
cd your-project-directory
```

### Step 2: Install Dependencies

```bash
pip install python-dotenv requests
```

Or install all at once:

```bash
pip install -r requirements.txt
```

### Step 3: Set Up Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the example and edit with your API keys
cp .env.example .env
```

Edit `.env` with your API keys (see [Configuration](#-configuration) below).

---

## 📋 Requirements

Create a `requirements.txt` file with:

```txt
python-dotenv>=1.0.0
requests>=2.31.0
```

Install with:
```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 1. Get Your API Keys

#### VirusTotal (Required)
1. Sign up at [https://www.virustotal.com](https://www.virustotal.com)
2. Go to your profile → API Key
3. Copy your API key

#### AbuseIPDB (Required)
1. Sign up at [https://www.abuseipdb.com](https://www.abuseipdb.com)
2. Go to Account → API
3. Create and copy your API key

#### AlienVault OTX (Required)
1. Sign up at [https://otx.alienvault.com](https://otx.alienvault.com)
2. Go to Settings → API Integration
3. Copy your OTX Key

#### Together AI (Required)
1. Sign up at [https://www.together.ai](https://www.together.ai)
2. Go to API Keys section
3. Create and copy your API key

### 2. Configure `.env` File

```env
# ===== Threat Intel API Keys =====
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
OTX_API_KEY=your_otx_key_here

# ===== Together AI Gemma API Key =====
TOGETHER_API_KEY=your_together_ai_key_here

# ===== Email Alert Settings (Optional) =====
EMAIL_TO=recipient@example.com
EMAIL_FROM=sender@example.com
SMTP_SERVER=smtp.gmail.com
SMTP_USER=sender@example.com
SMTP_PASS=your_app_password_here
SMTP_PORT=587
SMTP_USE_TLS=True
```

### 3. Gmail Setup (Optional - for email reports)

If using Gmail for email reports:

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password:
   - Go to Google Account → Security → 2-Step Verification → App passwords
   - Select "Mail" and your device
   - Copy the 16-character password
3. Use this App Password in `SMTP_PASS` (not your regular Gmail password)

---

## 🎮 Usage

### Basic Usage

Run the script:

```bash
python .kiro/python.py
```

### Interactive Mode

```
=== AI Threat Intel CLI (Together AI + VT/OTX/AbuseIPDB) ===
Type 'exit' or Ctrl+C to quit.

Enter indicator (hash, domain, or IP): 8.8.8.8
```

### Example Queries

**Analyze an IP Address:**
```
Enter indicator: 8.8.8.8
```

**Analyze a Domain:**
```
Enter indicator: suspicious-domain.com
```

**Analyze a File Hash:**
```
Enter indicator: 44d88612fea8a8f36de82e1278abb02f
```

### Email Reports

After analysis, you'll be prompted:
```
Send this report via email? (yes/no): yes
```

Type `yes` or `y` to send a beautiful HTML email report!

---

## 📊 Output Example

```
Detected type: ip

Gathered data from sources (summary):
 - AbuseIPDB: VT analysis stats: {'malicious': 0, 'suspicious': 0, ...}
 - OTX: OTX pulse count: 0
 - VirusTotal: VT analysis stats: {'malicious': 0, 'suspicious': 0, ...}

--- Together AI Raw Reply ---
{
  "Verdict": "Benign",
  "Score": 5,
  "Summary": "This IP address shows no signs of malicious activity...",
  "RecommendedActions": ["Monitor for changes", "No immediate action required"],
  "References": ["VirusTotal", "AbuseIPDB", "OTX"]
}

=== AI Structured Assessment ===
[Detailed JSON output...]

Send this report via email? (yes/no):
```

---

## 📧 Email Report Features

The HTML email includes:

✅ **Visual Verdict Banner** - Color-coded threat level  
✅ **Risk Score** - 0-100 scale with emoji indicators  
✅ **Detailed Statistics** - From all threat intelligence sources  
✅ **AI Summary** - Human-readable threat assessment  
✅ **Actionable Recommendations** - What to do next  
✅ **Raw Data** - Complete JSON for technical analysis  
✅ **Professional Design** - Responsive and mobile-friendly  

### Verdict Colors:
- 🚨 **Red** - Malicious (High Risk)
- ⚠️ **Yellow** - Suspicious (Medium Risk)
- ✅ **Green** - Benign (Low Risk)

---

## 🛠️ Troubleshooting

### Common Issues

**"API Key not set" errors:**
- Ensure your `.env` file is in the same directory as the script
- Check that variable names match exactly (e.g., `VIRUSTOTAL_API_KEY`)
- Verify no extra spaces or quotes around values

**Email not sending:**
- For Gmail, use an App Password, not your regular password
- Ensure 2FA is enabled on your Google account
- Check SMTP settings match your email provider

**"Module not found" errors:**
```bash
pip install python-dotenv requests
```

**403 Forbidden errors:**
- Verify your API keys are valid and active
- Check if you've exceeded rate limits
- Ensure API keys have proper permissions

---

## 📁 Project Structure

```
.
├── .kiro/
│   └── python.py          # Main application script
├── .env                   # Environment variables (API keys)
├── .env.example          # Example environment file
├── requirements.txt      # Python dependencies
├── README.md            # This file
└── test_threat_intel.py # Test script (optional)
```

---

## 🔐 Security Notes

⚠️ **Important Security Practices:**

- Never commit `.env` file to version control
- Keep API keys confidential
- Use App Passwords for email (not main passwords)
- Regularly rotate API keys
- Review API usage limits to avoid unexpected charges

Add to `.gitignore`:
```
.env
*.pyc
__pycache__/
```

---

## 🎯 Use Cases

- **Security Operations Centers (SOC)** - Quick threat triage
- **Incident Response** - Rapid indicator analysis
- **Threat Hunting** - Proactive threat intelligence gathering
- **Security Research** - Malware and threat analysis
- **IT Security Teams** - Daily security monitoring

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

Powered by:
- [VirusTotal](https://www.virustotal.com) - Malware and URL scanning
- [AbuseIPDB](https://www.abuseipdb.com) - IP reputation database
- [AlienVault OTX](https://otx.alienvault.com) - Open threat intelligence
- [Together AI](https://www.together.ai) - AI-powered analysis

---

## 📞 Support

Having issues? Here's how to get help:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review your `.env` configuration
3. Verify all API keys are valid
4. Check Python version: `python --version` (requires 3.8+)

---

## 🚦 Status Indicators

| Service | Status | Purpose |
|---------|--------|---------|
| VirusTotal | ✅ Active | File/URL/IP scanning |
| AbuseIPDB | ✅ Active | IP reputation |
| AlienVault OTX | ✅ Active | Threat intelligence |
| Together AI | ✅ Active | AI analysis |

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

⭐ Star this repo if you find it useful!

</div>
