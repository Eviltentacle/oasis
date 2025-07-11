# OASIS


# IOC Vetting Automation Tool

This project automates the process of scanning **IP addresses**, **URLs**, **domains**, and **Hashes** in **VirusTotal**, then logs the results into an Excel workbook (`.xlsx`). The tool is designed for automated triage of IOC then imported on sheets. Ideal for security analysts, threat hunters, and SOC teams.

---

## 📂 Features

- ✅ Scans IPs, URLs/domains, and Hashes. #Email Address will be added soon
- ✅ Extracts IOCS and checks them via VirusTotal.
- ✅ Outputs results into a designated Excel sheet (e.g., `IP`, `URL`, `Domain`, `Hashes` ) without affecting other sheets.
- ✅ Multithreaded scanning for better performance.
- ✅ Avoid overwriting and creates output file if it exist.
- ✅ Supports resuming and updating existing workbooks.

---
## 🧪 Installation

1. **Clone the repository**

**Linux**
- git clone https://github.com/Eviltentacle/oasis.git
- cd oasis
- pip install -r requirements.txt

**Windows**
- Download Zip and Extract
- cd oasis-main
- pip install -r requirements.txt


## 📦 Requirements

- Python 3.7+
- Install dependencies:
``pycountry``
``pandas``
``openpyxl``
``requests``
  
## 🚀 How to Use

- Prepare Your Input
- Use the provided ``ioc_vetting.xlsx`` template.
- Paste your IOCs into their respective sheets:
- **IP** → for IP addresses
- **URL/Domain** → for domains and URLs
- **Hash** → for SHA1/SHA256

## Run the Script

**bash** / **cmd or powershell**
- ``python.exe main.py -o <output_file>.xlsx``
- ``python.exe main.py --output <output_file>.xlsx``

If ``<output_file>`` already exists, the program will update only the specified sheet(s), avoiding full overwrite.

## 📦 Output
- Results are written to specific sheets inside the output Excel workbook.
- Each IOC category gets updated in its own sheet (e.g., IP, URL, Email, Hash).
- Results include VT detection score, geoblock status (if applicable), and metadata like ASN, country name, etc.


# 🧾 Version Changelog

---

###  v1.0 - Initial Release

**Features:**
- Hardcoded input file (`ioc_vetting.xlsx`)
- IP scan with VirusTotal API
- Output written into a fixed sheet in the Excel workbook

**Limitations:**
- No main menu or user interaction
- Country code from VirusTotal not converted to full country name
- URLs and domains with or without `http://`/`https://` not reliably parsed

**Fixes:**
- Generic output improved
- Separated result sheets (e.g., IP, URL) in the workbook instead of overwriting the entire file

**Known Issues:**
- Unrecognized domains/URLs depending on `http://` or `https://` prefix

---

###  v2.0 - Menu & Geoblock Support

**Features:**
- Added interactive main menu for selecting scan type (IP, URL, etc.)
- Added support for geoblocked country lookup
- Improved URL parsing:
  - Automatically handles domains with/without `http://`/`https://`
  - Converts country codes to full country names

**Fixes:**
- Country name conversion issue
- Domain recognition regardless of URL format

**Known Issues:**
- Does not yet detect SHA1/SHA256 hashes automatically

---

###  v3.0 - Performance & Hash Recognition

**Features:**
- Introduced multithreading for faster IOC scanning
- Automatically detects and categorizes SHA1/SHA256 hashes from input
- Intelligent formatting and writing of results into corresponding sheets

**Fixes:**
- Avoids overwriting unrelated sheets during parallel scans

###  v3.1 - Removed Hardcoded API, Email Domain Detection and New Reputation Scan

**Features:**
- Added email domain detection in email address section
- Added .env and removed hardcoded API's
- Added AbuseIPDB reputation scan

**Fixes:**
- Unorganized output in IP Address due to parallel scan

---

### 🚧 Coming Soon: v4.0

**Planned Features:**
- Supports both hardcoded input (`ioc_vetting.xlsx`) and dynamic user-provided input via arguments
- Adds `Email` sheet support:
  - Extracts domain from email
  - Checks domain against VirusTotal
  - Detects if email is flagged in 3rd-party trackers (future feature)

---

This project is licensed under the GNU General Public License v3.0.

You are free to:

Use the software for any purpose

Study how it works and modify it

Distribute copies

Share your improvements under the same license

📎 For full details, see LICENSE or visit:
https://www.gnu.org/licenses/gpl-3.0.en.html
