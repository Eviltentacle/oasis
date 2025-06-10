# oasis


# IOC Vetting Automation Tool

This project automates the process of scanning **IP addresses**, **URLs**, **domains**, and **Hashes** in **VirusTotal**, then logs the results into an Excel workbook (`.xlsx`). The tool is designed to avoid overwriting sheets and is ideal for analysts, threat hunters, and SOC teams.

---

## 📂 Features

- ✅ Scans IPs, URLs/domains, and Hashes. #Email Address will be added soon
- ✅ Extracts IOCS and checks them via VirusTotal.
- ✅ Outputs results into a designated Excel sheet (e.g., `IP`, `URL`, `Domain`, Hashes) without affecting other sheets.
- ✅ Multithreaded scanning for better performance.
- ✅ Avoid overwriting and creates output file if it exist.
- ✅ Supports resuming and updating existing workbooks.

---
## 🧪 Installation

1. **Clone the repository**

Linux
```bash
git clone https://github.com/yourusername/oasis.git
cd oasis
pip install -r requirements.txt

Windows
```cmd/powershell
open git
git clone https://github.com/yourusername/oasis.git
cd oasis
pip install -r requirements.txt

or

download the zip file in github and extract
cd oasis
pip install -r requirements.txt

## 📦 Requirements

- Python 3.7+
- Install dependencies:
pycountry
pandas
openpyxl
requests
  



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
