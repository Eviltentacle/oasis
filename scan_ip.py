import argparse
import pandas as pd
import requests
import pycountry
import logging
import shutil
import time
import os
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
if not API_KEY:
    raise ValueError("VirusTotal API key not found. Please set API_KEY in a .env file.")
if not ABUSE_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set ABUSE_API_KEY in a .env file.")

INPUT_FILE = 'ioc_vetting.xlsx'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_geoblocked_countries():
    geoblock_df = pd.read_excel(INPUT_FILE, sheet_name='Geoblocked')
    geoblock_df.columns = geoblock_df.columns.str.strip()
    countries = set(geoblock_df['Country'].str.strip())
    logging.info(f"Loaded {len(countries)} geoblocked countries.")
    return countries


def check_abuseipdb(ip_address):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': ABUSE_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        return "No data"
    data = response.json().get('data', {})
    reports = data.get('totalReports', 0)
    confidence = data.get('abuseConfidenceScore', 0)
    return f"Reported {reports} times. Confidence: {confidence}%"


def check_ip(ip_address, geoblocked_countries):
    # VirusTotal
    vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    vt_headers = {'x-apikey': API_KEY}
    vt_response = requests.get(vt_url, headers=vt_headers)

    if vt_response.status_code != 200:
        raise requests.exceptions.RequestException(f"VT API error: {vt_response.status_code} for IP {ip_address}")

    vt_data = vt_response.json()['data']['attributes']
    country_code = vt_data.get('country')
    as_owner = vt_data.get('as_owner')
    malicious = vt_data.get('last_analysis_stats', {}).get('malicious', 0)

    country_name = None
    if country_code:
        country_obj = pycountry.countries.get(alpha_2=country_code.upper())
        country_name = country_obj.name if country_obj else country_code

    geo_blocked = 'Y' if country_name and country_name in geoblocked_countries else 'N'

    # AbuseIPDB
    abuse_info = check_abuseipdb(ip_address)

    return {
        'IP': ip_address,
        'VT': malicious,
        'Country': country_name,
        'GB': geo_blocked,
        'Qradar': '',
        'Snow': '',
        'TV': '',
        'Autonomous': as_owner,
        'AbuseIPDB': abuse_info
    }


def main():
    parser = argparse.ArgumentParser(description="VirusTotal + AbuseIPDB IP scanner")
    parser.add_argument('-o', '--output-file', required=True, help='Output Excel file for results')
    args = parser.parse_args()

    if not os.path.exists(args.output_file):
        shutil.copyfile(INPUT_FILE, args.output_file)
        logging.info(f"Copied template '{INPUT_FILE}' to '{args.output_file}'")

    try:
        start_time = time.time()
        geoblocked_countries = load_geoblocked_countries()

        df_ip = pd.read_excel(INPUT_FILE, sheet_name='IP')
        df_ip.columns = df_ip.columns.str.strip()

        if 'IP' not in df_ip.columns:
            logging.error("Missing 'IP' column in the IP sheet.")
            return

        ip_list = df_ip['IP'].dropna().astype(str).tolist()
        logging.info(f"Loaded {len(ip_list)} IP addresses from the IP sheet.")

        results = []
        for ip in ip_list:
            try:
                result = check_ip(ip, geoblocked_countries)
                results.append(result)
                logging.info(f"Processed IP: {ip}")
            except Exception as e:
                logging.error(f"Failed to process IP {ip}: {e}")
                results.append({'IP': ip, 'Error': str(e)})

        result_df = pd.DataFrame(results)
        with pd.ExcelWriter(args.output_file, engine='openpyxl', mode='a', if_sheet_exists='replace') as writer:
            result_df.to_excel(writer, sheet_name='IP', index=False)

        logging.info(f"Scan complete. Results saved to '{args.output_file}'")
        print(f"\nScan completed in {round(time.time() - start_time, 2)} seconds.")
    except FileNotFoundError:
        logging.error(f"Input file '{INPUT_FILE}' or sheet not found.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")


if __name__ == '__main__':
    main()

