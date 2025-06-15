import argparse
import pandas as pd
import requests
import pycountry
import logging
import shutil
import time
import os

from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_KEY = 'YOUR_API'  # <-- Replace with your VirusTotal Premium API key
INPUT_FILE = 'ioc_vetting.xlsx'  

def load_geoblocked_countries():
    try:
        geoblock_df = pd.read_excel(INPUT_FILE, sheet_name='Geoblocked')  
        geoblock_df.columns = geoblock_df.columns.str.strip()  
        countries = set(geoblock_df['Country'].str.strip())    
        logging.info(f"Loaded {len(countries)} geoblocked countries.")
        return countries
    except FileNotFoundError:
        logging.error(f"Input file '{INPUT_FILE}' not found.")
        raise
    except KeyError:
        logging.error(f"'Country' column not found in 'Geoblocked' sheet.")
        raise
    except Exception as e:
        logging.error(f"Failed to load geoblock sheet: {e}")
        raise

def check_ip(ip_address, geoblocked_countries):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise requests.exceptions.RequestException(f"API error: {response.status_code} for IP {ip_address}")

    data = response.json()['data']['attributes']
    country_code = data.get('country')
    as_owner = data.get('as_owner')
    malicious = data.get('last_analysis_stats', {}).get('malicious', 0)

    country_name = None
    if country_code:
        country_obj = pycountry.countries.get(alpha_2=country_code.upper())
        country_name = country_obj.name if country_obj else country_code

    geo_blocked = 'Y' if country_name and country_name in geoblocked_countries else 'N'

    return {
        'IP': ip_address,
        'VT': malicious,
        'Country': country_name,
        'GB': geo_blocked,
        'Qradar': '',
        'Snow': '',
        'TV': '',
        'Autonomous': as_owner,
    }

def load_geoblocked_countries():
    geoblock_df = pd.read_excel(INPUT_FILE, sheet_name='Geoblocked')
    geoblock_df.columns = geoblock_df.columns.str.strip()
    countries = set(geoblock_df['Country'].str.strip())
    logging.info(f"Loaded {len(countries)} geoblocked countries.")
    return countries

def check_ip(ip_address, geoblocked_countries):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code != 200:
        raise requests.exceptions.RequestException(f"API error: {response.status_code} for IP {ip_address}")
    data = response.json()['data']['attributes']
    country_code = data.get('country')
    as_owner = data.get('as_owner')
    malicious = data.get('last_analysis_stats', {}).get('malicious', 0)
    country_name = None
    if country_code:
        country_obj = pycountry.countries.get(alpha_2=country_code.upper())
        country_name = country_obj.name if country_obj else country_code
    geo_blocked = 'Y' if country_name and country_name in geoblocked_countries else 'N'
    return {
        'IP': ip_address,
        'VT': malicious,
        'Country': country_name,
        'GB': geo_blocked,
        'Qradar': '',
        'Snow': '',
        'TV': '',
        'Autonomous': as_owner,
    }

def main():
    parser = argparse.ArgumentParser(description="VirusTotal IP scanner")
    #parser.add_argument('-i', '--input-file', required=True, help='Input Excel template file')
    parser.add_argument('-o', '--output-file', required=True, help='Output Excel file for results')
    args = parser.parse_args()
    
    if not os.path.exists(args.output_file):
        shutil.copyfile(INPUT_FILE, args.output_file)
        logging.info(f"Copied template '{INPUT_FILE}' to '{args.output_file}'")
    else:
        logging.info(f"Output file '{args.output_file}' already exists. Will update 'IP' sheet only.")
    
    try:
        start_time = time.time()
        geoblocked_countries = load_geoblocked_countries()

        df_ip = pd.read_excel(INPUT_FILE, sheet_name='IP')
        df_ip.columns = df_ip.columns.str.strip()
        #logging.info(f"IP sheet columns: {df_ip.columns.tolist()}")

        if 'IP' not in df_ip.columns:
            #logging.error("Missing 'IP' column in the IP sheet.")
            return

        ip_list = df_ip['IP'].dropna().astype(str).tolist()
        logging.info(f"Loaded {len(ip_list)} IP addresses from the IP sheet.")

        results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_ip, ip, geoblocked_countries): ip for ip in ip_list}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    logging.info(f"Processed IP: {ip}")
                except Exception as e:
                    logging.error(f"Failed to process IP {ip}: {e}")

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

