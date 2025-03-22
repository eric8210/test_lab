import pandas as pd
import requests
import json
import csv
import os
import logging
import time
import re
from datetime import datetime, timedelta
from collections import defaultdict

# ----------------------
# Configuration Section
# ----------------------
INPUT_CSV = "./inventory.csv"
API_KEY = "your api key"
API_DELAY = 6  # NVD API rate limit compliance
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ----------------------
# Logging Configuration
# ----------------------
logging.basicConfig(
    filename='cve_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)

def create_output_dirs():
    """Create dated output directories for JSON and CSV"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    json_dir = f"cve_{date_str}"
    csv_dir = "reports"
    
    os.makedirs(json_dir, exist_ok=True)
    os.makedirs(csv_dir, exist_ok=True)
    return json_dir, csv_dir

def query_nvd_api(cpe):
    """Query NVD API for CVE data"""
    headers={"apikey": API_KEY}
    try:
        response = requests.get(
            NVD_API_URL,headers=headers,
            params={"cpeName": cpe},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"API query failed for {cpe}: {str(e)}")
        return None

def save_json_results(os_version, vendor, cpe, data, json_dir):
    """Save API results to JSON file"""
    try:
        # Sanitize filename using regex
        safe_name = re.sub(r'[^\w\-_]', '_', os_version)
        filename = f"{safe_name}.json"
        output_path = os.path.join(json_dir, filename)
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "os_version": os_version,
            "vendor": vendor,
            "cpe": cpe,
            "vulnerabilities": data.get("vulnerabilities", []) if data else []
        }
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
            
        logging.info(f"Saved results for {os_version} to {filename}")
    except Exception as e:
        logging.error(f"Failed to save {os_version}: {str(e)}")

def process_inventory(json_dir):
    """Process CSV inventory and save JSON results"""
    try:
        df = pd.read_csv(INPUT_CSV)
        logging.info(f"Loaded {len(df)} entries from inventory")
        
        processed = defaultdict(bool)
        
        for _, row in df.iterrows():
            os_ver = str(row['os_version']).strip()
            vendor = str(row['vendor']).strip()
            cpe = str(row['cpe']).strip()
            
            if not cpe or processed[(os_ver, cpe)]:
                continue
                
            processed[(os_ver, cpe)] = True
            logging.info(f"Processing {os_ver} - {cpe}")
            
            results = query_nvd_api(cpe)
            save_json_results(os_ver, vendor, cpe, results, json_dir)
            time.sleep(API_DELAY)

    except Exception as e:
        logging.critical(f"Processing failed: {str(e)}", exc_info=True)
        raise

def parse_iso_date(date_str):
    """Parse ISO date with Zulu time and optional milliseconds"""
    try:
        if date_str.endswith('Z'):
            date_str = date_str[:-1] + '+00:00'
        return datetime.fromisoformat(date_str).replace(tzinfo=None)
    except:
        return None

def extract_cve_data(json_path):
    """Extract required fields from JSON files"""
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    output = []
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve', {})
        metrics = cve.get('metrics', {})
        
        # Get primary CVSS 3.1 metric
        cvss31 = next(
            (m for m in metrics.get('cvssMetricV31', []) 
             if m.get('type') == 'Primary'),
            metrics.get('cvssMetricV31', [{}])[0]
        )
        
        severity = cvss31.get('cvssData', {}).get('baseSeverity', '').upper()
        if severity not in ['MEDIUM', 'HIGH', 'CRITICAL']:
            continue
            
        # Extract version ranges
        version_ranges = []
        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable'):
                        version_ranges.append({
                            'start': match.get('versionStartIncluding'),
                            'end': match.get('versionEndExcluding')
                        })
        
        # Build record
        output.append({
            'cve_id': cve.get('id', 'null'),
            'vendor': data.get('vendor', 'null'),
            'os_version': data.get('os_version', 'null'),
            'description': next(
                (d['value'] for d in cve.get('descriptions', []) 
                 if d.get('lang') == 'en'), 'null'),
            'published': cve.get('published', 'null'),
            'lastModified': cve.get('lastModified', 'null'),
            'basescore': cvss31.get('cvssData', {}).get('baseScore', 'null'),
            'baseseverity': severity,
            'refer_url': next(
                (r['url'] for r in cve.get('references', [])), 'null'),
            'versionStartIncluding': '|'.join(
                filter(None, [v['start'] for v in version_ranges])) or 'null',
            'versionEndExcluding': '|'.join(
                filter(None, [v['end'] for v in version_ranges])) or 'null'
        })
    
    return output

def generate_final_report(json_dir, csv_dir):
    """Generate consolidated CSV report"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_csv = os.path.join(csv_dir, f"cve_report_{date_str}.csv")
    
    cve_dict = {}
    cutoff_date = datetime.utcnow() - timedelta(days=7)
    
    # Process all JSON files and aggregate data
    for root, _, files in os.walk(json_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                for entry in extract_cve_data(file_path):
                    # 时间过滤逻辑
                    pub_date = parse_iso_date(entry['published'])
                    mod_date = parse_iso_date(entry['lastModified'])
                    
                    # 检查是否满足时间条件
                    time_valid = False
                    if pub_date and pub_date >= cutoff_date:
                        time_valid = True
                    if mod_date and mod_date >= cutoff_date:
                        time_valid = True
                    if not time_valid:
                        continue
                    
                    cve_id = entry['cve_id']
                    
                    if cve_id not in cve_dict:
                        # Initialize new entry
                        cve_dict[cve_id] = {
                            **entry,
                            'vendors': set(),
                            'os_versions': set()
                        }
                        cve_dict[cve_id]['vendors'].add(entry['vendor'])
                        cve_dict[cve_id]['os_versions'].add(entry['os_version'])
                    else:
                        # Aggregate vendors and os_versions
                        cve_dict[cve_id]['vendors'].add(entry['vendor'])
                        cve_dict[cve_id]['os_versions'].add(entry['os_version'])
    
    # Prepare final report rows
    report_rows = []
    for cve_id, data in cve_dict.items():
        report_row = {
            'cve_id': cve_id,
            'vendor': '; '.join(sorted(data['vendors'])),
            'os_version': '; '.join(sorted(data['os_versions'])),
            'description': data['description'],
            'published': data['published'],
            'lastModified': data['lastModified'],
            'basescore': data['basescore'],
            'baseseverity': data['baseseverity'],
            'refer_url': data['refer_url'],
            'versionStartIncluding': data['versionStartIncluding'],
            'versionEndExcluding': data['versionEndExcluding']
        }
        report_rows.append(report_row)
    
    # Write to CSV
    fieldnames = [
        'cve_id', 'vendor', 'os_version', 'description', 'published',
        'lastModified', 'basescore', 'baseseverity', 'refer_url',
        'versionStartIncluding', 'versionEndExcluding'
    ]
    
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_rows)
    
    logging.info(f"Generated report with {len(report_rows)} entries")

if __name__ == "__main__":
    try:
        # Setup directories
        json_dir, csv_dir = create_output_dirs()
        
        # Step 1: Process inventory and save JSON results
        process_inventory(json_dir)
        
        # Step 2: Generate consolidated report
        generate_final_report(json_dir, csv_dir)
        
    except Exception as e:
        logging.critical(f"Main process failed: {str(e)}", exc_info=True)
