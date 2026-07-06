import time
import requests
from src.api_clients import check_abuseipdb
from src.api_clients import check_virustotal
from src.api_clients import check_alienvault
from src.pdf_generator import generate_pdf_report
from src.firewall_menager import block_ip_address

def load_ip_from_file(path):
    lists_ip = []
    try:
        with open(path, "r") as file:
            for line in file:
                ip = line.strip()
                if ip:
                    lists_ip.append(ip)
        return lists_ip
    except FileNotFoundError:
        print(f"Error: The file at location {path} was not found.")
        return None
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
def ip_analyze(ip_address, verbose=True):
    
    if verbose:
        print(f"Running a full Threat Intel analysis for the address: {ip_address}")
        print("-" * 50)
        print("Scanning through AbuseIPDB...")
    abuseIPDB = check_abuseipdb(ip_address)
    if verbose:
        print("Scanning through VirusTotal...")
    virusTotal = check_virustotal(ip_address)
    time.sleep(15)
    if verbose:
        print("Scanning through AlienVault OTX...")
    otx = check_alienvault(ip_address)
    
    results = {
        "ip": ip_address,
        "abuse_score": abuseIPDB,
        "virustotal": virusTotal,
        "alienvault": otx
    }
    return results


if __name__ == "__main__":
    print("=" * 50)
    print("        THREAT INTELLIGENCE AUTOMATOR - MENU        ")
    print("=" * 50)
    print("1. Scan one IP address")
    print("2. Load a file with a list of IP addresses")
    print("-" * 50)
    
    choice = input("Select an option: ").strip()
    all_analyses = []
    
    if choice == "1":
        ip_input = input("Enter the IP address to check: ").strip()
        if ip_input:
            result = ip_analyze(ip_input)
            all_analyses.append(result)
            if result:
                print("\n" + "*" * 50)
                print("RESULT")
                print("AbuseIPDB")
                print(f"AbuseIPDB Score: {result['abuse_score']}%")
                vt = result['virustotal']
                print("-" * 50)
                if vt:
                    print("VirusTotal")
                    print(f"Malicious: {vt['malicious']}")
                    print(f"Suspicious: {vt['suspicious']}")
                    print(f"Harmless: {vt['harmless']}")
                    print(f"Undetected: {vt['undetected']}")
                    print(f"Total scanners: {vt['total']}")
                else:
                    print("VirusTotal data is not available.")
                print("-" * 50)

                otx =result['alienvault']
                if otx:
                    print("AlienVault OTX")
                    print(f"Pulses: {otx['number_pulses']}")
                    print(f"Tags: {otx['tags']}")
                else:
                    print("AlienVault OTX data is not available.")
                
                if result['abuse_score'] > 80 or (result['virustotal'] and result['virustotal'].get('malicious', 0) > 3):
                    print(f"[Warning] {ip_input} is highly malicious! Initiating automated block...")
                    block_ip_address(ip_input)

    elif choice == "2":
        path = input("Enter the path to the .txt file: ").strip()
        ip_list = load_ip_from_file(path)
        if ip_list:
            print(f"Found {len(ip_list)} IP address to scan.")
            print("Starting background analysis. Please whait...\n")
            for serial_number, ip in enumerate(ip_list, 1):
                print(f"\n Scanning ({serial_number}/{len(ip_list)}): {ip}")
                result = ip_analyze(ip, verbose=False)
                all_analyses.append(result)

                if result['abuse_score'] > 80 or (result['virustotal'] and result['virustotal'].get('malicious', 0) > 3):
                    print(f"[Warning] {ip} is highly malicious! Initiating automated block...")
                    block_ip_address(ip)

    else:
        print("Wrong choice. Run the script again.")

    if all_analyses and choice == "2":
        print("\n" + "=" * 50)
        print("Scanning completed.")
        print(f"Total scanned addresses: {len(all_analyses)}")
        print("=" * 50)
        print("Generating PDF report...")
        generate_pdf_report(all_analyses, name_file="TIR.pdf")
    
