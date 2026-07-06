import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check_abuseipdb(ip_address):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    url = "https://api.abuseipdb.com/api/v2/check"
    
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    try:
        answer = requests.get(url, headers=headers, params=params)
        
        if answer.status_code == 200:
            data = answer.json()
            score = data["data"]["abuseConfidenceScore"]
            return score
        else:
            print (f"Error with AbuseIPDB: Status code {answer.status_code}")
            return None
    except Exception as e:
        print(f"Error connect to AbuseIPDB: {e}")
        return None
    
def check_virustotal(ip_address):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    try:
        answer = requests.get(url,headers=headers)
        if answer.status_code == 200:
            data = answer.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
        
            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values())
            }
        
            return result
        else:
            print(f"Error with VirusTotal: Status code {answer.status_code}")
            return None
    except Exception as e:
        print(f"Error connect to VirusTotal: {e}")
        return None
    
def check_alienvault(ip_address):
    api_key = os.getenv("OTX_API_KEY")
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    
    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json"
    }
    try:
        answer = requests.get(url, headers=headers)
        if answer.status_code == 200:
            data = answer.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            
            number_pulses = len(pulses)
            all_tags = set()
            for pulse in pulses:
                tags = pulse.get("tags", [])
                for tag in tags:
                    all_tags.add(tag.lower())
            result = {
                "number_pulses": number_pulses,
                "tags": list(all_tags)
            }
            return result
        else:
            print(f"Error with AlienVault: Status code {answer.status_code}")
            return None
    except Exception as e:
        print(f"Error connect to AlienVault: {e}")
    
                     