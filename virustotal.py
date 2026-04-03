import hashlib
import requests

def scan_with_virustotal(file_bytes, api_key):
    """
    Phase 4: VirusTotal API integration
    Takes file bytes and an API key. Returns a dictionary with scan results.
    """
    if not api_key:
        return {"malicious_engines": 0, "total_engines": 0, "permalink": None, "error": "No API key provided"}
        
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            permalink = f"https://www.virustotal.com/gui/file/{sha256_hash}"
            return {"malicious_engines": malicious, "total_engines": total, "permalink": permalink, "error": None}
        elif response.status_code == 404:
            return {"malicious_engines": 0, "total_engines": 0, "permalink": None, "error": "File not found in VirusTotal database. Full upload required (not implemented in fast viewer)."}
        else:
            return {"malicious_engines": 0, "total_engines": 0, "permalink": None, "error": f"API Error {response.status_code}: {response.text}"}
    except Exception as e:
         return {"malicious_engines": 0, "total_engines": 0, "permalink": None, "error": str(e)}
