import requests

def get_cve_data(cve_id):
    """
    Fetch CVE details from the CIRCL CVE API.
    Returns CVE data dict or None if not found.
    """
    if not cve_id or not cve_id.startswith('CVE-'):
        return None

    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if data:
                return {
                    'cve_id': cve_id,
                    'summary': data.get('summary', 'No description available'),
                    'cvss_score': data.get('cvss', 'N/A'),
                    'published': data.get('Published', 'N/A'),
                    'references': data.get('references', [])[:3]
                }
        return None

    except requests.exceptions.Timeout:
        print(f"[!] Timeout fetching CVE data for {cve_id}")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[!] Connection error fetching CVE data for {cve_id}")
        return None
    except Exception as e:
        print(f"[!] Error fetching CVE data: {e}")
        return None

def search_cves_by_keyword(keyword):
    """Search CVEs by keyword."""
    try:
        url = f"https://cve.circl.lu/api/search/{keyword}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        print(f"[!] Error searching CVEs: {e}")
        return []
