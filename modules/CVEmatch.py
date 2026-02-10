import nvdlib, AskAI, Notify, requests, json, re

def find_nvd(technologies):
    try:
        cve = list(nvdlib.searchCVE_V2(keywordSearch=technologies, limit=100))
        if not cve:
            return None, None
        cve.sort(key=lambda x: x.published, reverse=True)
    
        for cve in cve[:1]:
            cve_id = cve.id
            cve_desc = cve.descriptions[0].value
            return cve_id, cve_desc
    except Exception as e:
        return None, None
        
def get_cve_details(cveId):
    details = nvdlib.searchCVE(cveId=cveId)[0]
    return details.descriptions[0].value

def find_vulners(technologies):
    VULNERS_APIKEY = "VULNERSKEY"
    VULNERS_URL = "https://vulners.com/api/v3/search/lucene"

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": VULNERS_APIKEY
    }

    payload = {
        "query": technologies,
        "skip": 0,
        "size": 1,
        "sort": "published",
        "order": "desc",
        "fields": [
            "description",
            "title", 
            "cvelist"
        ]
    }

    try:
        response = requests.post(
            VULNERS_URL, 
            headers=headers, 
            json=payload
        )

        # Cek status code
        if response.status_code == 200:
            data = response.json()
            search_results = data.get('data', {}).get('search', [])
            if not search_results:
                return None, None
            first_item = search_results[0]
            source_data = first_item.get('_source', {})
            description = source_data.get('description', 'No description available')
            cvelist = source_data.get('cvelist', [])
            if not cvelist:
                cvelist = [] # Atau bisa return None

            return cvelist, description
        else:
            print(f"Error {response.status_code}: {response.text}")
            return None, None

    except Exception as e:
        print(f"Connection Error: {e}")
        return None, None

def match_cpe(cveid, technology):
    if not technology:
        return None
    else:
        technology = re.sub(r'[^a-z0-9]', '', technology.lower())

    results = nvdlib.searchCVE(cveId=cveid.upper())
    if not results:
        # print("CVE not found or API error occur.")
        return
    cve_item = results[0]
    if hasattr(cve_item, 'cpe'):
        for entry in cve_item.cpe:
            # print(entry.criteria)
            parts = entry.criteria.split(':')
            
            if len(parts) >= 5:
                cpe_product_raw = parts[4]
                cpe_product_clean = re.sub(r'[^a-z0-9]', '', cpe_product_raw.lower())

                if technology == cpe_product_clean:
                    # print("CPE found, technology used are affected")
                    return True
                else:
                    # print("No CPE found, technology used are not affected")
                    return False
    else:
        # print("CVE Exists but no CPE")
        return False

def find_cve(technology):
    cveid_nvd, cvedesc_nvd = find_nvd(technology)
    if cveid_nvd:
        return [cveid_nvd], cvedesc_nvd
    else:
        cveid_vulner, cvedesc_vulner = find_vulners(technology)
        if not cveid_vulner:
            return None, None
        valid_cves = []
        clean_techname = re.split(r'\s+(?=\d)', technology, maxsplit=1)[0]
        techname = technology.split()[0].lower()
        cvedesc_vulner = cvedesc_vulner.lower()
        for vuln in cveid_vulner:
            vuln = vuln.lower()
            if ((len(techname) >= 3 and techname in cvedesc_vulner) or (vuln in cvedesc_vulner)) and match_cpe(vuln, clean_techname):
                valid_cves.append(vuln.upper())
            else:
                try:
                    nvddesc = get_cve_details(vuln.upper())
                    # result = AskAI.compare_cve_details(nvddesc, cvedesc_vulner)
                    # if result:
                    #     valid_cves.append(vuln.upper())
                    print(f"asking GenAI about these comparison {nvddesc}\n{cvedesc_vulner}")
                except Exception as e:
                    continue

    if valid_cves:
        desc = get_cve_details(valid_cves[0])
        return valid_cves, desc
    else:
        return None, None

tech = 'jQuery UI 1.12.1'
# tech = 'nginx 1.20.1'
# cveid = 'CVE-2022-31160'
cveid = 'CVE-2014-7811'

a, b = find_cve(tech)
print(a)
print()
print(b)
print()


# match_cpe('CVE-2022-31160', 'jquery')