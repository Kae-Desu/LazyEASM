import requests, json

def get_ct_logs(domain):
    url = f"https://crt.sh/json?q={domain}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
        else:
            print(f"Error: Received status code {response.status_code}")
            return []
        return data
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def extract_subdomains(data):
        subdomain = set()
        for entry in data:
            subdomain.add(entry['common_name'])
            for name in entry['name_value'].split('\n'):
                subdomain.add(name)
        return sorted(list(subdomain))

subs = get_ct_logs("")
subs2 = extract_subdomains(subs)
print(f"found {len(subs2)} subdomains from CT logs")
for s in subs2:
    print(s)
