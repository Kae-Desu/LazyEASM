import wappalyzer

def scan_web_tech(web):
    tech_stack = []
    res = wappalyzer.analyze(web, scan_type="full")
    

    for url, techs in res.items():
        for tech_name, info in techs.items():
            version = info.get('version') or None
            if tech_name and version:
                tech_stack.append({
                    "technology": tech_name,
                    "version": version
                })
            else:
                continue

    return tech_stack

tech = scan_web_tech("https://admisi.unpar.ac.id")
for ent in tech:
    print(ent['technology'] + ' ' + ent['version'])