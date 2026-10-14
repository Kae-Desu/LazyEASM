"""
Exploit intelligence for CVE prioritization.

Sources:
    - CISA Known Exploited Vulnerabilities (KEV) catalog: CVEs exploited in
      the wild, with CISA's required action and due date
    - FIRST EPSS: probability that a CVE is exploited in the next 30 days

Priority (shown on findings and used for sorting):
    P1  in CISA KEV                     - exploited in the wild, patch now
    P2  EPSS >= 10%                     - likely to be exploited soon
    P3  CVSS >= 7.0                     - severe, but no exploitation signal
    P4  everything else
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

import requests
from utils.timeutil import utc_now_str

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100          # API default page size
KEV_CACHE_SECONDS = 6 * 3600   # CISA updates the catalog a few times a week
HTTP_TIMEOUT = 60

EPSS_HIGH = 0.10
CVSS_HIGH = 7.0

_kev_cache = {'fetched_at': 0.0, 'data': None}
_kev_lock = threading.Lock()


class IntelFetchError(Exception):
    """A threat-intel source could not be fetched."""


def compute_priority(cvss: Optional[float], epss: Optional[float], in_kev: bool) -> dict:
    """
    Returns:
        {'priority': 'P1'..'P4', 'reason': str}
    """
    if in_kev:
        return {'priority': 'P1', 'reason': 'Known exploited (CISA KEV)'}
    if epss is not None and epss >= EPSS_HIGH:
        return {'priority': 'P2', 'reason': f'EPSS {epss:.0%} chance of exploitation in 30 days'}
    if cvss is not None and cvss >= CVSS_HIGH:
        return {'priority': 'P3', 'reason': f'CVSS {cvss:.1f}, no exploitation signal'}
    if cvss is None:
        return {'priority': 'P4', 'reason': 'No CVSS score, no exploitation signal'}
    return {'priority': 'P4', 'reason': f'CVSS {cvss:.1f}, no exploitation signal'}


def fetch_kev(force: bool = False) -> Dict[str, dict]:
    """
    Download the CISA KEV catalog (cached in memory).

    Returns:
        {cve_id: {'date_added', 'due_date', 'required_action', 'ransomware'}}

    Raises:
        IntelFetchError
    """
    with _kev_lock:
        fresh = time.monotonic() - _kev_cache['fetched_at'] < KEV_CACHE_SECONDS
        if _kev_cache['data'] is not None and fresh and not force:
            return _kev_cache['data']

        try:
            response = requests.get(KEV_URL, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            entries = response.json().get('vulnerabilities', [])
        except (requests.RequestException, ValueError) as e:
            raise IntelFetchError(f"CISA KEV download failed: {e}") from e

        data = {}
        for entry in entries:
            cve_id = (entry.get('cveID') or '').upper()
            if cve_id:
                data[cve_id] = {
                    'date_added': entry.get('dateAdded'),
                    'due_date': entry.get('dueDate'),
                    'required_action': entry.get('requiredAction'),
                    'ransomware': entry.get('knownRansomwareCampaignUse') == 'Known',
                }
        if not data:
            raise IntelFetchError("CISA KEV catalog was empty")

        _kev_cache.update(fetched_at=time.monotonic(), data=data)
        return data


def fetch_epss(cve_ids: Iterable[str]) -> Dict[str, dict]:
    """
    Fetch EPSS scores in batches.

    Returns:
        {cve_id: {'epss': float, 'percentile': float, 'date': str}}
        CVEs without a score are absent.

    Raises:
        IntelFetchError if any batch fails
    """
    ids = sorted({c.upper() for c in cve_ids if c})
    scores = {}
    for i in range(0, len(ids), EPSS_BATCH_SIZE):
        batch = ids[i:i + EPSS_BATCH_SIZE]
        try:
            response = requests.get(EPSS_URL, params={'cve': ','.join(batch), 'limit': len(batch)},
                                    timeout=HTTP_TIMEOUT)
            response.raise_for_status()
            rows = response.json().get('data', [])
        except (requests.RequestException, ValueError) as e:
            raise IntelFetchError(f"EPSS request failed: {e}") from e

        for row in rows:
            try:
                scores[row['cve'].upper()] = {
                    'epss': float(row['epss']),
                    'percentile': float(row['percentile']),
                    'date': row.get('date'),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return scores


def refresh_threat_intel(cve_ids: Iterable[str] = None) -> dict:
    """
    Update cve_intel for the given CVEs (default: every CVE in vulnerabilities).

    A source that fails leaves its previously stored values untouched.

    Returns:
        {
            'cves_checked': int,
            'kev_count': int,          # checked CVEs currently in KEV
            'newly_kev': [{'cve_id', 'hosts', 'due_date', 'ransomware', 'required_action'}],
            'errors': [str]
        }
    """
    from utils.db_utils import get_all_vulnerability_cve_ids, get_cve_intel, upsert_cve_intel, \
        get_open_hosts_for_cve, set_setting

    ids = sorted({c.upper() for c in (cve_ids if cve_ids is not None else get_all_vulnerability_cve_ids())
                  if c and c.upper().startswith('CVE-')})
    result = {'cves_checked': len(ids), 'kev_count': 0, 'newly_kev': [], 'errors': []}
    if not ids:
        return result

    try:
        kev = fetch_kev()
    except IntelFetchError as e:
        kev = None
        result['errors'].append(str(e))
        logger.warning(str(e))

    try:
        epss = fetch_epss(ids)
    except IntelFetchError as e:
        epss = None
        result['errors'].append(str(e))
        logger.warning(str(e))

    previous = get_cve_intel(ids)
    for cve_id in ids:
        kev_entry = kev.get(cve_id) if kev is not None else None
        upsert_cve_intel(
            cve_id,
            epss=epss.get(cve_id) if epss is not None else None,
            kev=kev_entry,
            update_epss=epss is not None,
            update_kev=kev is not None,
        )
        if kev_entry:
            result['kev_count'] += 1
            if not previous.get(cve_id, {}).get('in_kev'):
                hosts = get_open_hosts_for_cve(cve_id)
                if hosts:
                    result['newly_kev'].append({
                        'cve_id': cve_id,
                        'hosts': hosts,
                        'due_date': kev_entry['due_date'],
                        'ransomware': kev_entry['ransomware'],
                        'required_action': kev_entry['required_action'],
                    })

    if cve_ids is None:
        set_setting('last_intel_check', utc_now_str())

    logger.info(f"Threat intel refreshed for {len(ids)} CVEs: {result['kev_count']} in KEV, "
                f"{len(result['newly_kev'])} newly KEV, {len(result['errors'])} errors")
    return result


def refresh_quietly(cve_ids: List[str]) -> None:
    """
    Refresh intel for CVEs found by a scan and alert on any that are
    actively exploited. Never raises, so a scan is never failed by it.
    """
    try:
        if not cve_ids:
            return
        result = refresh_threat_intel(cve_ids)
        if result['newly_kev']:
            from utils.phase3_worker import send_kev_notification
            send_kev_notification(result)
    except Exception as e:
        logger.warning(f"Threat intel refresh after scan failed: {e}")


if __name__ == '__main__':
    import argparse

    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description='Refresh EPSS / CISA KEV data')
    parser.add_argument('cves', nargs='*', help='CVE IDs to look up without touching the DB')
    args = parser.parse_args()

    if args.cves:
        kev = fetch_kev()
        scores = fetch_epss(args.cves)
        for cve in args.cves:
            cve = cve.upper()
            s = scores.get(cve, {})
            p = compute_priority(None, s.get('epss'), cve in kev)
            print(f"{cve}: KEV={'yes' if cve in kev else 'no'} EPSS={s.get('epss')} "
                  f"percentile={s.get('percentile')} -> {p['priority']} ({p['reason']})")
    else:
        print(refresh_threat_intel())
