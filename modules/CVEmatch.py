"""
Module: CVEmatch.py
Purpose: CVE vulnerability matching for detected technologies
Flow:
    1. Query NVD API for CVEs
    2. Fallback to Vulners API
    3. Extract CVSS score and description
    4. Return structured CVE data
"""

import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env

try:
    import nvdlib
    NVDLIB_AVAILABLE = True
except ImportError:
    NVDLIB_AVAILABLE = False

import requests

VULNERS_API_KEY = get_env('VULNERS_API_KEY', '')
VULNERS_URL = "https://vulners.com/api/v3/search/lucene"


def get_cvss_score(cve) -> float:
    """
    Extract CVSS score from NVD CVE object.
    
    Args:
        cve: nvdlib CVE object
    
    Returns:
        CVSS score (float) or 0.0 if not available
    """
    try:
        if hasattr(cve, 'metrics') and cve.metrics:
            metrics = cve.metrics
            
            if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                return metrics.cvssMetricV31[0].cvssData.baseScore
            elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
                return metrics.cvssMetricV30[0].cvssData.baseScore
            elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                return metrics.cvssMetricV2[0].cvssData.baseScore
        
        if hasattr(cve, 'cvssScore') and cve.cvssScore:
            return float(cve.cvssScore)
        
        return 0.0
    except Exception:
        return 0.0


def find_nvd(technology: str, limit: int = 10):
    """
    Search NVD API for CVEs related to technology.
    
    Args:
        technology: Technology name (e.g., 'nginx 1.20.1')
        limit: Maximum CVEs to return
    
    Returns:
        List of CVE dicts: [{'cve_id': str, 'cvss': float, 'description': str}, ...]
    """
    if not NVDLIB_AVAILABLE:
        return []
    
    try:
        cve_list = list(nvdlib.searchCVE_V2(keywordSearch=technology, limit=limit))
        if not cve_list:
            return []
        
        cve_list.sort(key=lambda x: get_cvss_score(x), reverse=True)
        
        results = []
        for cve in cve_list[:limit]:
            cve_id = cve.id
            cvss_score = get_cvss_score(cve)
            
            description = None
            if hasattr(cve, 'descriptions') and cve.descriptions:
                description = cve.descriptions[0].value
            
            results.append({
                'cve_id': cve_id,
                'cvss': cvss_score,
                'description': description or 'No description available'
            })
        
        return results
    except Exception:
        return []


def get_cve_details(cve_id: str):
    """
    Get CVE details from NVD including CVSS score.
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2023-1234')
    
    Returns:
        Dict: {'cve_id': str, 'cvss': float, 'description': str} or None
    """
    if not NVDLIB_AVAILABLE:
        return None
    
    try:
        results = list(nvdlib.searchCVE(cveId=cve_id.upper()))
        if results:
            cve = results[0]
            cvss_score = get_cvss_score(cve)
            description = cve.descriptions[0].value if hasattr(cve, 'descriptions') else None
            
            return {
                'cve_id': cve_id.upper(),
                'cvss': cvss_score,
                'description': description or 'No description available'
            }
    except Exception:
        pass
    
    return None


def find_vulners(technology: str):
    """
    Search Vulners API for CVEs related to technology.
    
    Args:
        technology: Technology name
    
    Returns:
        List of CVE dicts: [{'cve_id': str, 'cvss': float, 'description': str}, ...]
    """
    if not VULNERS_API_KEY:
        return []
    
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": VULNERS_API_KEY
    }
    
    payload = {
        "query": technology,
        "skip": 0,
        "size": 10,
        "sort": "cvss",
        "order": "desc",
        "fields": ["description", "title", "cvelist", "cvss"]
    }
    
    try:
        response = requests.post(
            VULNERS_URL,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            search_results = data.get('data', {}).get('search', [])
            
            if not search_results:
                return []
            
            results = []
            for item in search_results[:10]:
                source_data = item.get('_source', {})
                cvelist = source_data.get('cvelist', [])
                description = source_data.get('description', 'No description available')
                cvss_score = source_data.get('cvss', 0.0)
                
                if isinstance(cvss_score, (int, float)):
                    cvss_score = float(cvss_score)
                else:
                    cvss_score = 0.0
                
                for cve_id in cvelist:
                    results.append({
                        'cve_id': cve_id.upper() if cve_id else None,
                        'cvss': cvss_score,
                        'description': description
                    })
            
            return results
        else:
            return []
    
    except Exception:
        return []


def find_cve(technology: str, min_cvss: float = 0.0) -> dict:
    """
    Find CVEs for a given technology.
    
    Searches NVD first, then Vulners as fallback.
    Filters by minimum CVSS score.
    
    Args:
        technology: Technology name with version (e.g., 'nginx 1.20.1')
        min_cvss: Minimum CVSS score to include (default 0.0)
    
    Returns:
        Dict: {
            'technology': str,
            'cves': [
                {'cve_id': str, 'cvss': float, 'description': str, 'tech_name': str},
                ...
            ]
        }
    """
    tech_name = technology.split()[0] if technology else 'unknown'
    
    cves = find_nvd(technology)
    
    if not cves:
        cves = find_vulners(technology)
    
    valid_cves = []
    seen_ids = set()
    
    for cve in cves:
        cve_id = cve.get('cve_id')
        cvss = cve.get('cvss', 0.0)
        description = cve.get('description', 'No description available')
        
        if not cve_id or cve_id in seen_ids:
            continue
        
        if cvss < min_cvss:
            continue
        
        seen_ids.add(cve_id)
        valid_cves.append({
            'cve_id': cve_id,
            'cvss': cvss,
            'description': description,
            'tech_name': tech_name
        })
    
    return {
        'technology': technology,
        'cves': valid_cves
    }


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    print("Testing CVEmatch...")
    print(f"Vulners API Key configured: {'Yes' if VULNERS_API_KEY else 'No'}")
    print(f"NVDlib available: {'Yes' if NVDLIB_AVAILABLE else 'No'}")
    
    test_tech = 'apache 2.4.7'
    print(f"\nSearching CVEs for: {test_tech}")
    
    result = find_cve(test_tech, min_cvss=5.0)
    
    if result['cves']:
        print(f"Found {len(result['cves'])} CVEs:")
        for cve in result['cves']:
            print(f"  {cve['cve_id']} (CVSS: {cve['cvss']})")
            print(f"    {cve['description'][:100]}...")
    else:
        print("No CVEs found or API not configured")