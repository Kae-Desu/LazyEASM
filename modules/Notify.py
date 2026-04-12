"""
Module: Notify.py
Purpose: Discord webhook notifications for LazyEASM
Functions:
    - send_message: Basic Discord message
    - test_webhook: Test webhook configuration
    - send_vulnerability_alert: Send grouped CVE alerts
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


def send_message(message: str, user_id: str = None) -> tuple:
    """
    Send message to Discord via webhook.
    
    Args:
        message: Message content to send
        user_id: Optional Discord user ID to ping (overrides env default)
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'
    
    webhook_url = get_env('DISCORD_WEBHOOK_URL')
    
    if not webhook_url:
        return False, 'Discord webhook URL not configured'
    
    ping_user = user_id or get_env('DISCORD_USER_ID')
    
    if ping_user:
        content = f"<@{ping_user}> {message}"
    else:
        content = message
    
    data = {"content": content}
    
    try:
        response = requests.post(webhook_url, json=data, timeout=10)
        response.raise_for_status()
        return True, f'Message sent successfully (HTTP {response.status_code})'
    except requests.exceptions.Timeout:
        return False, 'Request timed out'
    except requests.exceptions.ConnectionError:
        return False, 'Connection failed - check network or webhook URL'
    except requests.exceptions.HTTPError as e:
        return False, f'HTTP error: {e}'
    except Exception as e:
        return False, f'Unexpected error: {str(e)}'


def send_vulnerability_alert(assets_with_cves: dict, min_cvss: float = 5.0) -> tuple:
    """
    Send vulnerability alert to Discord, grouped by asset.
    
    Args:
        assets_with_cves: Dict from Wappalyzer results:
            {
                'scanme.nmap.org': {
                    'host': 'scanme.nmap.org',
                    'url': 'http://scanme.nmap.org',
                    'technologies': [...],
                    'cves': [
                        {'cve_id': 'CVE-2021-44228', 'cvss': 10.0, 'tech_name': 'Apache'},
                        ...
                    ]
                }
            }
        min_cvss: Minimum CVSS to include (default 5.0)
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'
    
    webhook_url = get_env('DISCORD_WEBHOOK_URL')
    
    if not webhook_url:
        return False, 'Discord webhook URL not configured'
    
    if not assets_with_cves:
        return True, 'No CVEs to report'
    
    embeds = []
    
    total_cves = 0
    total_assets = 0
    
    for host, data in assets_with_cves.items():
        cves = data.get('cves', [])
        
        filtered_cves = [c for c in cves if c.get('cvss', 0) >= min_cvss]
        
        if not filtered_cves:
            continue
        
        total_assets += 1
        total_cves += len(filtered_cves)
        
        cvss_scores = [c['cvss'] for c in filtered_cves]
        max_cvss = max(cvss_scores) if cvss_scores else 0
        
        if max_cvss >= 9.0:
            color = 15158332
        elif max_cvss >= 7.0:
            color = 16027660
        elif max_cvss >= 5.0:
            color = 16312092
        else:
            color = 9807270
        
        cve_list = []
        for cve in filtered_cves[:10]:
            cvss_str = f"{cve['cvss']:.1f}" if isinstance(cve.get('cvss'), (int, float)) else str(cve.get('cvss', 'N/A'))
            tech = cve.get('tech_name', 'Unknown')
            cve_list.append(f"• **{cve['cve_id']}** (CVSS: {cvss_str}) - {tech}")
        
        if len(filtered_cves) > 10:
            cve_list.append(f"... and {len(filtered_cves) - 10} more")
        
        embed = {
            "title": f"🔍 {host}",
            "color": color,
            "fields": [
                {
                    "name": f"Found {len(filtered_cves)} CVE(s)",
                    "value": "\n".join(cve_list),
                    "inline": False
                }
            ],
            "footer": {
                "text": f"Max CVSS: {max_cvss:.1f}"
            }
        }
        
        embeds.append(embed)
    
    if not embeds:
        return True, 'No CVEs above threshold'
    
    ping_user = get_env('DISCORD_USER_ID')
    
    data = {
        "content": f"{'<@' + ping_user + '>' if ping_user else ''} **LazyEASM - Vulnerability Alert**",
        "embeds": embeds[:10]
    }
    
    if len(embeds) > 10:
        data["embeds"][-1]["fields"].append({
            "name": "Truncated",
            "value": f"... and {len(embeds) - 10} more assets",
            "inline": False
        })
    
    final_embed = {
        "title": "Summary",
        "color": 9807270,
        "fields": [
            {
                "name": "Total CVEs",
                "value": str(total_cves),
                "inline": True
            },
            {
                "name": "Affected Assets",
                "value": str(total_assets),
                "inline": True
            }
        ]
    }
    data["embeds"].append(final_embed)
    
    try:
        response = requests.post(webhook_url, json=data, timeout=30)
        response.raise_for_status()
        return True, f'Alert sent successfully - {total_cves} CVEs across {total_assets} assets'
    except requests.exceptions.Timeout:
        return False, 'Request timed out'
    except requests.exceptions.ConnectionError:
        return False, 'Connection failed - check network or webhook URL'
    except requests.exceptions.HTTPError as e:
        return False, f'HTTP error: {e}'
    except Exception as e:
        return False, f'Unexpected error: {str(e)}'


def send_certificate_alert(expiring_certs: list) -> tuple:
    """
    Send SSL certificate expiry alert to Discord.
    Only shows certificates about to expire (not already expired).
    
    Args:
        expiring_certs: List of certs expiring soon (from get_expiring_certificates)
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'
    
    webhook_url = get_env('DISCORD_WEBHOOK_URL')
    
    if not webhook_url:
        return False, 'Discord webhook URL not configured'
    
    embeds = []
    
    def extract_org(issuer: str) -> str:
        if not issuer:
            return 'Unknown'
        import re
        match = re.search(r'O=([^,]+)', issuer)
        if match:
            return match.group(1).strip()
        return 'Unknown'
    
    # Expiring within 7 days (one per hostname, max 5)
    if expiring_certs:
        seen_hosts = set()
        for cert in expiring_certs:
            if len(seen_hosts) >= 5:
                break
            if cert['hostname'] in seen_hosts:
                continue
            seen_hosts.add(cert['hostname'])
            
            days = int(cert.get('days_until_expiry') or 0)
            if days <= 7:
                color = 15158332 if days <= 3 else 16027660
                embeds.append({
                    "title": f"⚠️ {cert['hostname']}",
                    "color": color,
                    "fields": [
                        {"name": "Expires In", "value": f"**{days}** days", "inline": True},
                        {"name": "Issuer", "value": extract_org(cert.get('issuer')), "inline": True}
                    ]
                })
    
    if not embeds:
        return True, 'No certificate alerts to send'
    
    ping_user = get_env('DISCORD_USER_ID')
    
    data = {
        "content": f"{'<@' + ping_user + '>' if ping_user else ''} **LazyEASM - SSL Certificate Alert**",
        "embeds": embeds
    }
    
    try:
        response = requests.post(webhook_url, json=data, timeout=30)
        response.raise_for_status()
        return True, f'Alert sent - {len(embeds)} certificate(s)'
    except requests.exceptions.Timeout:
        return False, 'Request timed out'
    except requests.exceptions.ConnectionError:
        return False, 'Connection failed'
    except requests.exceptions.HTTPError as e:
        return False, f'HTTP error: {e}'
    except Exception as e:
        return False, f'Unexpected error: {str(e)}'


def test_webhook() -> tuple:
    """
    Test Discord webhook configuration.
    
    Returns:
        Tuple of (success: bool, message: str)
    """
    webhook_url = get_env('DISCORD_WEBHOOK_URL')
    
    if not webhook_url:
        return False, 'Webhook URL not configured'
    
    test_message = '🔌 **LazyEASM Webhook Test**\nConnection successful - notifications will work!'
    
    return send_message(test_message)


if __name__ == '__main__':
    print("Testing Notify module...")
    print(f"Discord webhook configured: {'Yes' if get_env('DISCORD_WEBHOOK_URL') else 'No'}")
    print(f"Discord user ID configured: {'Yes' if get_env('DISCORD_USER_ID') else 'No'}")
    
    print("\n[1] Testing webhook connection:")
    success, message = test_webhook()
    print(f"  Result: {'✓' if success else '✗'} {message}")