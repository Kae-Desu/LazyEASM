"""
Module: Notify.py
Purpose: Notifications for LazyEASM

Channels (each enabled by its settings; all configured channels receive
every notification, except that alerts about the hosts of a group with its
own channels go to that group's channels, see utils/groups.py):
    - Discord   DISCORD_WEBHOOK_URL (+ DISCORD_USER_ID to ping)
    - Slack     SLACK_WEBHOOK_URL (incoming webhook)
    - Webhook   NOTIFY_WEBHOOK_URL: JSON POST; with NOTIFY_WEBHOOK_SECRET the
                body is signed (X-LazyEASM-Signature: sha256=<hex HMAC>)
    - Email     SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
                SMTP_FROM, SMTP_TO (comma separated),
                SMTP_SECURITY (starttls | ssl | none)

Functions:
    - send_message: Send a message to every configured channel
    - send_about: Send an alert listing several hosts, split per group
    - test_webhook: Send a test message to every configured channel
    - send_vulnerability_alert: Grouped CVE alerts (Discord embeds, text elsewhere)
    - send_cert_expiry_threshold_alert: Certificate expiry alerts
"""

import hashlib
import hmac
import json
import os
import re
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

HTTP_TIMEOUT = 15
SMTP_TIMEOUT = 20


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def _plain(text: str) -> str:
    """Strip Discord markdown for email / generic webhooks."""
    return re.sub(r'\*\*(.+?)\*\*', r'\1', text or '').strip()


def _slack(text: str) -> str:
    """Discord **bold** -> Slack *bold*."""
    return re.sub(r'\*\*(.+?)\*\*', r'*\1*', text or '').strip()


def _title(text: str) -> str:
    first = next((line for line in _plain(text).splitlines() if line.strip()), 'LazyEASM notification')
    return first.strip()[:120]


def _embeds_as_text(heading: str, embeds: list) -> str:
    """Plain-text rendering of Discord embeds for the other channels."""
    lines = [heading]
    for embed in embeds:
        lines.append('')
        if embed.get('title'):
            lines.append(f"**{embed['title']}**")
        if embed.get('description'):
            lines.append(embed['description'])
        for f in embed.get('fields', []):
            lines.append(f"{f['name']}: {f['value']}")
        if embed.get('footer', {}).get('text'):
            lines.append(embed['footer']['text'])
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Channels: each returns (success, detail) or None when not configured
# ---------------------------------------------------------------------------

def _post(url: str, **kwargs) -> tuple:
    try:
        response = requests.post(url, timeout=HTTP_TIMEOUT, **kwargs)
        response.raise_for_status()
        return True, f'HTTP {response.status_code}'
    except requests.exceptions.Timeout:
        return False, 'Request timed out'
    except requests.exceptions.ConnectionError:
        return False, 'Connection failed - check network or URL'
    except requests.exceptions.HTTPError as e:
        return False, f'HTTP error: {e.response.status_code if e.response is not None else e}'
    except requests.exceptions.RequestException as e:
        return False, f'Request error: {e}'


def default_channels() -> dict:
    """The channels set in .env (Settings > Notifications)."""
    return {
        'discord_webhook': get_env('DISCORD_WEBHOOK_URL'),
        'discord_user_id': get_env('DISCORD_USER_ID'),
        'slack_webhook': get_env('SLACK_WEBHOOK_URL'),
        'webhook_url': get_env('NOTIFY_WEBHOOK_URL'),
        'webhook_secret': get_env('NOTIFY_WEBHOOK_SECRET'),
        'email_to': get_env('SMTP_TO'),
    }


def _send_discord(channels: dict, message: str = None, payload: dict = None, user_id: str = None):
    webhook_url = channels.get('discord_webhook')
    if not webhook_url:
        return None
    if payload is None:
        ping_user = user_id or channels.get('discord_user_id')
        payload = {"content": f"<@{ping_user}> {message}" if ping_user else message}
    return _post(webhook_url, json=payload)


def _send_slack(channels: dict, message: str):
    url = channels.get('slack_webhook')
    if not url:
        return None
    return _post(url, json={'text': _slack(message)})


def _send_webhook(channels: dict, message: str):
    url = channels.get('webhook_url')
    if not url:
        return None
    body = json.dumps({
        'source': 'lazyeasm',
        'title': _title(message),
        'message': _plain(message),
        'markdown': message,
        'sent_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    }, ensure_ascii=False).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    secret = channels.get('webhook_secret')
    if secret:
        signature = hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()
        headers['X-LazyEASM-Signature'] = f'sha256={signature}'
    return _post(url, data=body, headers=headers)


def _send_email(channels: dict, message: str):
    # The SMTP server is always the one in .env; groups only choose recipients
    host = get_env('SMTP_HOST')
    recipients = [r.strip() for r in (channels.get('email_to') or '').split(',') if r.strip()]
    if not host or not recipients:
        return None

    port = int(get_env('SMTP_PORT') or 587)
    security = (get_env('SMTP_SECURITY') or 'starttls').strip().lower()
    username = get_env('SMTP_USERNAME')
    password = get_env('SMTP_PASSWORD')

    email = EmailMessage()
    email['Subject'] = f"[LazyEASM] {_title(message)}"
    email['From'] = get_env('SMTP_FROM') or username or 'lazyeasm@localhost'
    email['To'] = ', '.join(recipients)
    email.set_content(_plain(message))

    try:
        context = ssl.create_default_context()
        if security == 'ssl':
            server = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT)
        with server:
            if security == 'starttls':
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.send_message(email)
        return True, f'sent to {len(recipients)} recipient(s)'
    except (smtplib.SMTPException, OSError) as e:
        return False, f'SMTP error: {e}'


OTHER_CHANNELS = {'slack': _send_slack, 'webhook': _send_webhook, 'email': _send_email}


def _summarize(results: dict) -> tuple:
    """Combine per-channel results into (success, message)."""
    results = {name: r for name, r in results.items() if r is not None}
    if not results:
        return False, 'No notification channel configured'
    ok = [name for name, (success, _) in results.items() if success]
    failed = [f"{name}: {detail}" for name, (success, detail) in results.items() if not success]
    message = f"Sent via {', '.join(ok)}" if ok else 'All channels failed'
    if failed:
        message += f" | Failed: {'; '.join(failed)}"
    return bool(ok), message


def _send_to_other_channels(channels: dict, message: str) -> dict:
    return {name: send(channels, message) for name, send in OTHER_CHANNELS.items()}


class Destination:
    """
    One set of channels: the default channels (group_id None) or a group's.
    Passed to the message builders of send_about() as the host filter.
    """

    def __init__(self, group_id, hosts, channels):
        self.group_id = group_id
        self.hosts = {h.lower() for h in hosts}
        self.channels = channels

    @property
    def default(self) -> bool:
        return self.group_id is None

    def __call__(self, host) -> bool:
        return bool(host) and host.lower() in self.hosts


def _destinations(hosts) -> list:
    """The destinations for alerts about these hosts (all default when routing fails)."""
    hosts = [h for h in hosts if h]
    try:
        from utils import groups
        found = []
        for group_id, routed in groups.notification_routes(hosts).items():
            channels = default_channels() if group_id is None else groups.get_channels(group_id)
            found.append(Destination(group_id, routed, channels))
        return found
    except Exception as e:
        print(f"[Notify] Group routing failed, using the default channels: {e}")
        return [Destination(None, hosts, default_channels())] if hosts else []


def _merge(outcomes: list) -> tuple:
    """Combine (success, message) of several destinations."""
    if not outcomes:
        return True, 'Nothing to send'
    if len(outcomes) == 1:
        return outcomes[0]
    return any(ok for ok, _ in outcomes), ' / '.join(message for _, message in outcomes)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _deliver(channels: dict, message: str, user_id: str = None) -> tuple:
    results = {'discord': _send_discord(channels, message, user_id=user_id)}
    results.update(_send_to_other_channels(channels, message))
    return _summarize(results)


def send_message(message: str, user_id: str = None, hosts=None) -> tuple:
    """
    Send a message to every configured channel.

    Args:
        message: Message content (Discord markdown)
        user_id: Optional Discord user ID to ping (overrides env default)
        hosts: hostnames/IPs the message is about; it then goes to the
            channels of their groups (see utils/groups.py) instead of only
            the default channels. Leave out for messages about the server.

    Returns:
        Tuple of (success: bool, message: str); success if any channel delivered
    """
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'
    if hosts is None:
        return _deliver(default_channels(), message, user_id)
    return _merge([_deliver(d.channels, message, user_id if d.default else None) for d in _destinations(hosts)])


def send_about(hosts, build) -> tuple:
    """
    Send an alert that lists several hosts, split by destination so a group's
    channels only see that group's hosts.

    Args:
        hosts: every host the alert may mention
        build: build(keep) -> message or None; keep(host) says whether a host
            belongs in this copy, keep.default whether it goes to the default
            channels (which may also get totals across all hosts)
    """
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'
    outcomes = []
    for destination in _destinations(hosts):
        message = build(destination)
        if message:
            outcomes.append(_deliver(destination.channels, message))
    return _merge(outcomes)


def send_group_test(group_id: int) -> tuple:
    """Send a test message to one group's own channels."""
    from utils import groups
    channels = groups.get_channels(group_id)
    if not groups.has_channels(channels):
        return False, 'This group has no channels of its own'
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'
    name = groups.label(f"g:{group_id}")
    return _deliver(channels, f'**Notification Test**\nAlerts about the group "{name}" will arrive here.')


def _send_embeds(channels: dict, heading: str, embeds: list) -> dict:
    """Discord gets the embeds; other channels get a text rendering."""
    ping_user = channels.get('discord_user_id')
    payload = {"content": f"{'<@' + ping_user + '>' if ping_user else ''} **{heading}**", "embeds": embeds}
    results = {'discord': _send_discord(channels, payload=payload)}
    results.update(_send_to_other_channels(channels, _embeds_as_text(f"**{heading}**", embeds)))
    return results


def send_vulnerability_alert(assets_with_cves: dict, min_cvss: float = 5.0) -> tuple:
    """
    Send vulnerability alert, grouped by asset.

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

    if not assets_with_cves:
        return True, 'No CVEs to report'

    outcomes = []
    for destination in _destinations(list(assets_with_cves)):
        part = {host: data for host, data in assets_with_cves.items() if destination(host)}
        outcome = _vulnerability_alert(destination.channels, part, min_cvss)
        if outcome:
            outcomes.append(outcome)
    return _merge(outcomes) if outcomes else (True, 'No CVEs above threshold')


def _vulnerability_alert(channels: dict, assets_with_cves: dict, min_cvss: float):
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

        embeds.append({
            "title": f"{host}",
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
        })

    if not embeds:
        return None

    hidden = len(embeds) - 10
    embeds = embeds[:10]
    if hidden > 0:
        embeds[-1]["fields"].append({
            "name": "Truncated",
            "value": f"... and {hidden} more assets",
            "inline": False
        })

    embeds.append({
        "title": "Summary",
        "color": 9807270,
        "fields": [
            {"name": "Total CVEs", "value": str(total_cves), "inline": True},
            {"name": "Affected Assets", "value": str(total_assets), "inline": True}
        ]
    })

    success, message = _summarize(_send_embeds(channels, 'Vulnerability Alert', embeds))
    if success:
        message = f'Alert sent - {total_cves} CVEs across {total_assets} assets ({message})'
    return success, message


def send_cert_expiry_threshold_alert(threshold_certs: dict) -> tuple:
    """
    Send SSL certificate expiry alerts grouped by threshold (7, 5, 3, 1 days).

    Args:
        threshold_certs: {7: [{cert_id, hostname}, ...], 5: [...], 3: [...], 1: [...]}

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not REQUESTS_AVAILABLE:
        return False, 'requests library not installed'

    hosts = [c['hostname'] for certs in threshold_certs.values() for c in certs]
    outcomes = []
    for destination in _destinations(hosts):
        part = {t: [c for c in certs if destination(c['hostname'])] for t, certs in threshold_certs.items()}
        outcome = _cert_expiry_alert(destination.channels, part)
        if outcome:
            outcomes.append(outcome)
    return _merge(outcomes) if outcomes else (True, 'No certificate alerts to send')


def _cert_expiry_alert(channels: dict, threshold_certs: dict):
    colors = {7: 16098851, 5: 16027660, 3: 15158332, 1: 15548997}
    severity = {7: "Warning", 5: "Warning", 3: "Critical", 1: "Critical"}

    embeds = []

    for threshold in [1, 3, 5, 7]:
        certs = threshold_certs.get(threshold, [])
        if not certs:
            continue

        level = severity[threshold]
        day_text = "1 day" if threshold == 1 else f"{threshold} days"
        title = f"{level}: {day_text} or less until expiry"

        cert_lines = [f"• {c['hostname']}" + (f" ({c['days']}d left)" if 'days' in c else '') for c in certs[:10]]
        if len(certs) > 10:
            cert_lines.append(f"• ... and {len(certs) - 10} more")

        embeds.append({
            "title": title,
            "description": "\n".join(cert_lines),
            "color": colors[threshold]
        })

    if not embeds:
        return None

    success, message = _summarize(_send_embeds(channels, 'SSL Certificate Expiry Alert', embeds))
    if success:
        total = sum(len(c) for c in threshold_certs.values())
        message = f'Alert sent - {total} certificate(s) across {len(embeds)} threshold(s) ({message})'
    return success, message


def configured_channels() -> list:
    """Names of the channels that have settings."""
    channels = []
    if get_env('DISCORD_WEBHOOK_URL'):
        channels.append('discord')
    if get_env('SLACK_WEBHOOK_URL'):
        channels.append('slack')
    if get_env('NOTIFY_WEBHOOK_URL'):
        channels.append('webhook')
    if get_env('SMTP_HOST') and get_env('SMTP_TO'):
        channels.append('email')
    return channels


def test_webhook() -> tuple:
    """
    Send a test message to every configured channel.

    Returns:
        Tuple of (success: bool, message: str)
    """
    if not configured_channels():
        return False, 'No notification channel configured'
    return send_message('**Notification Test**\nConnection successful - notifications will work!')


if __name__ == '__main__':
    print("Testing Notify module...")
    print(f"Configured channels: {', '.join(configured_channels()) or 'none'}")
    success, message = test_webhook()
    print(f"  Result: {'✓' if success else '✗'} {message}")
