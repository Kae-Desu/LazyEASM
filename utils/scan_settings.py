"""
Scanning settings edited in the dashboard (stored in the settings table).

    - Phase 3 check intervals: re-read by the worker on every scheduler
      cycle, so a change applies without a restart
    - Minimum CVSS score for CVE findings
"""

from typing import Dict, List, Tuple

# name, label, setting key, default, unit, min, max
SCHEDULE = [
    ('liveness', 'Liveness check', 'liveness_interval_min', 5, 'minutes', 1, 1440),
    ('ctlogs', 'CT logs poll', 'ctlogs_interval_hr', 1, 'hours', 1, 168),
    ('wappalyzer', 'Technology re-scan', 'wappalyzer_interval_hr', 24, 'hours', 1, 720),
    ('takeover', 'Subdomain takeover check', 'takeover_interval_hr', 24, 'hours', 1, 720),
    ('intel', 'Exploit intel (KEV / EPSS)', 'intel_interval_hr', 24, 'hours', 1, 720),
    ('misconfig', 'Misconfiguration check', 'misconfig_interval_hr', 24, 'hours', 1, 720),
    ('discovery', 'Subdomain discovery', 'discovery_interval_hr', 24, 'hours', 1, 720),
    ('screenshots', 'Web screenshots', 'screenshot_interval_hr', 24, 'hours', 1, 720),
]

CVE_MIN_CVSS_KEY = 'cve_min_cvss'
CVE_MIN_CVSS_DEFAULT = 5.0


def _get(key: str):
    from utils.db_utils import get_setting
    return get_setting(key)


def interval_value(key: str, default: int, low: int, high: int) -> int:
    """Stored interval, or the default if missing or out of range."""
    try:
        value = int(_get(key) or default)
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def get_schedule() -> List[Dict]:
    """Schedule rows for the dashboard, with current values."""
    return [
        {'name': name, 'label': label, 'key': key, 'unit': unit, 'min': low, 'max': high,
         'value': interval_value(key, default, low, high)}
        for name, label, key, default, unit, low, high in SCHEDULE
    ]


def get_cve_min_cvss() -> float:
    try:
        value = float(_get(CVE_MIN_CVSS_KEY) or CVE_MIN_CVSS_DEFAULT)
    except (TypeError, ValueError):
        return CVE_MIN_CVSS_DEFAULT
    return value if 0.0 <= value <= 10.0 else CVE_MIN_CVSS_DEFAULT


def save_scanning_settings(form) -> Tuple[List[str], List[str]]:
    """
    Validate and store submitted values. Nothing is stored if any value is invalid.

    Returns:
        (errors, changed labels)
    """
    from utils.db_utils import set_setting

    errors, updates = [], []
    for name, label, key, default, unit, low, high in SCHEDULE:
        raw = (form.get(key) or '').strip()
        if not raw:
            continue
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{label}: must be a whole number")
            continue
        if not low <= value <= high:
            errors.append(f"{label}: must be between {low} and {high} {unit}")
            continue
        if value != interval_value(key, default, low, high):
            updates.append((key, str(value), label))

    raw = (form.get(CVE_MIN_CVSS_KEY) or '').strip()
    if raw:
        try:
            value = round(float(raw), 1)
            if not 0.0 <= value <= 10.0:
                raise ValueError
        except ValueError:
            errors.append("Minimum CVSS: must be a number between 0 and 10")
        else:
            if value != get_cve_min_cvss():
                updates.append((CVE_MIN_CVSS_KEY, str(value), 'Minimum CVSS'))

    if errors:
        return errors, []
    for key, value, _ in updates:
        set_setting(key, value)
    return [], [label for _, _, label in updates]
