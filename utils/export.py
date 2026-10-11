"""
CSV / JSON export of assets and findings.

CSV cells that start with a formula character get a leading apostrophe, so
values taken from scanned targets (titles, hostnames, evidence) cannot run
as formulas when the file is opened in a spreadsheet.
"""

import csv
import io
import json

FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')

ASSET_COLUMNS = [
    'name', 'type', 'root_domain', 'status', 'ips', 'open_port_count', 'service_count',
    'technology_count', 'vulnerability_count', 'max_cvss', 'max_epss', 'kev_count',
    'certificate_state', 'certificate_not_after', 'certificate_days_remaining',
    'first_seen', 'last_seen', 'last_scanned',
]

FINDING_COLUMNS = [
    'host', 'kind', 'identifier', 'title', 'severity', 'priority', 'cvss', 'epss', 'in_kev',
    'kev_due_date', 'technology', 'port', 'status', 'status_note', 'first_seen', 'last_seen', 'evidence',
]


def safe_cell(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if isinstance(value, (list, tuple)):
        value = '; '.join(str(v) for v in value)
    if isinstance(value, str) and value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def flatten_asset(asset: dict) -> dict:
    row = dict(asset)
    certificate = row.pop('certificate', None) or {}
    row['certificate_state'] = certificate.get('state')
    row['certificate_not_after'] = certificate.get('not_after')
    row['certificate_days_remaining'] = certificate.get('days_remaining')
    return row


def to_csv(rows: list, columns: list) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def to_json(rows: list, columns: list) -> str:
    return json.dumps([{column: row.get(column) for column in columns} for row in rows], indent=2, default=str)
