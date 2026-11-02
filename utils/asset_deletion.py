"""
Delete an asset and everything recorded about it.

Most of what LazyEASM learns about a host (web services, technologies, CVEs,
screenshots, findings, certificates, change history, jobs) is keyed by the
hostname, not linked to the asset row, so removing only the row left all of
it behind. This module removes it all:

    - domain:    the domain, every subdomain under it (also ones a previous
                 delete left without a domain) and all their data
    - subdomain: the subdomain and its data
    - ip:        the IP, its ports and its data; web services of hostnames
                 that pointed to it stay with those hostnames

IPs only the deleted hostnames pointed to are removed too; an IP another
asset still uses is kept. Deleted content is overwritten (secure_delete) and
the write-ahead log is checkpointed, so it cannot be read back from the
database file. Backups made earlier still contain it.

Used after an engagement to remove a client's data; the log records counts
only, not the hostnames.
"""

import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ASSET_TYPES = ('domain', 'subdomain', 'ip')


def _placeholders(values) -> str:
    return ','.join('?' * len(values))


def _hosts_and_ips(conn, asset_type: str, asset_id: int) -> Optional[tuple]:
    """(hostnames, subdomain ids, domain ids, candidate IP ids, IP ids to delete) or None if not found."""
    if asset_type == 'domain':
        row = conn.execute('SELECT domain_name FROM domain_asset WHERE dom_id = ?', (asset_id,)).fetchone()
        if not row:
            return None
        domain = row['domain_name'].lower()
        subs = [r for r in conn.execute('SELECT sub_id, dom_id, subdomain_name FROM subdomain_asset')
                if r['dom_id'] == asset_id or r['subdomain_name'].lower().endswith('.' + domain)]
        sub_ids = [r['sub_id'] for r in subs]
        hosts = [row['domain_name']] + [r['subdomain_name'] for r in subs]
        candidates = {r[0] for r in conn.execute('SELECT ip_id FROM domain_ip WHERE dom_id = ?', (asset_id,))}
        if sub_ids:
            candidates |= {r[0] for r in conn.execute(
                f'SELECT ip_id FROM subdomain_ip WHERE sub_id IN ({_placeholders(sub_ids)})', sub_ids)}
        return hosts, sub_ids, [asset_id], candidates, []
    if asset_type == 'subdomain':
        row = conn.execute('SELECT subdomain_name FROM subdomain_asset WHERE sub_id = ?', (asset_id,)).fetchone()
        if not row:
            return None
        candidates = {r[0] for r in conn.execute('SELECT ip_id FROM subdomain_ip WHERE sub_id = ?', (asset_id,))}
        return [row['subdomain_name']], [asset_id], [], candidates, []
    row = conn.execute('SELECT ip_value FROM ip_asset WHERE ip_id = ?', (asset_id,)).fetchone()
    if not row:
        return None
    return [row['ip_value']], [], [], set(), [asset_id]


def _delete_host_data(conn, hosts: List[str], counts: Dict[str, int]) -> List[str]:
    """Remove every hostname-keyed record; returns screenshot files to delete."""
    if not hosts:
        return []
    marks = _placeholders(hosts)
    http_ids = [r[0] for r in conn.execute(f'SELECT http_id FROM http_services WHERE host IN ({marks})', hosts)]

    files = []
    shots = conn.execute(f'''
        SELECT screenshot_id, image_file, thumb_file FROM screenshots
        WHERE host IN ({marks}) {f"OR http_id IN ({_placeholders(http_ids)})" if http_ids else ''}
    ''', hosts + http_ids).fetchall()
    for shot in shots:
        files += [shot['image_file'], shot['thumb_file']]
    if shots:
        ids = [s['screenshot_id'] for s in shots]
        conn.execute(f'DELETE FROM screenshots WHERE screenshot_id IN ({_placeholders(ids)})', ids)
    counts['screenshots'] += len(shots)

    if http_ids:
        http_marks = _placeholders(http_ids)
        # vulnerabilities.tech_id is ON DELETE SET NULL: remove them before their technologies
        counts['vulnerabilities'] += conn.execute(f'''
            DELETE FROM vulnerabilities WHERE tech_id IN
                (SELECT tech_id FROM technologies WHERE http_id IN ({http_marks}))
        ''', http_ids).rowcount
        counts['technologies'] += conn.execute(
            f'DELETE FROM technologies WHERE http_id IN ({http_marks})', http_ids).rowcount
        counts['directories'] += conn.execute(
            f'DELETE FROM directories WHERE http_id IN ({http_marks})', http_ids).rowcount
        counts['web_services'] += conn.execute(
            f'DELETE FROM http_services WHERE http_id IN ({http_marks})', http_ids).rowcount

    counts['findings'] += conn.execute(f'DELETE FROM findings WHERE host IN ({marks})', hosts).rowcount
    counts['changes'] += conn.execute(f'DELETE FROM asset_changes WHERE host IN ({marks})', hosts).rowcount
    conn.execute(f'DELETE FROM cert_notifications WHERE hostname IN ({marks})', hosts)
    counts['certificates'] += conn.execute(f'DELETE FROM certificates WHERE hostname IN ({marks})', hosts).rowcount
    conn.execute(f'DELETE FROM scan_hints WHERE target IN ({marks})', hosts)
    conn.execute(f'DELETE FROM scan_history WHERE target IN ({marks})', hosts)
    conn.execute(f'UPDATE scan_progress SET current_target = NULL WHERE current_target IN ({marks})', hosts)
    counts['jobs'] += conn.execute(f'DELETE FROM scan_queue WHERE target IN ({marks})', hosts).rowcount
    counts['jobs'] += _delete_submission_jobs(conn, {h.lower() for h in hosts})
    _forget_unserved_strikes(conn, hosts)
    return files


def _delete_submission_jobs(conn, hosts: set) -> int:
    """Dashboard submissions store their targets as JSON lists; remove those naming a deleted host."""
    from utils.pipeline import INPUT_DISCOVERY
    doomed = []
    for row in conn.execute('SELECT queue_id, target FROM scan_queue WHERE scan_type = ?', (INPUT_DISCOVERY,)):
        try:
            payload = json.loads(row['target'])
        except (TypeError, ValueError):
            continue
        values = [v for items in payload.values() if isinstance(items, list) for v in items] \
            if isinstance(payload, dict) else []
        if any(str(v).lower() in hosts for v in values):
            doomed.append(row['queue_id'])
    if doomed:
        conn.execute(f'DELETE FROM scan_queue WHERE queue_id IN ({_placeholders(doomed)})', doomed)
    return len(doomed)


def _forget_unserved_strikes(conn, hosts: List[str]):
    from utils.misconfig_checker import UNSERVED_STRIKES_KEY
    row = conn.execute('SELECT value FROM settings WHERE key = ?', (UNSERVED_STRIKES_KEY,)).fetchone()
    if not row or not row['value']:
        return
    try:
        strikes = json.loads(row['value'])
    except ValueError:
        return
    kept = {host: n for host, n in strikes.items() if host not in hosts}
    if kept != strikes:
        conn.execute('UPDATE settings SET value = ? WHERE key = ?', (json.dumps(kept), UNSERVED_STRIKES_KEY))


def delete_asset(asset_type: str, asset_id: int) -> Optional[Dict[str, int]]:
    """
    Delete the asset and everything recorded about it.

    Returns:
        counts of what was removed ({'hosts', 'ips', 'web_services', ...}),
        or None if the asset does not exist

    Raises:
        ValueError: unknown asset type
    """
    from utils.db_utils import get_db_connection
    from utils.screenshots import _remove as remove_screenshot_file

    if asset_type not in ASSET_TYPES:
        raise ValueError(f'unknown asset type {asset_type}')

    counts = dict.fromkeys(('hosts', 'ips', 'web_services', 'technologies', 'vulnerabilities', 'screenshots',
                            'directories', 'findings', 'certificates', 'changes', 'jobs'), 0)
    files = []
    conn = get_db_connection()
    try:
        conn.execute('PRAGMA secure_delete = ON')     # overwrite deleted content in the file
        found = _hosts_and_ips(conn, asset_type, asset_id)
        if found is None:
            return None
        hosts, sub_ids, dom_ids, candidate_ips, ip_ids = found

        files += _delete_host_data(conn, hosts, counts)
        if sub_ids:
            containers = [r[0] for r in conn.execute(
                f'SELECT DISTINCT dom_id FROM subdomain_asset WHERE sub_id IN ({_placeholders(sub_ids)}) '
                f'AND dom_id IS NOT NULL', sub_ids)]
            conn.execute(f'DELETE FROM subdomain_asset WHERE sub_id IN ({_placeholders(sub_ids)})', sub_ids)
            # A domain kept only to hold single submitted subdomains (expand = 0)
            # goes with its last one: its name is the client's data too
            for dom_id in containers:
                if dom_id in dom_ids:
                    continue
                row = conn.execute('SELECT domain_name, expand FROM domain_asset WHERE dom_id = ?', (dom_id,)).fetchone()
                if row and not row['expand'] and not conn.execute(
                        'SELECT 1 FROM subdomain_asset WHERE dom_id = ?', (dom_id,)).fetchone():
                    _delete_host_data(conn, [row['domain_name']], counts)
                    dom_ids.append(dom_id)
                    hosts.append(row['domain_name'])
                    candidate_ips |= {r[0] for r in conn.execute(
                        'SELECT ip_id FROM domain_ip WHERE dom_id = ?', (dom_id,))}
        if dom_ids:
            conn.execute(f'DELETE FROM domain_asset WHERE dom_id IN ({_placeholders(dom_ids)})', dom_ids)
        counts['hosts'] = len(hosts)

        # IPs no remaining asset points to belong to the deleted hosts only
        orphaned = [ip for ip in candidate_ips if not conn.execute(
            'SELECT 1 FROM domain_ip WHERE ip_id = ? UNION SELECT 1 FROM subdomain_ip WHERE ip_id = ?',
            (ip, ip)).fetchone()]
        ip_ids = list(dict.fromkeys(ip_ids + orphaned))
        if ip_ids:
            values = [r[0] for r in conn.execute(
                f'SELECT ip_value FROM ip_asset WHERE ip_id IN ({_placeholders(ip_ids)})', ip_ids)]
            files += _delete_host_data(conn, values, counts)
            conn.execute(f'DELETE FROM ip_asset WHERE ip_id IN ({_placeholders(ip_ids)})', ip_ids)
        counts['ips'] = len(ip_ids)
        conn.commit()

        # Old page versions stay in the write-ahead log until a checkpoint
        try:
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        except Exception as e:
            logger.warning(f"Checkpoint after delete failed (retried automatically later): {e}")
    finally:
        conn.close()

    for name in files:
        remove_screenshot_file(name)
    logger.info(f"Deleted a {asset_type} asset: " + ', '.join(f'{v} {k}' for k, v in counts.items() if v))
    return counts


# ---------------------------------------------------------------------------
# Purge a named group (utils/groups.py): delete a whole client at once
# ---------------------------------------------------------------------------

def group_assets(group_id: int) -> Optional[dict]:
    """
    What purging the group deletes.

    Returns:
        {'name', 'domains': [(id, name, subdomain count)], 'subdomains': [(id, name)],
         'ips': [(id, value)], 'hostnames': int, 'shared': [(host, [group names])]}
        or None if the group does not exist.

        Subdomains under a listed domain are left out (deleting the domain
        takes them with it). IPs the deleted hostnames point to are not
        listed either: deleting the hostnames removes them unless another
        asset still uses them. 'ips' are the group's other IPs (submitted on
        their own or inside its ranges), deleted outright.
    """
    from utils.db_utils import get_db_connection
    from utils.groups import Inventory

    conn = get_db_connection()
    try:
        inventory = Inventory(conn)
        if group_id not in inventory.names:
            return None
        members = inventory.named[group_id]
        hosts = inventory.hosts_for(members['domain'], members['cidr'])
        domain_names = sorted(d for d in inventory.domains if d in hosts)
        under = lambda name: any(name == d or name.endswith('.' + d) for d in domain_names)
        domains = [(inventory.domains[d], d, sum(1 for s in inventory.subdomains if s.endswith('.' + d)))
                   for d in domain_names]
        subdomains = [(r['sub_id'], r['subdomain_name']) for r in conn.execute(
            'SELECT sub_id, subdomain_name FROM subdomain_asset ORDER BY subdomain_name')
            if r['subdomain_name'].lower() in hosts and not under(r['subdomain_name'].lower())]
        hostnames = {h for h in inventory.hostnames if h in hosts}
        linked = {ip for name in hostnames for ip in inventory.links.get(name, ())}
        ips = [(r['ip_id'], r['ip_value']) for r in conn.execute('SELECT ip_id, ip_value FROM ip_asset ORDER BY ip_value')
               if r['ip_value'] in hosts and r['ip_value'] not in linked]
        shared = []
        for host in sorted(hostnames) + [value for _, value in ips]:
            names = inventory.groups_of(host)
            if len(names) > 1:
                shared.append((host, names))
        return {'name': inventory.names[group_id], 'domains': domains, 'subdomains': subdomains, 'ips': ips,
                'hostnames': len(hostnames), 'shared': shared}
    finally:
        conn.close()


def purge_group(group_id: int, delete_backups: bool = False) -> Optional[Dict[str, int]]:
    """
    Delete every asset of the group (and everything recorded about them),
    then the group. With delete_backups, every local backup is deleted (they
    are snapshots of the whole database, so they still hold the group) and a
    fresh one is taken.

    Returns:
        summed counts plus 'backups_deleted', or None if the group does not exist
    """
    from utils import backup, groups

    plan = group_assets(group_id)
    if plan is None:
        return None
    totals: Dict[str, int] = {}
    for asset_type, items in (('domain', plan['domains']), ('subdomain', plan['subdomains']), ('ip', plan['ips'])):
        for item in items:
            removed = delete_asset(asset_type, item[0])        # None: already gone with a domain
            for key, value in (removed or {}).items():
                totals[key] = totals.get(key, 0) + value
    groups.delete_group(group_id)

    totals['backups_deleted'] = 0
    if delete_backups:
        for item in backup.list_backups():
            try:
                os.remove(os.path.join(backup.BACKUP_DIR, item['name']))
                totals['backups_deleted'] += 1
            except OSError as e:
                logger.warning(f"Could not delete a backup during a group purge: {e}")
        backup.create_backup('manual')
    logger.info("Purged a group: " + ', '.join(f'{v} {k}' for k, v in totals.items() if v))
    return totals
