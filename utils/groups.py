"""
Asset groups: view one client, brand or engagement at a time.

A group is a filter over the one shared database, not a separate database:
the same worker and threat intelligence serve every group.

    - Every root domain is a group of its own ("automatic" groups), so
      grouping works with no setup. A root that was never scanned counts too
      (submitting shop.example.com alone creates a non-expanded example.com).
    - Named groups combine domains and CIDRs as entered, e.g. "Example Corp"
      = example.com + example.org + 203.0.113.0/27. A root domain in a named
      group no longer shows as an automatic group.
    - A domain member matches the name and every hostname under it.
    - A CIDR member matches the IPs inside it (containment; blocks are never
      guessed from loose IPs, so a /27 and a /28 group can overlap).
    - IPs the group's hostnames point to belong to the group too, except
      CDN/shared-hosting IPs, which would otherwise merge every client
      behind the same CDN.
    - Hosts that match no group are "Ungrouped".

Group keys (switcher, ?group=, cookie): 'all', 'ungrouped', 'g:<group id>',
'd:<root domain>'. Pages filter their queries through bind(), which puts the
group's hostnames and IPs in a temporary table on the connection.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set

from utils.timeutil import utc_now_str

ALL = 'all'
UNGROUPED = 'ungrouped'
MAX_NAME_LENGTH = 60
HOSTNAME = re.compile(r'^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$')


class GroupError(ValueError):
    """Invalid group input; the message is safe to show in the dashboard."""


def _db():
    from utils.db_utils import get_db_connection
    return get_db_connection()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    name = ' '.join((name or '').split())
    if not name:
        raise GroupError('Group name is required')
    if len(name) > MAX_NAME_LENGTH:
        raise GroupError(f'Group name: at most {MAX_NAME_LENGTH} characters')
    if name.lower() in (ALL, UNGROUPED):
        raise GroupError(f'"{name}" is reserved')
    return name


def normalize_domain(value: str) -> str:
    domain = (value or '').strip().lower().rstrip('.')
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1].split('/', 1)[0]
    if not HOSTNAME.match(domain):
        raise GroupError(f'"{value}" is not a domain name')
    return domain


def normalize_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network((value or '').strip(), strict=False)
    except ValueError:
        raise GroupError(f'"{value}" is not an IP address or CIDR range')
    if network.prefixlen == 0:
        raise GroupError('A range covering every address is not allowed')
    return str(network)


def normalize_member(kind: str, value: str) -> str:
    if kind == 'domain':
        return normalize_domain(value)
    if kind == 'cidr':
        return normalize_cidr(value)
    raise GroupError('Member must be a domain or a CIDR range')


def member_kind(value: str) -> str:
    """'cidr' for an IP or range, else 'domain' (for free-text input)."""
    try:
        ipaddress.ip_network((value or '').strip(), strict=False)
        return 'cidr'
    except ValueError:
        return 'domain'


# ---------------------------------------------------------------------------
# Named groups
# ---------------------------------------------------------------------------

def list_named_groups() -> List[dict]:
    conn = _db()
    try:
        groups = [dict(r) for r in conn.execute('SELECT group_id, name, created_at FROM asset_groups ORDER BY name')]
        members = conn.execute('SELECT group_id, kind, value FROM asset_group_members ORDER BY kind, value').fetchall()
    finally:
        conn.close()
    for group in groups:
        group['key'] = f"g:{group['group_id']}"
        group['domains'] = [m['value'] for m in members if m['group_id'] == group['group_id'] and m['kind'] == 'domain']
        group['cidrs'] = [m['value'] for m in members if m['group_id'] == group['group_id'] and m['kind'] == 'cidr']
    return groups


def create_group(name: str) -> int:
    import sqlite3
    name = normalize_name(name)
    conn = _db()
    try:
        cursor = conn.execute('INSERT INTO asset_groups (name, created_at) VALUES (?, ?)', (name, utc_now_str()))
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        raise GroupError(f'A group named "{name}" already exists')
    finally:
        conn.close()


def rename_group(group_id: int, name: str):
    import sqlite3
    name = normalize_name(name)
    conn = _db()
    try:
        if not conn.execute('UPDATE asset_groups SET name = ? WHERE group_id = ?', (name, group_id)).rowcount:
            raise GroupError('Group not found')
        conn.commit()
    except sqlite3.IntegrityError:
        raise GroupError(f'A group named "{name}" already exists')
    finally:
        conn.close()


def delete_group(group_id: int):
    """Remove the group (its domains return to their automatic groups); assets are not touched."""
    conn = _db()
    try:
        if not conn.execute('DELETE FROM asset_groups WHERE group_id = ?', (group_id,)).rowcount:
            raise GroupError('Group not found')
        conn.commit()
    finally:
        conn.close()


def add_member(group_id: int, kind: str, value: str) -> str:
    value = normalize_member(kind, value)
    conn = _db()
    try:
        if not conn.execute('SELECT 1 FROM asset_groups WHERE group_id = ?', (group_id,)).fetchone():
            raise GroupError('Group not found')
        conn.execute('INSERT OR IGNORE INTO asset_group_members (group_id, kind, value) VALUES (?, ?, ?)',
                     (group_id, kind, value))
        conn.commit()
        return value
    finally:
        conn.close()


def remove_member(group_id: int, kind: str, value: str):
    conn = _db()
    try:
        conn.execute('DELETE FROM asset_group_members WHERE group_id = ? AND kind = ? AND value = ?',
                     (group_id, kind, value))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------

class Inventory:
    """Every hostname and IP in the database, with their links, loaded once per request."""

    def __init__(self, conn):
        self.domains = {r['domain_name'].lower(): r['dom_id']
                        for r in conn.execute('SELECT dom_id, domain_name FROM domain_asset')}
        self.subdomains = [r['subdomain_name'].lower() for r in conn.execute('SELECT subdomain_name FROM subdomain_asset')]
        self.ips = {r['ip_value']: bool(r['is_shared'])
                    for r in conn.execute('SELECT ip_value, is_shared FROM ip_asset')}
        self.links: Dict[str, Set[str]] = {}
        for row in conn.execute('''
                SELECT d.domain_name AS host, i.ip_value FROM domain_ip x
                JOIN domain_asset d ON d.dom_id = x.dom_id JOIN ip_asset i ON i.ip_id = x.ip_id
                UNION ALL
                SELECT s.subdomain_name, i.ip_value FROM subdomain_ip x
                JOIN subdomain_asset s ON s.sub_id = x.sub_id JOIN ip_asset i ON i.ip_id = x.ip_id'''):
            self.links.setdefault(row['host'].lower(), set()).add(row['ip_value'])
        self.named = {}
        for row in conn.execute('SELECT group_id, kind, value FROM asset_group_members'):
            self.named.setdefault(row['group_id'], {'domain': set(), 'cidr': set()})[row['kind']].add(row['value'])
        self.names = {r['group_id']: r['name'] for r in conn.execute('SELECT group_id, name FROM asset_groups')}
        for group_id in self.names:
            self.named.setdefault(group_id, {'domain': set(), 'cidr': set()})

    @property
    def hostnames(self) -> Set[str]:
        return set(self.domains) | set(self.subdomains)

    def hosts_for(self, domains: Set[str], cidrs: Set[str]) -> Set[str]:
        """Hostnames under the domains, IPs inside the CIDRs, and non-shared IPs those hostnames use."""
        names = {h for h in self.hostnames if any(h == d or h.endswith('.' + d) for d in domains)}
        networks = [ipaddress.ip_network(c) for c in cidrs]
        ips = set()
        for ip in self.ips:
            address = ipaddress.ip_address(ip)
            if any(address.version == n.version and address in n for n in networks):
                ips.add(ip)
        for name in names:
            ips |= {ip for ip in self.links.get(name, ()) if not self.ips.get(ip)}
        return names | ips

    def named_domains(self) -> Set[str]:
        return {d for members in self.named.values() for d in members['domain']}

    def automatic_roots(self) -> List[str]:
        """Root domains that are their own group (not in a named group)."""
        covered = self.named_domains()
        return sorted(d for d in self.domains
                      if not any(d == c or d.endswith('.' + c) for c in covered))

    def resolve(self, key: str) -> Optional[Set[str]]:
        """The group's hostnames and IPs (lowercase), or None for all assets."""
        if key == ALL:
            return None
        if key.startswith('g:'):
            members = self.named[int(key[2:])]
            return self.hosts_for(members['domain'], members['cidr'])
        if key.startswith('d:'):
            return self.hosts_for({key[2:]}, set())
        grouped = set()
        for members in self.named.values():
            grouped |= self.hosts_for(members['domain'], members['cidr'])
        for root in self.automatic_roots():
            grouped |= self.hosts_for({root}, set())
        return (self.hostnames | set(self.ips)) - grouped

    def groups_of(self, host: str) -> List[str]:
        """Names of the groups the host is in (automatic groups as their root domain)."""
        host = host.lower()
        found = [self.names[g] for g, m in sorted(self.named.items(), key=lambda kv: self.names[kv[0]].lower())
                 if host in self.hosts_for(m['domain'], m['cidr'])]
        found += [root for root in self.automatic_roots() if host in self.hosts_for({root}, set())]
        return found


def is_valid_key(key: str, inventory: Inventory = None) -> bool:
    if key in (ALL, UNGROUPED):
        return True
    if inventory is None:
        conn = _db()
        try:
            inventory = Inventory(conn)
        finally:
            conn.close()
    if key.startswith('g:') and key[2:].isdigit():
        return int(key[2:]) in inventory.names
    if key.startswith('d:'):
        return key[2:] in inventory.domains
    return False


def bind(conn, key: Optional[str]) -> bool:
    """
    Load the group's hosts into temp.group_hosts on this connection.

    Returns:
        True if queries should filter on it, False for all assets
    """
    if not key or key == ALL:
        return False
    inventory = Inventory(conn)
    if not is_valid_key(key, inventory):
        raise GroupError('Unknown group')
    hosts = inventory.resolve(key)
    conn.execute('CREATE TEMP TABLE IF NOT EXISTS group_hosts (host TEXT PRIMARY KEY)')
    conn.execute('DELETE FROM temp.group_hosts')
    conn.executemany('INSERT OR IGNORE INTO temp.group_hosts (host) VALUES (?)', [(h.lower(),) for h in hosts])
    return True


# SQL condition for a hostname/IP column, used after bind()
def in_group(column: str) -> str:
    return f"LOWER({column}) IN (SELECT host FROM temp.group_hosts)"


# ---------------------------------------------------------------------------
# Switcher
# ---------------------------------------------------------------------------

def menu() -> dict:
    """
    Entries for the group switcher, each with the number of assets it shows
    (the Assets list counts IPs only when no hostname points to them).
    """
    conn = _db()
    try:
        inventory = Inventory(conn)
        listed = {r[0].lower() for r in conn.execute('''
            SELECT domain_name FROM domain_asset WHERE expand = 1
            UNION ALL SELECT subdomain_name FROM subdomain_asset
            UNION ALL SELECT ip_value FROM ip_asset i
            WHERE NOT EXISTS (SELECT 1 FROM domain_ip x WHERE x.ip_id = i.ip_id)
              AND NOT EXISTS (SELECT 1 FROM subdomain_ip x WHERE x.ip_id = i.ip_id)''')}
    finally:
        conn.close()

    def count(key):
        hosts = inventory.resolve(key)
        return len(listed if hosts is None else listed & hosts)

    named = [{'key': f'g:{gid}', 'name': name, 'count': count(f'g:{gid}')}
             for gid, name in sorted(inventory.names.items(), key=lambda kv: kv[1].lower())]
    roots = [{'key': f'd:{root}', 'name': root, 'count': count(f'd:{root}')} for root in inventory.automatic_roots()]
    return {'all': count(ALL), 'named': named, 'roots': roots, 'ungrouped': count(UNGROUPED)}


def label(key: str) -> str:
    if key == ALL:
        return 'All assets'
    if key == UNGROUPED:
        return 'Ungrouped'
    if key.startswith('d:'):
        return key[2:]
    if key.startswith('g:') and key[2:].isdigit():
        conn = _db()
        try:
            row = conn.execute('SELECT name FROM asset_groups WHERE group_id = ?', (int(key[2:]),)).fetchone()
        finally:
            conn.close()
        if row:
            return row['name']
    return 'All assets'
