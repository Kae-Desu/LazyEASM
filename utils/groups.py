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
    - A named group can have its own notification channels and engagement
      dates (outside them its hosts are not scanned); see the sections below.

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
        groups = [dict(r) for r in conn.execute(
            'SELECT group_id, name, created_at, starts_on, ends_on FROM asset_groups ORDER BY name')]
        channels = {r['group_id']: r for r in conn.execute('SELECT * FROM asset_group_channels')}
        members = conn.execute('SELECT group_id, kind, value FROM asset_group_members ORDER BY kind, value').fetchall()
    finally:
        conn.close()
    for group in groups:
        group['key'] = f"g:{group['group_id']}"
        group['domains'] = [m['value'] for m in members if m['group_id'] == group['group_id'] and m['kind'] == 'domain']
        group['cidrs'] = [m['value'] for m in members if m['group_id'] == group['group_id'] and m['kind'] == 'cidr']
        group['engagement'] = engagement_state(group['starts_on'], group['ends_on'])
        row = channels.get(group['group_id'])
        group['channels'] = [f for f in DESTINATIONS if row and row[f]]
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
        self.names, self.dates = {}, {}
        for r in conn.execute('SELECT group_id, name, starts_on, ends_on FROM asset_groups'):
            self.names[r['group_id']] = r['name']
            self.dates[r['group_id']] = (r['starts_on'], r['ends_on'])
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

    def contains(self, group_id: int, host: str) -> bool:
        """
        Whether a hostname or IP belongs to the named group, also for names not
        (yet) in the database, e.g. a subdomain that was just discovered.
        """
        members = self.named.get(group_id)
        if not members:
            return False
        host = host.lower()
        if any(host == d or host.endswith('.' + d) for d in members['domain']):
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        if any(address.version == n.version and address in n
               for n in (ipaddress.ip_network(c) for c in members['cidr'])):
            return True
        if self.ips.get(host):
            return False            # CDN / shared hosting: not joined through hostnames
        return any(host in ips and any(name == d or name.endswith('.' + d) for d in members['domain'])
                   for name, ips in self.links.items())

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


def groups_of_host(host: str) -> List[str]:
    """Names of the groups a hostname or IP is in (more than one: shared between groups)."""
    conn = _db()
    try:
        return Inventory(conn).groups_of(host)
    finally:
        conn.close()


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
# Engagement dates
# ---------------------------------------------------------------------------
#
# A named group can have a start and an end date (inclusive, UTC). Outside
# them its hosts are not scanned: the checks skip them and queued jobs for
# them are dropped. Their data stays (findings are not closed) until the
# group is purged. A host that is also in a group without dates, or in one
# whose engagement is running, is still scanned.

def today() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime('%Y-%m-%d')


def normalize_date(value: str) -> Optional[str]:
    from datetime import date
    value = (value or '').strip()
    if not value:
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        raise GroupError(f'"{value}" is not a date (YYYY-MM-DD)')


def engagement_state(starts_on: Optional[str], ends_on: Optional[str], on: str = None) -> Optional[str]:
    """'upcoming', 'running' or 'ended'; None for a group without dates."""
    if not starts_on and not ends_on:
        return None
    on = on or today()
    if starts_on and on < starts_on:
        return 'upcoming'
    if ends_on and on > ends_on:
        return 'ended'
    return 'running'


def set_engagement(group_id: int, starts_on: str, ends_on: str):
    starts_on, ends_on = normalize_date(starts_on), normalize_date(ends_on)
    if starts_on and ends_on and ends_on < starts_on:
        raise GroupError('The end date is before the start date')
    conn = _db()
    try:
        if not conn.execute('UPDATE asset_groups SET starts_on = ?, ends_on = ? WHERE group_id = ?',
                            (starts_on, ends_on, group_id)).rowcount:
            raise GroupError('Group not found')
        conn.commit()
    finally:
        conn.close()


def ended_engagements() -> List[dict]:
    """Groups whose end date has passed (the dashboard reminds to export and purge them)."""
    conn = _db()
    try:
        rows = conn.execute('SELECT group_id, name, ends_on FROM asset_groups WHERE ends_on < ? ORDER BY ends_on',
                            (today(),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def scan_filter():
    """
    A predicate host -> bool: False for hosts that must not be scanned now
    (only in groups whose engagement has not started or has ended).
    """
    on = today()
    conn = _db()
    try:
        if not conn.execute('SELECT 1 FROM asset_groups WHERE starts_on > ? OR ends_on < ? LIMIT 1',
                            (on, on)).fetchone():
            return lambda host: True
        inventory = Inventory(conn)
    finally:
        conn.close()
    stopped = [g for g, (start, end) in inventory.dates.items()
               if engagement_state(start, end, on) in ('upcoming', 'ended')]
    active = [g for g in inventory.names if g not in stopped]

    def allowed(host: str) -> bool:
        if not host or not any(inventory.contains(g, host) for g in stopped):
            return True
        return any(inventory.contains(g, host) for g in active)
    return allowed


def scannable(items, key=None) -> list:
    """The items whose host may be scanned now; key gets the host from an item."""
    items = list(items)
    allowed = scan_filter()
    kept = [item for item in items if allowed(key(item) if key else item)]
    if len(kept) < len(items):
        import logging
        logging.getLogger(__name__).info(
            f"Skipped {len(items) - len(kept)} targets outside their group's engagement dates")
    return kept


def may_scan(host: str) -> bool:
    return scan_filter()(host)


# ---------------------------------------------------------------------------
# Notification channels
# ---------------------------------------------------------------------------
#
# A named group can have its own channels, so alerts about one client never
# reach another client's Slack or webhook. Alerts about a group's hosts go to
# its channels (and also to the default channels in .env unless that is
# turned off); hosts in no group with channels use the default channels.
# Server alerts (worker stopped, disk full) always use the default channels.

CHANNEL_FIELDS = ('discord_webhook', 'discord_user_id', 'slack_webhook', 'webhook_url', 'webhook_secret', 'email_to')
DESTINATIONS = ('discord_webhook', 'slack_webhook', 'webhook_url', 'email_to')
# Same rules as the default channels in Settings
CHANNEL_RULES = {
    'discord_webhook': 'DISCORD_WEBHOOK_URL',
    'discord_user_id': 'DISCORD_USER_ID',
    'slack_webhook': 'SLACK_WEBHOOK_URL',
    'webhook_url': 'NOTIFY_WEBHOOK_URL',
    'email_to': 'SMTP_TO',
}


def get_channels(group_id: int) -> dict:
    conn = _db()
    try:
        row = conn.execute('SELECT * FROM asset_group_channels WHERE group_id = ?', (group_id,)).fetchone()
    finally:
        conn.close()
    channels = {field: (row[field] if row else None) or '' for field in CHANNEL_FIELDS}
    channels['also_default'] = bool(row['also_default']) if row else True
    return channels


def set_channels(group_id: int, values: dict, also_default: bool):
    """
    Store the group's channels. A field missing from values keeps its value;
    an empty string clears it.
    """
    from utils.env_manager import VALIDATION_RULES

    current = get_channels(group_id)
    for field in CHANNEL_FIELDS:
        if field not in values:
            continue
        value = (values[field] or '').strip()
        rule = VALIDATION_RULES.get(CHANNEL_RULES.get(field, ''))
        if value and rule and not re.match(rule['pattern'], value):
            raise GroupError(rule['message'])
        current[field] = value
    columns = ', '.join(CHANNEL_FIELDS)
    marks = ', '.join('?' * len(CHANNEL_FIELDS))
    conn = _db()
    try:
        if not conn.execute('SELECT 1 FROM asset_groups WHERE group_id = ?', (group_id,)).fetchone():
            raise GroupError('Group not found')
        conn.execute(f'INSERT OR REPLACE INTO asset_group_channels (group_id, {columns}, also_default) '
                     f'VALUES (?, {marks}, ?)',
                     [group_id] + [current[f] or None for f in CHANNEL_FIELDS] + [1 if also_default else 0])
        conn.commit()
    finally:
        conn.close()


def has_channels(channels: dict) -> bool:
    """Whether the group has a channel that can deliver (email needs the SMTP server from Settings)."""
    from utils.config import get_env
    usable = DESTINATIONS if get_env('SMTP_HOST') else tuple(f for f in DESTINATIONS if f != 'email_to')
    return any(channels.get(field) for field in usable)


def notification_routes(hosts) -> Dict[Optional[int], Set[str]]:
    """
    Who hears about which hosts: {group_id: hosts} for groups with their own
    channels, {None: hosts} for the default channels. A host in two groups
    with channels goes to both.
    """
    hosts = {h for h in hosts if h}
    conn = _db()
    try:
        rows = conn.execute('SELECT * FROM asset_group_channels').fetchall()
        configured = {r['group_id']: bool(r['also_default']) for r in rows if has_channels(dict(r))}
        inventory = Inventory(conn) if configured and hosts else None
    finally:
        conn.close()
    if inventory is None:
        return {None: hosts} if hosts else {}
    routes: Dict[Optional[int], Set[str]] = {}
    for host in hosts:
        groups = [g for g in configured if inventory.contains(g, host)]
        if not groups or any(configured[g] for g in groups):
            routes.setdefault(None, set()).add(host)
        for g in groups:
            routes.setdefault(g, set()).add(host)
    return routes


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
