#!/usr/bin/env python3
"""
zabbix_migration_70.py
Migrates objects from Zabbix 6.4 to Zabbix 7.0.

Supported object types (and their execution order when 'all' is selected):
  1. templates   - exported/imported via native configuration API
  2. hosts       - exported/imported via native configuration API
  3. maps        - exported/imported via native configuration API
  4. dashboards  - migrated with full widget field resolution + owner logic

For templates and hosts the required template/host groups are automatically
created in the destination before import.

For dashboards:
  - The original owner is preserved when the same username exists in destination.
  - When it does not exist, the fallback owner 'prd-metrologie-instru-api' is
    used and the dashboard is shared (Edit permission) with every usergroup of
    the original owner that can be found in the destination.

Official Zabbix 6.4 widget field types:
  0=Integer  1=String  2=HostGroup  3=Host  4=Item  5=ItemPrototype
  6=Graph    7=GraphPrototype       8=Map

Config files (same directory as this script):
  zabbix_credential.yml        - username / password
  zabbix_instances_{env}.yml   - cia.<n>.url_export / url_import

Usage:
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate all
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate templates hosts
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate dashboards
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate dashboards \\
      --dashboard "CVS UAT Monitoring" --skip-existing
  python zabbix_migration_70.py --env ppr --cia all   --migrate all --debug
  python zabbix_migration_70.py --pull-repository
  python zabbix_migration_70.py --pull-repository --env ppr --cia biz01 --migrate all
"""

import os
import re
import sys
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import re

import yaml
from zabbix_utils import ZabbixAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pre-quoting regexes for Zabbix 6.4 → 7.0 map YAML.
#
# Zabbix 6.4 exports these values UNQUOTED; PyYAML 1.1 then corrupts them:
#
# 1. HEX COLORS ("000000", "007700", etc.)
#    PyYAML 1.1 treats /^0[0-7]+$/ strings as octal integers and pure-decimal
#    strings as decimal integers.  After safe_load+dump they become plain ints
#    (0, 4032, …) which Zabbix 7.0 rejects as "a character string is expected".
#    Matches both "  key: value" and "  - key: value" (YAML seq first field).
#
# 2. BOOLEAN-LIKE STRINGS ("NO", "YES")
#    PyYAML 1.1 parses bare NO/YES as Python False/True.  After dump they
#    become "false"/"true" which Zabbix 7.0 rejects for string fields.
_COLOR_FIX_RE = re.compile(
    r'^(\s*(?:-\s+)?\w*color\s*:\s*)([0-9A-Fa-f]{6})\s*$',
    re.MULTILINE | re.IGNORECASE,
)
_BOOL_FIX_RE = re.compile(
    r'^(\s*(?:-\s+)?\w+\s*:\s*)(YES|NO)\s*$',
    re.MULTILINE,
)


def _prequote_zabbix_yaml(text: str) -> str:
    """Quote values that PyYAML 1.1 would corrupt in Zabbix 6.4 YAML."""
    text = _COLOR_FIX_RE.sub(lambda m: m.group(1) + "'" + m.group(2) + "'", text)
    text = _BOOL_FIX_RE.sub(lambda m: m.group(1) + "'" + m.group(2) + "'", text)
    return text

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Migration order when 'all' is requested
MIGRATION_ORDER = ["templates", "hosts", "maps", "dashboards", "usergroups"]

# Sentinel: widget field references a deleted / inaccessible object
_INACCESSIBLE = "__INACCESSIBLE__"

# Fallback dashboard owner when original user is not in destination
FALLBACK_OWNER = "prd-metrologie-instru-api"

# Dashboard sharing permission: 3 = read-write (Edit)
PERM_READ_WRITE = 3

# Official Zabbix 6.4 widget field type constants
FIELD_TYPE_INTEGER        = "0"
FIELD_TYPE_STRING         = "1"
FIELD_TYPE_HOST_GROUP     = "2"
FIELD_TYPE_HOST           = "3"
FIELD_TYPE_ITEM           = "4"
FIELD_TYPE_ITEM_PROTOTYPE = "5"
FIELD_TYPE_GRAPH          = "6"
FIELD_TYPE_GRAPH_PROTO    = "7"
FIELD_TYPE_MAP            = "8"

# Zabbix 6.4 tag filter fields — flat structure incompatible with 7.0 API
_TAG_FIELD_RE = re.compile(r'^tags\.(tag|operator|value)\.\d+$')

# Grid: 6.4 = 24 cols, 7.0 = 36 cols. Only horizontal scaled (x1.5).
# Vertical grid is identical in both versions (y 0-62, height 2-32).
GRID_SCALE = 1.5

# Configuration import rules
# ---------------------------------------------------------------------------
# configuration.export / configuration.import  —  API contract reference
# ---------------------------------------------------------------------------
#
# EXPORT  (called on SOURCE — Zabbix 6.4)
# ───────────────────────────────────────
#   method : configuration.export
#   params :
#     format  : "yaml" | "json"   (we use yaml for tpl/hosts, json for maps)
#     options : object whose keys select what to export:
#       templates     → array of templateids
#       hosts         → array of hostids
#       maps          → array of sysmapids
#       (also valid: groups, templateGroups, images, mediaTypes — not used here)
#   result  : plain string (yaml/json export payload)
#
# IMPORT  (called on DESTINATION — Zabbix 7.0)
# ─────────────────────────────────────────────
#   method : configuration.import
#   params :
#     format  : "yaml" | "json"
#     source  : the export string returned above
#     rules   : object controlling create/update/delete behaviour per entity
#               KEY NAMING in 7.0:
#                 snake_case → host_groups, template_groups
#                 camelCase  → everything else (templates, hosts, items, …)
#   result  : true on success
#
#   7.0 automatically upgrades 6.4 export payloads (version tag in YAML/JSON
#   header triggers Zabbix's internal schema-upgrade path).
# ---------------------------------------------------------------------------

TEMPLATE_IMPORT_RULES = {
    # ── groups ──────────────────────────────────────────────────────────────
    # snake_case in 7.0; pre-created by _ensure_template_groups_for_templates()
    # but included here so any missed groups are created automatically.
    "template_groups":    {"createMissing": True,  "updateExisting": False},
    # ── template + its owned objects ────────────────────────────────────────
    "templates":          {"createMissing": True,  "updateExisting": True},
    "templateDashboards": {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "templateLinkage":    {"createMissing": True,  "deleteMissing": False},
    "items":              {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "triggers":           {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "graphs":             {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "discoveryRules":     {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "httptests":          {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "valueMaps":          {"createMissing": True,  "updateExisting": False},
}

# Same as TEMPLATE_IMPORT_RULES but with templateDashboards disabled.
# Used in Step 1 of the two-step template import:
#   Step 1 (this)   : import template + items + graphs (no dashboards)
#   Step 2 (full)   : re-import with dashboards; graphs exist so widget refs resolve
# Reason: Zabbix 7.0 resolves templateDashboard graph references before it
# finishes creating top-level graphs in a single import, so a one-shot import
# fails with "Cannot find graph … used in dashboard".
TEMPLATE_IMPORT_RULES_NO_DASHBOARDS = {
    "template_groups":    {"createMissing": True,  "updateExisting": False},
    "templates":          {"createMissing": True,  "updateExisting": True},
    "templateDashboards": {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "templateLinkage":    {"createMissing": True,  "deleteMissing": False},
    "items":              {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "triggers":           {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "graphs":             {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "discoveryRules":     {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "httptests":          {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "valueMaps":          {"createMissing": True,  "updateExisting": False},
}

HOST_IMPORT_RULES = {
    # ── groups ──────────────────────────────────────────────────────────────
    # snake_case in 7.0; pre-created by _ensure_host_groups_for_hosts().
    "host_groups":     {"createMissing": True,  "updateExisting": False},
    # ── host skeleton + template linkage ────────────────────────────────────
    # items/triggers/graphs/discoveryRules are intentionally DISABLED.
    # We import only the host shell (interfaces, groups, macros, inventory)
    # and its template links.  Zabbix auto-propagates all template-owned
    # objects when the link is created.  Directly-created host objects (no
    # templateid in source) are NOT migrated — they belong to the source host.
    "hosts":           {"createMissing": True,  "updateExisting": True},
    "templateLinkage": {"createMissing": True,  "deleteMissing": False},
    "items":           {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "triggers":        {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "graphs":          {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "discoveryRules":  {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "httptests":       {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "valueMaps":       {"createMissing": False, "updateExisting": False},
}

MAP_IMPORT_RULES = {
    # maps   : the network maps themselves (selements, links, shapes, etc.)
    # images : background images referenced by map selements (elementtype=4)
    # icon_maps : custom icon-mapping sets referenced by selement.iconmapid.
    #             6.4 embeds icon_maps inline in the export; without this rule
    #             7.0 creates maps with missing icons instead of failing loudly.
    "maps":      {"createMissing": True, "updateExisting": True},
    "images":    {"createMissing": True, "updateExisting": False},
    "icon_maps": {"createMissing": True, "updateExisting": False},
}

logger = logging.getLogger(__name__)

LOG_DIR = BASE_DIR   # log files written next to the script


# ---------------------------------------------------------------------------
# Incremental log writer
# ---------------------------------------------------------------------------

class MigrationLog:
    """
    Appends structured, timestamped detail to migration_{env}_{cia}.log.
    Console output shows statistics only; this file keeps the full detail
    for post-run investigation.  A separate file per env+cia keeps logs
    manageable and makes it easy to grep for a specific instance.
    """

    def __init__(self, env: str, cia: str, types_run: List[str],
                 dashboard_filter: str = None):
        # One file per environment + CIA  (e.g. migration_ppr_biz01.log)
        # When cia="all" the filename becomes migration_ppr_all.log
        cia_slug   = cia.replace("/", "_").replace(" ", "_")
        filename   = f"migration_{env}_{cia_slug}.log"
        self.path  = os.path.join(LOG_DIR, filename)
        self.run_ts     = datetime.now()
        self.env        = env
        self.cia        = cia
        self.types_run  = types_run
        self.dashboard_filter = dashboard_filter
        self._sections: List[str] = []

    def _ts(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def section(self, cia_name: str, migrator: "ZabbixMigrator"):
        """Collect detail for one CIA after its migration completes."""
        lines = [
            f"",
            f"  CIA: {cia_name}",
            f"  {'─' * 60}",
        ]

        for t in self.types_run:
            r = migrator.results[t]
            lines.append(
                f"  [{t.capitalize():12}] "
                f"Migrated: {r['migrated']:4}  "
                f"Skipped: {r['skipped']:4}  "
                f"Failed: {r['failed']:4}"
            )

            # List every successfully migrated object
            if r.get("names"):
                lines.append("")
                lines.append(f"  Migrated {t} [{len(r['names'])}]:")
                for obj_name in r["names"]:
                    lines.append(f"    + {obj_name}")

            # List every error
            if r["errors"]:
                lines.append("")
                lines.append(f"  Failed {t} [{len(r['errors'])}]:")
            for err in r["errors"]:
                name   = err.get("name", "")
                reason = err.get("reason", "")
                prefix = f"'{name}' -- " if name else ""
                lines.append(f"      ERROR: {prefix}{reason}")
                for d in err.get("details", []):
                    lines.append(f"          . {d}")

        # Disabled hosts
        if "hosts" in self.types_run and migrator.disabled_hosts:
            lines.append(
                f"\n  Disabled hosts NOT imported [{len(migrator.disabled_hosts)}]:"
            )
            for name in sorted(migrator.disabled_hosts):
                lines.append(f"    - {name}  [DISABLED in source]")

        # Hosts missing after import
        if "hosts" in self.types_run and migrator.missing_hosts_after_import:
            lines.append(
                f"\n  Enabled hosts missing in destination after import "
                f"[{len(migrator.missing_hosts_after_import)}]:"
            )
            for name in migrator.missing_hosts_after_import:
                lines.append(f"    - {name}  [MISSING in destination]")

        # Skipped templates
        if "templates" in self.types_run and migrator.skipped_templates:
            lines.append(
                f"\n  Templates skipped (no enabled host link) "
                f"[{len(migrator.skipped_templates)}]:"
            )
            for name in sorted(migrator.skipped_templates):
                lines.append(f"    - {name}  [no active host link, direct or indirect]")

        self._sections.append("\n".join(lines))

    def write(self, global_results: Dict[str, Dict]):
        """Flush the full run to the log file (append mode)."""
        run_start = self.run_ts.strftime("%Y-%m-%d %H:%M:%S")
        run_end   = self._ts()

        header = [
            "",
            "=" * 70,
            f"  RUN STARTED : {run_start}",
            f"  RUN FINISHED: {run_end}",
            f"  env={self.env}  cia={self.cia}  "
            f"migrate={' '.join(self.types_run)}",
        ]
        if self.dashboard_filter:
            header.append(f"  dashboard filter='{self.dashboard_filter}'")
        header.append("=" * 70)

        global_lines = [
            "",
            "  Global totals:",
        ]
        for t in self.types_run:
            r = global_results[t]
            global_lines.append(
                f"  [{t.capitalize():12}] "
                f"Migrated: {r['migrated']:4}  "
                f"Skipped: {r['skipped']:4}  "
                f"Failed: {r['failed']:4}"
            )

        body = (
            "\n".join(header)
            + "\n"
            + "\n".join(self._sections)
            + "\n"
            + "\n".join(global_lines)
            + "\n"
        )

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(body)

        print(f"\n  Details written to: {self.path}")




# ---------------------------------------------------------------------------
# Config loaders
# ---------------------------------------------------------------------------

def load_credentials() -> Dict:
    """Load Zabbix credentials from zabbix_credential.yml."""
    path = os.path.join(BASE_DIR, "zabbix_credential.yml")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Credentials file not found: {path}")
    with open(path, "r") as f:
        creds = yaml.safe_load(f)
    if not creds or "username" not in creds or "password" not in creds:
        raise ValueError(f"'{path}' must contain 'username' and 'password' keys.")
    return creds


def load_instances(environment: str) -> Dict:
    """Load Zabbix instance URLs from zabbix_instances_{env}.yml."""
    filename = f"zabbix_instances_{environment}.yml"
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Instances file not found: {path}")
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    if not config or "cia" not in config:
        raise ValueError(f"'{path}' must contain a 'cia' mapping.")
    return config


# ---------------------------------------------------------------------------
# Git pull helper
# ---------------------------------------------------------------------------

def pull_repository(repo_name: str = None) -> bool:
    """
    Perform a 'git pull <repo> <branch>' using information from
    projects_branch.yml, found by walking upward from the script directory.

    repo_name: explicit project name; if None, the current folder name is used.

    Expected YAML structure:
      projects:
        - name: "zabbix-python-scripts"
          branch: "feature/NXIBW17-601"
    """
    import subprocess

    repo_name = repo_name or os.path.basename(BASE_DIR)

    # Walk upward from the script's directory until projects_branch.yml is found.
    # The script lives inside <repo>/<subdir>/, so the file may be 2+ levels up.
    _search  = BASE_DIR
    yml_path = None
    for _ in range(5):                        # safety: max 5 levels
        _search    = os.path.dirname(_search)
        _candidate = os.path.join(_search, "projects_branch.yml")
        if os.path.exists(_candidate):
            yml_path = _candidate
            break
    if yml_path is None:                      # fallback path used only in error message
        yml_path = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "projects_branch.yml"))

    print(f"\n  Repository : {repo_name}")
    print(f"  Config file: {yml_path}")

    # Load YAML
    if not os.path.exists(yml_path):
        print(f"  ERROR: '{yml_path}' not found.", file=sys.stderr)
        return False

    with open(yml_path, "r") as f:
        data = yaml.safe_load(f)

    projects = data.get("projects") if data else None
    if not projects:
        print(f"  ERROR: 'projects' key missing or empty in '{yml_path}'.",
              file=sys.stderr)
        return False

    # Accept both a list of entries or a single dict
    if isinstance(projects, dict):
        projects = [projects]

    # Find the entry whose 'name' matches this folder
    entry = next(
        (p for p in projects if p.get("name") == repo_name),
        None
    )
    if not entry:
        print(
            f"  ERROR: No entry with name='{repo_name}' found in '{yml_path}'.\n"
            f"         Available names: "
            f"{[p.get('name') for p in projects]}",
            file=sys.stderr
        )
        return False

    branch = entry.get("branch")
    if not branch:
        print(f"  ERROR: 'branch' missing for project '{repo_name}'.", file=sys.stderr)
        return False

    cmd = ["git", "pull", repo_name, branch]
    print(f"  Running    : {' '.join(cmd)}\n")

    result = subprocess.run(cmd, cwd=BASE_DIR)
    if result.returncode == 0:
        print("\n  git pull completed successfully.")
        return True
    else:
        print(f"\n  ERROR: git pull exited with code {result.returncode}.",
              file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Main migrator
# ---------------------------------------------------------------------------

class ZabbixMigrator:
    """
    Migrates Templates, Hosts, Maps, and Dashboards from Zabbix 6.4 to 7.0.
    One instance per CIA pair (source URL / destination URL).
    """

    def __init__(self, source_url: str, dest_url: str,
                 username: str, password: str, cia_name: str,
                 skip_existing: bool = False,
                 dashboard_filter: Optional[str] = None,
                 host_filter: Optional[str] = None,
                 usergroup_filter: Optional[str] = None,
                 debug_json: bool = False):
        self.cia_name          = cia_name
        self.skip_existing     = skip_existing
        self.dashboard_filter  = dashboard_filter
        self.host_filter       = host_filter
        self.usergroup_filter  = usergroup_filter
        self.debug_json       = debug_json
        self._source_url      = source_url  # kept for raw API calls
        self._dest_url        = dest_url   # kept for raw API calls (bypass pyzabbix)

        # Per-type result counters
        self.results: Dict[str, Dict] = {
            t: {"migrated": 0, "skipped": 0, "failed": 0, "errors": [], "names": []}
            for t in MIGRATION_ORDER
        }
        # Source/destination object counts for final report
        # Each entry: {"src_total": int, "src_enabled": int, "src_disabled": int,
        #              "dst_total": int, "dst_enabled": int, "dst_disabled": int}
        self.counts: Dict[str, Dict] = {t: {} for t in MIGRATION_ORDER}
        # Hosts disabled in source — tracked separately for final report
        self.disabled_hosts: List[str] = []
        # Hosts that were enabled in source but absent in destination after import
        self.missing_hosts_after_import: List[str] = []
        # Templates skipped (not linked to any active host, directly or indirectly)
        self.skipped_templates: List[str] = []

        self._username = username
        self._password = password

        logger.debug("Connecting to source: %s", source_url)
        self.source = ZabbixAPI(url=source_url)
        self.source.login(user=username, password=password)
        logger.debug("Source login OK.")

        logger.debug("Connecting to destination: %s", dest_url)
        self.dest = ZabbixAPI(url=dest_url)
        self.dest.login(user=username, password=password)
        logger.debug("Destination login OK.")

        # Store raw tokens for _raw_export/_raw_import — independent of pyzabbix internals
        self._src_token  = self._raw_login(self._source_url, username, password)
        self._dest_token = self._raw_login(self._dest_url,   username, password)

    @staticmethod
    def _raw_login(url: str, username: str, password: str) -> str:
        """
        Authenticate via raw HTTP and return the session token string.
        Tries 'username' (Zabbix 7.0) first, falls back to 'user' (Zabbix 6.x).
        """
        import requests as _requests
        api_url = url.rstrip("/") + "/api_jsonrpc.php"

        for user_key in ("username", "user"):
            payload = json.dumps({
                "jsonrpc": "2.0", "method": "user.login", "id": 1,
                "params": {user_key: username, "password": password}
            })
            resp = _requests.post(api_url, data=payload,
                                  headers={"Content-Type": "application/json"}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if "error" in data:
                err_msg = data["error"].get("data") or data["error"].get("message", "")
                # If the param name was wrong, try the other key
                if "username" in err_msg.lower() or "user" in err_msg.lower():
                    continue
                raise Exception(err_msg)
            return data["result"]

        raise Exception(f"user.login failed on {url} with both 'username' and 'user' params")

    def _reconnect(self):
        """Re-login to both source and destination and refresh raw tokens."""
        logger.debug("Re-connecting to source and destination...")
        self._src_token  = self._raw_login(self._source_url, self._username, self._password)
        self._dest_token = self._raw_login(self._dest_url,   self._username, self._password)
        # Keep pyzabbix session in sync too (for .host.get etc.)
        try:
            self.source = ZabbixAPI(url=self._source_url)
            self.source.login(user=self._username, password=self._password)
        except Exception as exc:
            logger.debug("pyzabbix source re-login failed: %s", exc)
        try:
            self.dest = ZabbixAPI(url=self._dest_url)
            self.dest.login(user=self._username, password=self._password)
        except Exception as exc:
            logger.debug("pyzabbix dest re-login failed: %s", exc)
        logger.debug("Re-connected OK.")

    def logout(self):
        """Gracefully logout from both APIs."""
        for api in (self.source, self.dest):
            try:
                api.logout()
            except Exception:
                pass

    # =======================================================================
    # 1. TEMPLATES
    # =======================================================================

    def migrate_templates(self):
        """
        Export and import only templates that are actually in use.

        A template is considered 'in use' if:
          - It is directly linked to at least one ENABLED host, OR
          - It is linked (nested) inside another template that is in use
            (resolved recursively so the full dependency tree is covered).

        All needed templates are exported and imported in a SINGLE batch call
        to avoid dependency errors caused by one template referencing objects
        that belong to a not-yet-imported nested template.
        """
        print("  [Templates] Analysing template usage on source...")

        # ── 1. Fetch all templates with their nested (linked) templates ──────
        try:
            all_templates = self.source.template.get(
                output=["templateid", "name"],
                selectParentTemplates=["templateid"]   # nested templates this one inherits
            )
        except Exception as exc:
            self._fail("templates", "template.get failed", exc)
            return

        if not all_templates:
            print("  [Templates] No templates found.")
            return

        tpl_by_id  = {t["templateid"]: t for t in all_templates}
        total      = len(all_templates)
        print(f"  [Templates] Found {total} templates total.")

        # Record source count; fetch dest count for comparison
        self.counts["templates"]["src_total"] = total
        try:
            dst_count = int(self.dest.template.get(countOutput=True))
            self.counts["templates"]["dst_total"] = dst_count
        except Exception:
            self.counts["templates"]["dst_total"] = -1

        # ── 2. Fetch all ENABLED hosts with their directly linked templates ──
        try:
            enabled_hosts = self.source.host.get(
                filter={"status": "0"},           # 0 = enabled
                output=["hostid", "name"],
                selectParentTemplates=["templateid"]
            )
        except Exception as exc:
            self._fail("templates", "host.get (for template linkage) failed", exc)
            return

        # Seed: templates directly linked to at least one enabled host
        needed_ids: set = set()
        for host in enabled_hosts:
            for tpl in host.get("parentTemplates", []):
                needed_ids.add(tpl["templateid"])

        # ── 3. Expand: add nested templates recursively ─────────────────────
        # If template A is needed and it inherits from template B,
        # B must also be imported (even if no host links B directly).
        changed = True
        while changed:
            changed = False
            for tid in list(needed_ids):
                tpl = tpl_by_id.get(tid)
                if not tpl:
                    continue
                for parent in tpl.get("parentTemplates", []):
                    pid = parent["templateid"]
                    if pid not in needed_ids:
                        needed_ids.add(pid)
                        changed = True

        # ── 4. Report skipped templates ──────────────────────────────────────
        not_needed = [t for t in all_templates if t["templateid"] not in needed_ids]
        if not_needed:
            self.skipped_templates = [t["name"] for t in not_needed]
            print(f"  [Templates] Skipping {len(not_needed)} template(s) "
                  f"not linked to any enabled host (directly or indirectly).")
            logger.debug("Skipped templates: %s", self.skipped_templates)

        if not needed_ids:
            print("  [Templates] No templates in use — nothing to import.")
            return

        needed_list = [t for t in all_templates if t["templateid"] in needed_ids]

        # ── skip_existing: remove templates already in destination ───────────
        if self.skip_existing and needed_list:
            try:
                dest_tpls     = self.dest.template.get(output=["name"])
                dest_tpl_names = {t["name"] for t in dest_tpls}
                already        = [t for t in needed_list if t["name"] in dest_tpl_names]
                needed_list    = [t for t in needed_list if t["name"] not in dest_tpl_names]
                needed_ids     = {t["templateid"] for t in needed_list}
                if already:
                    self.results["templates"]["skipped"] += len(already)
                    print(f"  [Templates] Skipping {len(already)} template(s) "
                          f"already in destination (--skip-existing).")
            except Exception as exc:
                print(f"  [Templates] Warning: could not check existing templates: {exc}")

        print(f"  [Templates] Will import {len(needed_list)} template(s) "
              f"individually (2-pass: topo-order + cross-ref retry).")

        # ── 5. Ensure template groups exist before import ────────────────────
        self._ensure_template_groups_for_templates()

        # ── 6. Topological sort using parentTemplates from template.get ────────
        # We derive the import order directly from the already-fetched needed_list
        # (which has parentTemplates).  No need to parse the batch export for this.
        tpl_id_to_name = {t["templateid"]: t["name"] for t in needed_list}
        all_needed_names = set(tpl_id_to_name.values())

        deps: Dict[str, set] = {t["name"]: set() for t in needed_list}
        for t in needed_list:
            name = t["name"]
            for p in t.get("parentTemplates", []):
                pname = tpl_id_to_name.get(p["templateid"], "")
                if pname and pname in all_needed_names and pname != name:
                    deps[name].add(pname)

        # Kahn's algorithm for topological sort
        in_degree: Dict[str, int] = {n: 0 for n in deps}
        children:  Dict[str, List[str]] = {n: [] for n in deps}
        for name, parents in deps.items():
            for p in parents:
                in_degree[name] += 1
                children[p].append(name)

        queue   = [n for n, d in in_degree.items() if d == 0]
        ordered: List[str] = []
        while queue:
            n = queue.pop(0)
            ordered.append(n)
            for child in children[n]:
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        # Append any remaining (cycles — uncommon but safe fallback)
        remaining = [n for n in deps if n not in ordered]
        ordered.extend(remaining)

        # name → templateid lookup for export calls
        tpl_name_to_id = {t["name"]: t["templateid"] for t in needed_list}

        # ── 7. Export + import each template individually, in topo order ────────
        # KEY DESIGN: one configuration.export call per template.
        # A batch export of N templates produces a top-level "graphs" array
        # containing cross-template graphs (graphs whose items span multiple
        # templates).  If we split the batch JSON and feed each slice to
        # configuration.import, those cross-template graphs end up in EVERY
        # template's payload — including templates that own zero graphs — causing
        # spurious "cannot find item" errors.
        # Exporting each template alone avoids this entirely: Zabbix only returns
        # what belongs to that specific template.
        SESSION_ERRORS = ("session terminated", "re-login", "not authorized",
                          "invalid token", "session expired")
        CROSS_REF_ERR  = "cannot find item"

        ok_count      = 0
        ok_names      : List[str] = []   # names of successfully imported templates
        deferred      : List[str] = []
        hard_failures : List[tuple] = []

        # Reconnect once before the loop — group creation above may have
        # been slow enough to let the session expire.
        try:
            self._reconnect()
        except Exception as exc:
            print(f"  [Templates] Warning: reconnect before import loop failed: {exc}")

        def _export_and_import_one(name: str, is_retry: bool = False) -> bool:
            """Export one template from source, import it into destination."""
            nonlocal ok_count, ok_names
            tid = tpl_name_to_id.get(name)
            if not tid:
                return True

            # Export this single template from source
            for attempt in range(2):
                try:
                    exported = self._raw_export("templates", [tid])
                    break
                except Exception as exc:
                    msg = str(exc)
                    if attempt == 0 and any(s in msg.lower() for s in SESSION_ERRORS):
                        self._reconnect()
                        continue
                    hard_failures.append((name, f"export failed: {msg}"))
                    self.results["templates"]["errors"].append(
                        {"name": name, "reason": f"export failed: {msg}"})
                    logger.debug("Template '%s' export FAILED: %s", name, msg)
                    return False

            # Import into destination — TWO STEPS to work around Zabbix 7.0
            # import ordering: it resolves template-dashboard graph references
            # before creating top-level graphs, so a one-shot import fails with
            # "Cannot find graph … used in dashboard".
            # Step 1: import everything EXCEPT template dashboards (items + graphs first).
            # Step 2: re-import with dashboards enabled (graphs now exist, refs resolve).
            for step, rules in [
                (1, TEMPLATE_IMPORT_RULES_NO_DASHBOARDS),
                (2, TEMPLATE_IMPORT_RULES),
            ]:
                for attempt in range(2):
                    try:
                        self._raw_import(fmt="yaml", source=exported, rules=rules)
                        break  # step succeeded
                    except Exception as exc:
                        msg = str(exc)
                        if attempt == 0 and any(s in msg.lower() for s in SESSION_ERRORS):
                            self._reconnect()
                            continue
                        # Only propagate errors on step 2 (step 1 partial failures
                        # are expected when the template has no dashboards at all).
                        if step == 2:
                            if not is_retry and CROSS_REF_ERR in msg.lower():
                                deferred.append(name)
                                logger.debug("Template '%s' deferred (cross-ref): %s", name, msg)
                                return False
                            hard_failures.append((name, msg))
                            self.results["templates"]["errors"].append(
                                {"name": name, "reason": msg})
                            logger.debug("Template '%s' FAILED (step 2): %s", name, msg)
                            return False
                        # Step 1 failed — log at debug and continue to step 2
                        # (step 2 is idempotent and will still create any missing objects).
                        logger.debug("Template '%s' step 1 non-fatal: %s", name, msg)
                        break

            ok_count += 1
            ok_names.append(name)
            logger.debug("Template '%s' imported OK.", name)
            return True

        # ── Pass 1: topo order ────────────────────────────────────────────────
        print(f"  [Templates] Importing {len(ordered)} templates "
              f"individually (1 export+import per template)...")
        for i, name in enumerate(ordered, 1):
            _export_and_import_one(name)
            if i % 50 == 0 or i == len(ordered):
                print(f"  [Templates] Progress: {i}/{len(ordered)} "
                      f"({ok_count} OK, {len(deferred)} deferred, "
                      f"{len(hard_failures)} failed)...")

        # ── Pass 2: retry deferred (cross-ref) ───────────────────────────────
        if deferred:
            print(f"  [Templates] Pass 2: retrying {len(deferred)} deferred template(s)...")
            still_deferred = list(deferred)
            deferred.clear()
            for name in still_deferred:
                _export_and_import_one(name, is_retry=True)
            if deferred:
                for name in deferred:
                    hard_failures.append((name, "cross-ref unresolved after pass 2"))
                    self.results["templates"]["errors"].append(
                        {"name": name, "reason": "cross-ref unresolved after pass 2"})
            print(f"  [Templates] Pass 2 done: {ok_count} total OK, "
                  f"{len(hard_failures)} total failed.")

        self.results["templates"]["migrated"] += ok_count
        self.results["templates"]["names"].extend(ok_names)
        self.results["templates"]["failed"]   += len(hard_failures)
        self.results["templates"]["skipped"]  += len(not_needed)

        print(f"  [Templates] Done: {ok_count} imported, {len(hard_failures)} failed.")
        try:
            self.counts["templates"]["dst_total"] = int(
                self.dest.template.get(countOutput=True))
        except Exception:
            pass

    def _ensure_template_groups_for_templates(self):
        """Create any missing template groups in destination before template import."""
        try:
            src_groups = self.source.templategroup.get(output=["name"])
            self._ensure_groups_in_dest(
                src_groups, "name",
                lambda name: self.dest.templategroup.get(filter={"name": name}, output=["groupid"]),
                lambda name: self.dest.templategroup.create(name=name),
                label="template group"
            )
        except Exception as exc:
            print(f"  [Templates] Warning: could not pre-create template groups: {exc}")

    # =======================================================================
    # 2. HOSTS
    # =======================================================================

    def migrate_hosts(self):
        """
        Export and import only ENABLED hosts from source.

        Strategy:
          1. Try batch import of all enabled hosts at once (fast path).
          2. If batch fails, fall back to importing each host individually
             so a single bad host does not block the rest.
          3. Disabled hosts are skipped silently — detail goes to log only.
          4. After import, verify counts in destination.
        """
        EXCLUDED_GROUP = "Discovered hosts"

        # Zabbix flags field:
        #   0 = plain host (manually created)
        #   2 = host prototype (defined inside a template/host LLD rule)
        #   4 = discovered host (auto-created at runtime by LLD)
        # We only want to migrate plain hosts (flags=0).
        # We request flags in the output and filter client-side (belt-and-suspenders)
        # because passing filter={"flags":"0"} via pyzabbix keyword args can be
        # unreliable — "filter" is a Python builtin and some versions mangle it.
        print("  [Hosts] Fetching host list from source (plain hosts only, flags=0)...")
        try:
            all_hosts = self.source.host.get(
                output=["hostid", "name", "status", "flags"],
            )
        except Exception as exc:
            self._fail("hosts", "host.get failed", exc)
            return

        if not all_hosts:
            print("  [Hosts] No hosts found.")
            return

        # Client-side filter: keep only flags=0 (plain/manually-created hosts).
        # flags=2: host prototypes (LLD-defined, live inside discovery rules).
        # flags=4: discovered hosts (auto-created at runtime by LLD).
        # Neither should be migrated — they are recreated automatically when the
        # templates and their LLD rules are in place on the destination.
        lld_hosts = [h for h in all_hosts if str(h.get("flags", "0")) != "0"]
        if lld_hosts:
            print(f"  [Hosts] Excluding {len(lld_hosts)} LLD-managed host(s) "
                  f"(flags≠0: host prototypes + discovered hosts).")
            logger.debug("Excluded LLD hosts: %s", [h["name"] for h in lld_hosts])
        all_hosts = [h for h in all_hosts if str(h.get("flags", "0")) == "0"]

        if not all_hosts:
            print("  [Hosts] No plain hosts found after LLD exclusion.")
            return

        enabled  = [h for h in all_hosts if str(h.get("status", "0")) == "0"]
        disabled = [h for h in all_hosts if str(h.get("status", "0")) != "0"]

        # Record source counts
        self.counts["hosts"]["src_total"]    = len(all_hosts)
        self.counts["hosts"]["src_enabled"]  = len(enabled)
        self.counts["hosts"]["src_disabled"] = len(disabled)

        # Fetch destination counts now (before import, for a baseline)
        try:
            dst_all  = self.dest.host.get(output=["status"], countOutput=True)
            dst_ena  = self.dest.host.get(filter={"status": "0"}, output=["status"], countOutput=True)
            self.counts["hosts"]["dst_total"]    = int(dst_all)
            self.counts["hosts"]["dst_enabled"]  = int(dst_ena)
            self.counts["hosts"]["dst_disabled"] = int(dst_all) - int(dst_ena)
        except Exception:
            self.counts["hosts"]["dst_total"] = -1

        # --host filter: restrict to a single host by name
        if self.host_filter:
            enabled = [h for h in enabled if h["name"] == self.host_filter]
            disabled = []
            if not enabled:
                print(f"  [Hosts] Host '{self.host_filter}' not found "
                      f"(or is disabled) in source.")
                return
            print(f"  [Hosts] Filtered to single host: '{self.host_filter}'.")

        print(f"  [Hosts] Source — total: {len(all_hosts)}, "
              f"enabled: {len(enabled)}, disabled: {len(disabled)}.")

        if disabled:
            self.disabled_hosts = [h["name"] for h in disabled]
            self.results["hosts"]["skipped"] += len(disabled)
            # No console detail — disabled list goes to log file only

        if not enabled:
            print("  [Hosts] No enabled hosts to import.")
            return

        self._ensure_host_groups_for_hosts()

        # ── skip_existing: remove hosts already in destination ───────────────
        if self.skip_existing:
            try:
                dest_host_names = {h["name"] for h in self.dest.host.get(output=["name"])}
                already  = [h for h in enabled if h["name"] in dest_host_names]
                enabled  = [h for h in enabled if h["name"] not in dest_host_names]
                if already:
                    self.results["hosts"]["skipped"] += len(already)
                    print(f"  [Hosts] Skipping {len(already)} host(s) "
                          f"already in destination (--skip-existing).")
            except Exception as exc:
                print(f"  [Hosts] Warning: could not check existing hosts: {exc}")

        if not enabled:
            print("  [Hosts] No new hosts to import after skip-existing filter.")
            return

        # Refresh sessions — group sync + skip-existing queries may have been
        # slow enough to expire the source or destination session token.
        try:
            self._reconnect()
        except Exception as exc:
            print(f"  [Hosts] Warning: reconnect before import failed: {exc}")

        # ── Chunked export + import ──────────────────────────────────────────
        # Export/import in chunks to avoid session timeout on large sets.
        CHUNK_SIZE  = 100
        SESSION_ERRORS = ("session terminated", "re-login", "not authorized",
                          "invalid token", "session expired")
        total_hosts = len(enabled)
        ok_count    = 0
        chunks      = [enabled[i:i+CHUNK_SIZE]
                       for i in range(0, total_hosts, CHUNK_SIZE)]

        print(f"  [Hosts] Importing {total_hosts} hosts "
              f"in {len(chunks)} chunk(s) of up to {CHUNK_SIZE}...")

        for chunk_idx, chunk in enumerate(chunks, 1):
            chunk_ids = [h["hostid"] for h in chunk]

            # --- export chunk ---
            for attempt in range(2):
                try:
                    chunk_exported = self._raw_export("hosts", chunk_ids)
                    break
                except Exception as exc:
                    if attempt == 0 and any(s in str(exc).lower() for s in SESSION_ERRORS):
                        print(f"  [Hosts] Session expired during export "
                              f"(chunk {chunk_idx}/{len(chunks)}) — reconnecting...")
                        self._reconnect()
                    else:
                        # Record every host in this chunk as failed
                        for h in chunk:
                            self.results["hosts"]["errors"].append({
                                "name": h["name"], "reason": str(exc)})
                            self.results["hosts"]["failed"] += 1
                        chunk_exported = None
                        break

            if chunk_exported is None:
                continue

            # --- import chunk ---
            for attempt in range(2):
                try:
                    self._raw_import(fmt="yaml", source=chunk_exported,
                                     rules=HOST_IMPORT_RULES)
                    ok_count += len(chunk)
                    break
                except Exception as exc:
                    if attempt == 0 and any(s in str(exc).lower() for s in SESSION_ERRORS):
                        print(f"  [Hosts] Session expired during import "
                              f"(chunk {chunk_idx}/{len(chunks)}) — reconnecting...")
                        self._reconnect()
                    else:
                        # Chunk import failed — fall back to per-host for this chunk
                        for h in chunk:
                            for h_attempt in range(2):
                                try:
                                    h_exp = self._raw_export("hosts", [h["hostid"]])
                                    self._raw_import(fmt="yaml", source=h_exp,
                                                     rules=HOST_IMPORT_RULES)
                                    ok_count += 1
                                    break
                                except Exception as h_exc:
                                    if h_attempt == 0 and any(
                                            s in str(h_exc).lower() for s in SESSION_ERRORS):
                                        self._reconnect()
                                    else:
                                        self.results["hosts"]["errors"].append({
                                            "name": h["name"], "reason": str(h_exc)})
                                        self.results["hosts"]["failed"] += 1
                                        break
                        break

            if chunk_idx % 10 == 0 or chunk_idx == len(chunks):
                print(f"  [Hosts] Progress: {chunk_idx}/{len(chunks)} chunks  "
                      f"({ok_count} OK so far)...")

        # ── Post-import verification ─────────────────────────────────────────
        print("  [Hosts] Verifying destination...")
        try:
            dest_hosts  = self.dest.host.get(output=["name", "status"])
            dest_names  = {h["name"] for h in dest_hosts}
            dst_enabled = sum(1 for h in dest_hosts if str(h.get("status","0")) == "0")
            self.counts["hosts"]["dst_total"]    = len(dest_hosts)
            self.counts["hosts"]["dst_enabled"]  = dst_enabled
            self.counts["hosts"]["dst_disabled"] = len(dest_hosts) - dst_enabled
        except Exception as exc:
            print(f"  [Hosts] Warning: could not verify destination: {exc}")
            dest_names = None

        enabled_names = {h["name"] for h in enabled}

        if dest_names is not None:
            missing_after  = sorted(enabled_names - dest_names)
            confirmed_names = sorted(enabled_names - set(missing_after))
            confirmed       = len(confirmed_names)
            self.results["hosts"]["migrated"] += confirmed
            self.results["hosts"]["names"].extend(confirmed_names)
            print(f"  [Hosts] Destination — confirmed: {confirmed}, "
                  f"missing: {len(missing_after)}.")
            if missing_after:
                self.missing_hosts_after_import = missing_after
                # Add to errors only if not already recorded from per-host loop
                already = {e["name"] for e in self.results["hosts"]["errors"]}
                for name in missing_after:
                    if name not in already:
                        self.results["hosts"]["errors"].append({
                            "name": name,
                            "reason": "not found in destination after import"
                        })
                        self.results["hosts"]["failed"] += 1
        else:
            self.results["hosts"]["migrated"] += len(enabled)
            self.results["hosts"]["names"].extend(sorted(h["name"] for h in enabled))

    def _ensure_host_groups_for_hosts(self):
        """Create any missing host groups in destination before host import."""
        try:
            src_groups = self.source.hostgroup.get(output=["name"])
            self._ensure_groups_in_dest(
                src_groups, "name",
                lambda name: self.dest.hostgroup.get(filter={"name": name}, output=["groupid"]),
                lambda name: self.dest.hostgroup.create(name=name),
                label="host group"
            )
        except Exception as exc:
            print(f"  [Hosts] Warning: could not pre-create host groups: {exc}")

    # =======================================================================
    # 3. MAPS
    # =======================================================================

    def _topo_sort_maps(self, maps: list) -> list:
        """Return maps in dependency order (referenced maps first).

        A map that contains a selement of elementtype=1 (map element) depends
        on the referenced map. We topo-sort within the set of maps being
        imported so that a sub-map is always imported before the parent that
        references it. Maps already present in the destination are treated as
        already resolved and skipped in the dep-graph.
        """
        mid_to_map = {m["sysmapid"]: m for m in maps}
        import_mids = set(mid_to_map)

        # Build dep graph: mid -> set of mids it needs (within import_mids only)
        deps: dict[str, set] = {m["sysmapid"]: set() for m in maps}
        for m in maps:
            for sel in m.get("_selements", []):
                if str(sel.get("elementtype")) == "1":   # elementtype 1 = map
                    for el in sel.get("elements", []):
                        ref = str(el.get("sysmapid", ""))
                        if ref and ref in import_mids and ref != m["sysmapid"]:
                            deps[m["sysmapid"]].add(ref)

        # DFS topo-sort
        ordered: list = []
        visited: set = set()
        in_stack: set = set()

        def visit(mid: str):
            if mid in visited:
                return
            if mid in in_stack:
                # Circular reference — break the cycle silently
                return
            in_stack.add(mid)
            for dep in deps.get(mid, set()):
                visit(dep)
            in_stack.discard(mid)
            visited.add(mid)
            if mid in mid_to_map:
                ordered.append(mid_to_map[mid])

        for m in maps:
            visit(m["sysmapid"])

        return ordered

    def migrate_maps(self):
        """Export all network maps from source and import to destination."""
        print("  [Maps] Fetching map list from source...")
        try:
            # selectSelements is needed for topo-sort (inter-map dependencies).
            raw_maps = self.source.map.get(
                output=["sysmapid", "name"],
                selectSelements=["selementid", "elementtype", "elements"],
            )
            # Store selement data under a private key; keep main fields clean.
            maps = []
            for m in raw_maps:
                entry = {"sysmapid": m["sysmapid"], "name": m["name"],
                         "_selements": m.get("selements", [])}
                maps.append(entry)
        except Exception as exc:
            self._fail("maps", "map.get failed", exc)
            return

        if not maps:
            print("  [Maps] No maps found.")
            return

        print(f"  [Maps] Found {len(maps)} maps.")

        self.counts["maps"]["src_total"] = len(maps)
        try:
            self.counts["maps"]["dst_total"] = int(self.dest.map.get(countOutput=True))
        except Exception:
            self.counts["maps"]["dst_total"] = -1

        # Maps can reference host groups — ensure they exist
        self._ensure_host_groups_for_maps()

        # ── skip_existing: remove maps already in destination ────────────────
        if self.skip_existing:
            try:
                dest_map_names = {m["name"] for m in self.dest.map.get(output=["name"])}
                already = [m for m in maps if m["name"] in dest_map_names]
                maps    = [m for m in maps if m["name"] not in dest_map_names]
                if already:
                    self.results["maps"]["skipped"] += len(already)
                    print(f"  [Maps] Skipping {len(already)} map(s) "
                          f"already in destination (--skip-existing).")
            except Exception as exc:
                print(f"  [Maps] Warning: could not check existing maps: {exc}")

        if not maps:
            print("  [Maps] No new maps to import after skip-existing filter.")
            return

        # ── Topo-sort: import sub-maps before the maps that reference them ────
        # A map element (elementtype=1) references another map by sysmapid.
        # If both maps are being imported in this run, the referenced map must
        # be imported first — otherwise Zabbix 7.0 rejects the parent with
        # "Cannot find map X used in map Y".
        maps = self._topo_sort_maps(maps)
        logger.debug("Maps topo-sort order: %s", [m["name"] for m in maps])

        SESSION_ERRORS = ("session terminated", "re-login", "not authorized",
                          "invalid token", "session expired")

        try:
            self._reconnect()
        except Exception as exc:
            print(f"  [Maps] Warning: reconnect before export failed: {exc}")

        # ── Per-map export+import ─────────────────────────────────────────────
        # One map at a time so a single bad map never blocks the rest.
        #
        # FORMAT: JSON (not YAML)
        # ─────────────────────────────────────────────────────────────────────
        # Zabbix 6.4 YAML export is NOT used for maps because PyYAML 1.1
        # corrupts hex color values (e.g. "000000" → int 0, "000066" → int 54)
        # when loading the YAML, and yaml.dump re-serialises them in a way that
        # Zabbix 7.0's PHP validator rejects ("a character string is expected").
        # The Zabbix 7.0 FRONTEND can import 6.4 YAML directly because Symfony
        # YAML (the PHP YAML parser) handles "000000" as a string — but our
        # Python yaml module does not.
        #
        # JSON has no such ambiguity: "font_color": "000000" is always a string.
        # We export as JSON, fix the structure with the json module (no type
        # corruption), and import as JSON.  All color values are preserved
        # exactly as Zabbix stored them.
        #
        # Schema fixes applied after json.loads:
        #   1. MISSING / NULL ARRAYS
        #      6.4 JSON export omits empty arrays entirely (unlike YAML which
        #      outputs `{  }`).  Zabbix 7.0 requires the keys to be present.
        #      Fields ensured:
        #        map:       links, shapes, lines, urls, selements
        #        selement:  elements (types 0/1/2/3 only), urls, tags
        #        link:      linktriggers
        #   2. ORPHANED SELEMENTS
        #      Selements of type 0/1/2/3 (host/map/trigger/hostgroup) with an
        #      empty elements list reference objects deleted in source.
        #      Zabbix 7.0 rejects them with "elements: cannot be empty" — drop.
        #   3. BAD URLS
        #      URL entries with an empty/whitespace url string fail validation
        #      with "Wrong value for url field" — drop them.
        print(f"  [Maps] Importing {len(maps)} maps individually (JSON format)...")
        ok_count  = 0
        ok_names  = []
        fail_maps = []

        for i, m in enumerate(maps, 1):
            map_name = m["name"]
            mid      = m["sysmapid"]

            # Export single map as JSON
            for attempt in range(2):
                try:
                    exported = self._raw_export("maps", [mid], fmt="json")
                    break
                except Exception as exc:
                    if attempt == 0 and any(s in str(exc).lower() for s in SESSION_ERRORS):
                        self._reconnect()
                        continue
                    fail_maps.append((map_name, f"export failed: {exc}"))
                    exported = None
                    break

            if exported is None:
                continue

            # ── 6.4 → 7.0 schema patch (JSON) ────────────────────────────────
            try:
                export_data = json.loads(exported)
                root = export_data.get("zabbix_export", export_data)
                patch_log = []

                def _ensure_list(obj, field):
                    """Ensure field exists and is a list (not None/missing)."""
                    val = obj.get(field)
                    if val is None:
                        obj[field] = []
                        patch_log.append(f"missing:{field}")
                    elif not isinstance(val, list):
                        obj[field] = list(val) if hasattr(val, '__iter__') else []
                        patch_log.append(f"nonlist:{field}")

                for smap in root.get("maps", []):
                    _ensure_list(smap, "links")
                    _ensure_list(smap, "shapes")
                    _ensure_list(smap, "lines")
                    _ensure_list(smap, "urls")
                    _ensure_list(smap, "selements")

                    for sel in smap.get("selements", []):
                        etype = str(sel.get("elementtype", "4"))
                        if etype == "4":
                            # Image selements: elements field must be ABSENT.
                            if "elements" in sel:
                                del sel["elements"]
                                patch_log.append("removed:type4-elements")
                        else:
                            _ensure_list(sel, "elements")
                        _ensure_list(sel, "urls")
                        _ensure_list(sel, "tags")

                    for link in smap.get("links", []):
                        _ensure_list(link, "linktriggers")

                    # Drop orphaned selements (type 0/1/2/3 with empty elements)
                    before = len(smap.get("selements", []))
                    smap["selements"] = [
                        sel for sel in smap.get("selements", [])
                        if str(sel.get("elementtype")) == "4"
                        or sel.get("elements")
                    ]
                    dropped = before - len(smap["selements"])
                    if dropped:
                        patch_log.append(f"dropped:{dropped}×empty-selements")

                    # Drop URL entries with empty/whitespace url string
                    for sel in smap.get("selements", []):
                        before_urls = len(sel.get("urls", []))
                        sel["urls"] = [
                            u for u in sel.get("urls", [])
                            if isinstance(u.get("url"), str) and u["url"].strip()
                        ]
                        if len(sel["urls"]) < before_urls:
                            patch_log.append("dropped:bad-url")

                    for obj in smap.get("links", []) + [smap]:
                        if "urls" in obj and isinstance(obj["urls"], list):
                            before_urls = len(obj["urls"])
                            obj["urls"] = [
                                u for u in obj["urls"]
                                if isinstance(u.get("url"), str) and u["url"].strip()
                            ]
                            if len(obj["urls"]) < before_urls:
                                patch_log.append("dropped:bad-url")

                exported = json.dumps(export_data)

                if patch_log:
                    summary = ", ".join(
                        f"{cnt}×{tag}" for tag, cnt in
                        sorted(
                            {t: patch_log.count(t) for t in set(patch_log)}.items(),
                            key=lambda x: -x[1]
                        )
                    )
                    logger.debug("Map '%s': patched: %s", map_name, summary)

            except Exception as exc:
                # If patch fails, try with raw JSON export as-is
                logger.warning("Map '%s': JSON patch failed, using raw export: %s",
                               map_name, exc)
                print(f"  [Maps] WARNING: patch failed for '{map_name}': {exc}")

            # Import
            for attempt in range(2):
                try:
                    self._raw_import(fmt="json", source=exported, rules=MAP_IMPORT_RULES)
                    ok_count += 1
                    ok_names.append(map_name)
                    break
                except Exception as exc:
                    if attempt == 0 and any(s in str(exc).lower() for s in SESSION_ERRORS):
                        self._reconnect()
                        continue
                    fail_maps.append((map_name, str(exc)))
                    break

            if i % 100 == 0 or i == len(maps):
                print(f"  [Maps] Progress: {i}/{len(maps)} "
                      f"({ok_count} OK, {len(fail_maps)} failed)...")

        self.results["maps"]["migrated"] += ok_count
        self.results["maps"]["names"].extend(ok_names)
        self.results["maps"]["failed"]   += len(fail_maps)
        for name, reason in fail_maps:
            self.results["maps"]["errors"].append({"name": name, "reason": reason})

        print(f"  [Maps] Done: {ok_count} imported, {len(fail_maps)} failed.")
        try:
            self.counts["maps"]["dst_total"] = int(self.dest.map.get(countOutput=True))
        except Exception:
            pass

    def _ensure_host_groups_for_maps(self):
        """Create any missing host groups in destination before map import."""
        try:
            src_groups = self.source.hostgroup.get(output=["name"])
            self._ensure_groups_in_dest(
                src_groups, "name",
                lambda name: self.dest.hostgroup.get(filter={"name": name}, output=["groupid"]),
                lambda name: self.dest.hostgroup.create(name=name),
                label="host group (for maps)"
            )
        except Exception as exc:
            print(f"  [Maps] Warning: could not pre-create host groups: {exc}")

    # =======================================================================
    # 4. DASHBOARDS
    # =======================================================================

    def migrate_dashboards(self):
        """Migrate all dashboards with full widget field resolution."""
        print("  [Dashboards] Fetching dashboard list from source...")
        try:
            dashboards = self.source.dashboard.get(
                output="extend",
                selectPages="extend",
                selectUsers="extend",
                selectUserGroups="extend"
            )
        except Exception as exc:
            self._fail("dashboards", "dashboard.get failed", exc)
            return

        if not dashboards:
            print("  [Dashboards] No dashboards found.")
            return

        print(f"  [Dashboards] Found {len(dashboards)} dashboards.")

        self.counts["dashboards"]["src_total"] = len(dashboards)
        try:
            self.counts["dashboards"]["dst_total"] = int(
                self.dest.dashboard.get(countOutput=True))
        except Exception:
            self.counts["dashboards"]["dst_total"] = -1

        # Filter to a specific dashboard if requested
        if self.dashboard_filter:
            dashboards = [d for d in dashboards
                          if d.get("name") == self.dashboard_filter]
            if not dashboards:
                print(f"  [Dashboards] Dashboard '{self.dashboard_filter}' not found in source.")
                return
            print(f"  [Dashboards] Filtered to: '{self.dashboard_filter}'")

        print()
        for dashboard in dashboards:
            name = dashboard.get("name", "Unnamed")
            print(f"  [Dashboards] Processing: {name}")
            self._migrate_one_dashboard(dashboard)
            print()

    def _migrate_one_dashboard(self, dashboard: Dict):
        name = dashboard.get("name", "Unnamed")
        try:
            # Check existence
            if self._dashboard_exists(name):
                if self.skip_existing:
                    print(f"    ~ Skipped (already exists): {name}")
                    self.results["dashboards"]["skipped"] += 1
                    return
                else:
                    self._delete_dashboard(name)

            print("    - Resolving owner...")
            owner_userid, extra_groups = self._resolve_dashboard_owner(
                dashboard.get("userid", "")
            )

            print("    - Converting widget IDs to names...")
            converted = self._resolve_names(dashboard)

            print("    - Resolving names to destination IDs...")
            resolved, hard_missing, soft_warnings = self._resolve_ids(converted)

            # Soft warnings: shared groups not found in destination — drop them,
            # log quietly, and continue creating the dashboard.
            if soft_warnings:
                for w in soft_warnings:
                    logger.info("[Dashboard '%s'] %s", name, w)

            # Hard failures: widget data objects missing — skip dashboard.
            if hard_missing:
                print(f"    x Skipped -- {len(hard_missing)} missing widget objects "
                      f"in destination:")
                for obj in hard_missing:
                    print(f"      - {obj}")
                self.results["dashboards"]["failed"] += 1
                self.results["dashboards"]["errors"].append({
                    "name": name,
                    "reason": "Missing widget objects in destination",
                    "details": hard_missing
                })
                return

            print("    - Creating dashboard...")
            self._create_dashboard(resolved, owner_userid, extra_groups)
            self.results["dashboards"]["migrated"] += 1
            self.results["dashboards"]["names"].append(name)

        except Exception as exc:
            print(f"    x Error: {exc}")
            self.results["dashboards"]["failed"] += 1
            self.results["dashboards"]["errors"].append({
                "name": name, "reason": str(exc)
            })

    # -----------------------------------------------------------------------
    # Dashboard: owner resolution
    # -----------------------------------------------------------------------

    def _resolve_dashboard_owner(self, source_userid: str) -> Tuple[str, List[Dict]]:
        """
        Determine the owner userid and any extra sharing groups for the destination.

        Steps:
          1. Look up original owner username in source.
          2. Try to find the same user in destination → use their ID directly.
          3. If not found:
             a. Use fallback owner FALLBACK_OWNER.
             b. Get the original user's usergroups in source.
             c. Find which of those groups exist in destination.
             d. Return those groups for sharing with Edit (read-write) permission.
        """
        extra_groups: List[Dict] = []

        # Get original owner's username
        src_username = None
        if source_userid:
            try:
                data = self.source.user.get(
                    userids=source_userid,
                    output=["username"]
                )
                src_username = data[0]["username"] if data else None
            except Exception as exc:
                logger.debug("Could not get source user %s: %s", source_userid, exc)

        if src_username:
            # Try to find same user in destination
            try:
                dest_data = self.dest.user.get(
                    filter={"username": src_username},
                    output=["userid"]
                )
                if dest_data:
                    logger.debug("Owner '%s' found in destination.", src_username)
                    return dest_data[0]["userid"], []
            except Exception as exc:
                logger.debug("Error looking up user '%s' in destination: %s",
                             src_username, exc)

        # Owner not found in destination — use fallback
        print(f"    ! Owner '{src_username or source_userid}' not found in destination.")
        print(f"      Using fallback owner: '{FALLBACK_OWNER}'")

        fallback_id = self._get_fallback_owner_id()

        # Resolve original user's groups and find which exist in destination
        if src_username and source_userid:
            extra_groups = self._resolve_owner_groups_for_sharing(
                source_userid, src_username
            )

        return fallback_id, extra_groups

    def _get_fallback_owner_id(self) -> str:
        """Return the userid of FALLBACK_OWNER in destination, raise if not found."""
        try:
            data = self.dest.user.get(
                filter={"username": FALLBACK_OWNER},
                output=["userid"]
            )
            if data:
                return data[0]["userid"]
        except Exception as exc:
            logger.debug("Error looking up fallback user: %s", exc)
        raise RuntimeError(
            f"Fallback owner '{FALLBACK_OWNER}' not found in destination. "
            "Please create this user before running the migration."
        )

    def _resolve_owner_groups_for_sharing(
            self, source_userid: str, src_username: str) -> List[Dict]:
        """
        Get the source user's usergroups and return those that also exist in
        the destination, formatted as dashboard sharing entries with Edit permission.
        """
        sharing: List[Dict] = []
        try:
            # Get groups of original user in source
            src_groups = self.source.usergroup.get(
                userids=source_userid,
                output=["usrgrpid", "name"]
            )
        except Exception as exc:
            logger.debug("Could not get usergroups for '%s': %s", src_username, exc)
            return sharing

        print(f"      Original user '{src_username}' belongs to "
              f"{len(src_groups)} group(s) in source:")

        for grp in src_groups:
            gname = grp["name"]
            try:
                dest_grp = self.dest.usergroup.get(
                    filter={"name": gname},
                    output=["usrgrpid"]
                )
                if dest_grp:
                    sharing.append({
                        "usrgrpid":  dest_grp[0]["usrgrpid"],
                        "permission": PERM_READ_WRITE
                    })
                    print(f"        + Group '{gname}' exists in destination → "
                          "will share with Edit permission")
                else:
                    print(f"        - Group '{gname}' NOT found in destination → skipped")
            except Exception as exc:
                logger.debug("Error resolving group '%s': %s", gname, exc)

        return sharing

    # -----------------------------------------------------------------------
    # Dashboard: name/ID resolution (phase 1 — source side)
    # -----------------------------------------------------------------------

    def _resolve_names(self, dashboard: Dict) -> Dict:
        """Convert every object ID in a dashboard to a portable name."""
        converted = dashboard.copy()

        # Shared users — intentionally skipped.
        # Individual user shares are not migrated: the dashboard owner is
        # normalised to the fallback account, and access is granted via group
        # shares instead.  This avoids failures caused by users existing in
        # source but not in destination.
        converted["users"] = []

        # Shared user groups
        if dashboard.get("userGroups"):
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                try:
                    data = self.source.usergroup.get(
                        usrgrpids=group["usrgrpid"], output=["name"])
                    if data:
                        converted["userGroups"].append({
                            "name":       data[0]["name"],
                            "permission": group["permission"]
                        })
                except Exception:
                    pass

        # Pages and widgets
        if dashboard.get("pages"):
            converted["pages"] = []
            for page in dashboard["pages"]:
                cp = page.copy()
                if page.get("widgets"):
                    cp["widgets"] = [
                        self._widget_ids_to_names(w) for w in page["widgets"]
                    ]
                converted["pages"].append(cp)

        return converted

    def _widget_ids_to_names(self, widget: Dict) -> Dict:
        """Resolve every object-reference field ID to a portable name."""
        converted = widget.copy()
        wtype = widget.get("type", "?")

        if not widget.get("fields"):
            return converted

        converted["fields"] = []
        for field in widget["fields"]:
            cf    = field.copy()
            ftype = str(field.get("type", ""))
            fname = field.get("name", "")
            fval  = field.get("value")

            try:
                if ftype == FIELD_TYPE_HOST_GROUP:
                    data = self.source.hostgroup.get(groupids=fval, output=["name"])
                    cf["value_name"] = data[0]["name"] if data else _INACCESSIBLE

                elif ftype == FIELD_TYPE_HOST:
                    data = self.source.host.get(hostids=fval, output=["host"])
                    cf["value_name"] = data[0]["host"] if data else _INACCESSIBLE

                elif ftype == FIELD_TYPE_ITEM:
                    data = self.source.item.get(
                        itemids=fval, output=["key_"], selectHosts=["host"])
                    if data:
                        cf["value_name"] = data[0]["key_"]
                        cf["host_name"]  = data[0]["hosts"][0]["host"]
                    else:
                        cf["value_name"] = _INACCESSIBLE

                elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:
                    data = self.source.itemprototype.get(
                        itemids=fval, output=["key_"], selectHosts=["host"])
                    if data:
                        cf["value_name"] = data[0]["key_"]
                        cf["host_name"]  = data[0]["hosts"][0]["host"]
                    else:
                        cf["value_name"] = _INACCESSIBLE

                elif ftype == FIELD_TYPE_GRAPH:
                    data = self.source.graph.get(
                        graphids=fval, output=["name"], selectHosts=["host"])
                    if data:
                        cf["value_name"] = data[0]["name"]
                        if data[0].get("hosts"):
                            cf["host_name"] = data[0]["hosts"][0]["host"]
                    else:
                        cf["value_name"] = _INACCESSIBLE

                elif ftype == FIELD_TYPE_GRAPH_PROTO:
                    data = self.source.graphprototype.get(
                        graphids=fval, output=["name"], selectHosts=["host"])
                    if data:
                        cf["value_name"] = data[0]["name"]
                        if data[0].get("hosts"):
                            cf["host_name"] = data[0]["hosts"][0]["host"]
                    else:
                        cf["value_name"] = _INACCESSIBLE

                elif ftype == FIELD_TYPE_MAP:
                    data = self.source.map.get(sysmapids=fval, output=["name"])
                    cf["value_name"] = data[0]["name"] if data else _INACCESSIBLE

                else:
                    logger.debug("[%s] field '%s' type=%s -> pass-through",
                                 wtype, fname, ftype)

            except Exception as exc:
                logger.debug("[%s] field '%s' error: %s -> inaccessible",
                             wtype, fname, exc)
                cf["value_name"] = _INACCESSIBLE

            converted["fields"].append(cf)

        return converted

    # -----------------------------------------------------------------------
    # Dashboard: name/ID resolution (phase 2 — destination side)
    # -----------------------------------------------------------------------

    def _resolve_ids(self, dashboard: Dict) -> Tuple[Dict, List[str], List[str]]:
        """Convert portable names back to IDs valid in the destination.

        Returns:
            (converted_dashboard, hard_missing, soft_warnings)

            hard_missing  - widget data objects (hosts, items, graphs, maps…)
                            not found in destination; block dashboard creation.
            soft_warnings - individual shared users/groups not found in
                            destination; dropped silently, dashboard still created.
        """
        converted = dashboard.copy()
        hard_missing: List[str] = []
        soft_warnings: List[str] = []

        # Shared users — always empty (dropped at resolve_names stage).
        converted["users"] = []

        # Shared user groups — drop if not in destination (soft warning only)
        if dashboard.get("userGroups"):
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                data = self.dest.usergroup.get(
                    filter={"name": group["name"]}, output=["usrgrpid"])
                if data:
                    converted["userGroups"].append({
                        "usrgrpid":   data[0]["usrgrpid"],
                        "permission": group["permission"]
                    })
                else:
                    soft_warnings.append(
                        f"Shared group not in destination (dropped): '{group['name']}'")

        # Pages and widgets — missing data objects are hard failures
        if dashboard.get("pages"):
            converted["pages"] = []
            for page in dashboard["pages"]:
                cp = page.copy()
                if page.get("widgets"):
                    cp["widgets"] = []
                    for widget in page["widgets"]:
                        w, w_miss = self._widget_names_to_ids(widget)
                        cp["widgets"].append(w)
                        hard_missing.extend(w_miss)
                converted["pages"].append(cp)

        return converted, hard_missing, soft_warnings

    def _widget_names_to_ids(self, widget: Dict) -> Tuple[Dict, List[str]]:
        """Resolve portable names to destination IDs. Drop _INACCESSIBLE fields."""
        converted = widget.copy()
        missing: List[str] = []
        wname = widget.get("name", "?")
        wtype = widget.get("type", "?")

        if not widget.get("fields"):
            return converted, missing

        converted["fields"] = []
        for field in widget["fields"]:
            cf    = field.copy()
            ftype = str(field.get("type", ""))
            fname = field.get("name", "")

            # Pass-through fields (no value_name means integer/string/etc.)
            if "value_name" not in field:
                converted["fields"].append(cf)
                continue

            # Silently drop fields that were inaccessible in source
            if field["value_name"] == _INACCESSIBLE:
                logger.debug("[%s '%s'] field '%s' inaccessible in source, dropped",
                             wtype, wname, fname)
                continue

            vname = field["value_name"]
            ctx   = f"widget '{wname}' (type:{wtype}) field '{fname}'"

            try:
                if ftype == FIELD_TYPE_HOST_GROUP:
                    data = self.dest.hostgroup.get(
                        filter={"name": vname}, output=["groupid"])
                    if data:
                        cf["value"] = data[0]["groupid"]
                    else:
                        annotation = self._annotate_missing_group(vname)
                        missing.append(f"Host group '{vname}' [{ctx}]{annotation}")

                elif ftype == FIELD_TYPE_HOST:
                    data = self.dest.host.get(
                        filter={"host": vname}, output=["hostid"])
                    if data:
                        cf["value"] = data[0]["hostid"]
                    else:
                        annotation = self._annotate_missing_host(vname)
                        missing.append(f"Host '{vname}' [{ctx}]{annotation}")

                elif ftype == FIELD_TYPE_ITEM:
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name}, output=["hostid"])
                        if hosts:
                            items = self.dest.item.get(
                                filter={"key_": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["itemid"])
                            if items:
                                cf["value"] = items[0]["itemid"]
                            else:
                                missing.append(
                                    f"Item '{vname}' on host '{host_name}' [{ctx}]")
                        else:
                            missing.append(
                                f"Host '{host_name}' (for item '{vname}') [{ctx}]")
                    else:
                        missing.append(f"Item '{vname}' (no host context) [{ctx}]")

                elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name}, output=["hostid"])
                        if hosts:
                            protos = self.dest.itemprototype.get(
                                filter={"key_": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["itemid"])
                            if protos:
                                cf["value"] = protos[0]["itemid"]
                            else:
                                missing.append(
                                    f"Item prototype '{vname}' on host '{host_name}' [{ctx}]")
                        else:
                            missing.append(
                                f"Host '{host_name}' (for item_proto '{vname}') [{ctx}]")
                    else:
                        missing.append(f"Item prototype '{vname}' (no host context) [{ctx}]")

                elif ftype == FIELD_TYPE_GRAPH:
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name}, output=["hostid"])
                        if hosts:
                            graphs = self.dest.graph.get(
                                filter={"name": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["graphid"])
                            if graphs:
                                cf["value"] = graphs[0]["graphid"]
                            else:
                                missing.append(
                                    f"Graph '{vname}' on host '{host_name}' [{ctx}]")
                        else:
                            missing.append(
                                f"Host '{host_name}' (for graph '{vname}') [{ctx}]")
                    else:
                        graphs = self.dest.graph.get(
                            filter={"name": vname}, output=["graphid"])
                        if graphs:
                            cf["value"] = graphs[0]["graphid"]
                        else:
                            missing.append(f"Graph '{vname}' [{ctx}]")

                elif ftype == FIELD_TYPE_GRAPH_PROTO:
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name}, output=["hostid"])
                        if hosts:
                            protos = self.dest.graphprototype.get(
                                filter={"name": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["graphid"])
                            if protos:
                                cf["value"] = protos[0]["graphid"]
                            else:
                                missing.append(
                                    f"Graph prototype '{vname}' on host '{host_name}' [{ctx}]")
                        else:
                            missing.append(
                                f"Host '{host_name}' (for graph_proto '{vname}') [{ctx}]")
                    else:
                        missing.append(f"Graph prototype '{vname}' (no host context) [{ctx}]")

                elif ftype == FIELD_TYPE_MAP:
                    data = self.dest.map.get(
                        filter={"name": vname}, output=["sysmapid"])
                    if data:
                        cf["value"] = data[0]["sysmapid"]
                    else:
                        missing.append(f"Map '{vname}' [{ctx}]")

            except Exception as exc:
                missing.append(f"{ctx} -- error: {exc}")

            cf.pop("value_name", None)
            cf.pop("host_name",  None)
            converted["fields"].append(cf)

        return converted, missing

    # -----------------------------------------------------------------------
    # Dashboard: create
    # -----------------------------------------------------------------------

    def _create_dashboard(self, dashboard: Dict,
                          owner_userid: str,
                          extra_groups: List[Dict]):
        """Build cleaned payload and create dashboard in destination."""
        name = dashboard["name"]

        clean = {
            "name":           name,
            "userid":         owner_userid,
            "display_period": int(dashboard.get("display_period", 30)),
            "auto_start":     int(dashboard.get("auto_start", 1)),
        }

        # Individual user shares are intentionally not migrated (dropped at
        # resolve_names stage).  Access is granted via group shares only.

        # Merge existing shared groups + groups added for fallback owner
        all_groups = list(dashboard.get("userGroups") or [])
        for eg in extra_groups:
            # Avoid duplicates
            if not any(g.get("usrgrpid") == eg["usrgrpid"] for g in all_groups):
                all_groups.append(eg)
        if all_groups:
            clean["userGroups"] = all_groups

        clean["pages"] = []
        for page in dashboard.get("pages", []):
            clean_page = {
                "name":           page.get("name", ""),
                "display_period": int(page.get("display_period", 0)),
                "widgets":        []
            }
            for widget in page.get("widgets", []):
                # --- Grid scaling (horizontal only, per official docs) ---
                # 6.4: x 0-23, width 1-24   7.0: x 0-35, width 1-36  (x1.5)
                # Vertical unchanged: y 0-62, height 2-32
                src_x = int(widget.get("x", 0))
                src_w = int(widget.get("width", 1))

                x     = round(src_x * GRID_SCALE)
                width = round((src_x + src_w) * GRID_SCALE) - x

                y      = int(widget.get("y", 0))
                height = int(widget.get("height", 2))

                if x + width > 36:
                    width = 36 - x
                width  = max(1, min(width, 36))
                height = max(2, min(height, 32))

                cw = {
                    "type":      widget["type"],
                    "name":      widget.get("name", ""),
                    "x":         x,
                    "y":         y,
                    "width":     width,
                    "height":    height,
                    "view_mode": int(widget.get("view_mode", 0)),
                }
                if widget.get("fields"):
                    cw["fields"] = [
                        f for f in widget["fields"]
                        if not _TAG_FIELD_RE.match(f.get("name", ""))
                    ]
                clean_page["widgets"].append(cw)

            clean["pages"].append(clean_page)

        self.dest.dashboard.create(**clean)
        print(f"    + Created: {name}")

    # -----------------------------------------------------------------------
    # Dashboard: helpers
    # -----------------------------------------------------------------------

    def _dashboard_exists(self, name: str) -> bool:
        return bool(self.dest.dashboard.get(
            filter={"name": name}, output=["dashboardid"]))

    def _delete_dashboard(self, name: str):
        existing = self.dest.dashboard.get(
            filter={"name": name}, output=["dashboardid"])
        if existing:
            self.dest.dashboard.delete(existing[0]["dashboardid"])
            logger.debug("Deleted existing dashboard '%s'", name)

    def _annotate_missing_group(self, group_name: str) -> str:
        """Add diagnostic annotation for a host group missing in destination."""
        try:
            src_grp = self.source.hostgroup.get(
                filter={"name": group_name}, output=["groupid"])
            if not src_grp:
                return " [group also absent from source — possibly deleted]"
            gid = src_grp[0]["groupid"]
            count = int(self.source.host.get(groupids=gid, countOutput=True))
            if count == 0:
                return (
                    " [NOTE: group is EMPTY in source (no hosts)"
                    " -- verify if it should exist in destination]"
                )
            else:
                return (
                    f" [!! UNEXPECTED: group has {count} host(s) in source"
                    " but is MISSING in destination -- please investigate !!]"
                )
        except Exception:
            return " [could not determine source status]"

    def _annotate_missing_host(self, host_name: str) -> str:
        """Add diagnostic annotation for a host missing in destination."""
        try:
            data = self.source.host.get(
                filter={"host": host_name}, output=["status"])
            if not data:
                return " [host also absent from source — possibly deleted]"
            if str(data[0]["status"]) == "1":
                return (
                    " [NOTE: host is DISABLED in source"
                    " -- verify if it should be migrated to destination]"
                )
            else:
                return (
                    " [!! UNEXPECTED: host is ACTIVE in source"
                    " but is MISSING in destination -- please investigate !!]"
                )
        except Exception:
            return " [could not determine source status]"

    # =======================================================================
    # Generic helpers
    # =======================================================================

    def _raw_export(self, object_type: str, ids: List[str],
                    fmt: str = "yaml") -> str:
        """
        Call ``configuration.export`` on the SOURCE (Zabbix 6.4) instance.

        Zabbix 6.4 API — configuration.export
        ──────────────────────────────────────
        params.format   : "yaml" | "json"  (we also accept "xml" but never use it)
        params.options  : dict with ONE of:
            templates     → list of templateids  (str)
            hosts         → list of hostids      (str)
            maps          → list of sysmapids    (str)
            (also valid in 6.4: groups, templateGroups, images, mediaTypes)
        result          : plain string (yaml/json/xml payload)

        Format choice rationale
        ───────────────────────
        yaml   — used for templates and hosts.  Compact, human-readable.
                 PyYAML 1.1 parses bare integers correctly for these objects
                 (no hex-color fields exist in template/host exports).
        json   — used for maps.  PyYAML 1.1 corrupts unquoted 6-digit hex
                 strings: "000000" → int(0), "000066" → int(54).  Zabbix 7.0
                 rejects non-string color values.  JSON preserves them as
                 strings with no ambiguity.

        Arguments
        ─────────
        object_type : "templates" | "hosts" | "maps"
        ids         : list of ID strings (templateid / hostid / sysmapid)
        fmt         : "yaml" (default) or "json"
        """
        import requests as _requests

        token   = self._src_token
        api_url = self._source_url.rstrip("/") + "/api_jsonrpc.php"

        payload = json.dumps(self._sanitize({
            "jsonrpc": "2.0",
            "method":  "configuration.export",
            "id":      1,
            "auth":    token,
            "params":  {
                "format":  fmt,
                "options": {object_type: ids}
            }
        }))

        resp = _requests.post(
            api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise Exception(data["error"].get("data") or data["error"].get("message", str(data["error"])))
        result = data.get("result", "")
        # result is a plain string for both json and yaml formats
        if isinstance(result, str):
            return result
        return json.dumps(result)

    @staticmethod
    def _sanitize(obj):
        """
        Recursively convert any object to plain JSON-safe Python types.
        Handles pyzabbix APIObject regardless of whether it subclasses dict.
        """
        # Primitives — already safe
        if obj is None or isinstance(obj, (bool, int, float, str)):
            return obj
        # Plain dict — recurse into values
        if type(obj) is dict:
            return {str(k): ZabbixMigrator._sanitize(v) for k, v in obj.items()}
        # Plain list/tuple
        if type(obj) in (list, tuple):
            return [ZabbixMigrator._sanitize(i) for i in obj]
        # Dict-like (APIObject, AttrDict, any dict subclass)
        try:
            return {str(k): ZabbixMigrator._sanitize(v) for k, v in obj.items()}
        except (AttributeError, TypeError):
            pass
        # Any iterable
        try:
            return [ZabbixMigrator._sanitize(i) for i in obj]
        except TypeError:
            pass
        # Last resort — stringify
        return str(obj)

    def _raw_import(self, fmt: str, source, rules: Dict):
        """
        Call ``configuration.import`` on the DESTINATION (Zabbix 7.0) instance.

        Zabbix 7.0 API — configuration.import
        ──────────────────────────────────────
        params.format   : "yaml" | "json"  (must match the export format)
        params.source   : the export string from configuration.export
        params.rules    : dict controlling create/update/delete per entity type.

        Rules key naming in 7.0  (differs from 6.4!)
        ─────────────────────────────────────────────
          snake_case  →  host_groups, template_groups
          camelCase   →  templates, hosts, items, triggers, graphs,
                         discoveryRules, templateDashboards, templateLinkage,
                         httptests, valueMaps, maps, images, icon_maps, …

        Version upgrade
        ───────────────
        Zabbix 7.0 automatically upgrades exports from 6.4: the YAML/JSON
        payload carries a ``version: '6.4'`` header which triggers 7.0's
        internal schema-upgrade path.  No manual transformation is required
        except the JSON map-structure patches applied before this call.

        result : true on success; raises on API error
        """
        import requests as _requests

        token   = self._dest_token
        api_url = self._dest_url.rstrip("/") + "/api_jsonrpc.php"

        source_str = source if isinstance(source, str) \
                     else json.dumps(self._sanitize(source))

        payload = {
            "jsonrpc": "2.0",
            "method":  "configuration.import",
            "id":      1,
            "auth":    token,
            "params":  {
                "format": fmt,
                "source": source_str,
                "rules":  rules,
            }
        }

        # --debug-json: walk the entire payload and report any non-serializable type
        if self.debug_json:
            def _find_bad(obj, path="root"):
                try:
                    json.dumps(obj)
                    return          # this branch is fine
                except TypeError:
                    pass
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        _find_bad(v, f"{path}.{k}")
                elif isinstance(obj, (list, tuple)):
                    for i, v in enumerate(obj):
                        _find_bad(v, f"{path}[{i}]")
                else:
                    print(f"  [DEBUG-JSON] Non-serializable at {path}: "
                          f"type={type(obj).__name__!r}  value={repr(obj)[:120]}")

            print("  [DEBUG-JSON] Inspecting payload for non-serializable types...")
            _find_bad(payload)

            dump_path = os.path.join(BASE_DIR, "debug_payload.json")
            try:
                sanitized = self._sanitize(payload)
                with open(dump_path, "w", encoding="utf-8") as _f:
                    json.dump(sanitized, _f, indent=2)
                print(f"  [DEBUG-JSON] Sanitized payload written to: {dump_path}")
            except Exception as _e:
                print(f"  [DEBUG-JSON] Could not write payload: {_e}")

        raw_body = json.dumps(self._sanitize(payload))
        resp = _requests.post(
            api_url,
            data=raw_body,
            headers={"Content-Type": "application/json"},
            timeout=120
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise Exception(
                data["error"].get("data") or
                data["error"].get("message", str(data["error"]))
            )
        return data.get("result", True)

    # =======================================================================
    # 5. USER GROUPS
    # =======================================================================

    def migrate_usergroups(self):
        """
        Migrate user groups from source (6.4) to destination (7.0).

        Algorithm
        ─────────
        1. Fetch every usergroup from source with its host-group rights and
           template-group rights.
        2. Resolve each right's group ID to a group name using bulk lookups
           against the source.
        3. In destination, resolve each group name back to an ID.
        4. Create the usergroup if it does not exist; update it if it does.

        API differences between 6.4 (source) and 7.0 (destination)
        ─────────────────────────────────────────────────────────────
        Source 6.4  selectRights               → rights[]            (host groups)
                    selectTemplateGroupRights   → templategroup_rights[] (tpl groups)

        Dest   7.0  create/update uses:
                    hostgroup_rights[]          (snake_case, replaces 6.4 "rights")
                    templategroup_rights[]      (same name as 6.4 response key)

        Rights permission values are identical in both versions:
          0 = Deny  1 = (none)  2 = Read  3 = Read-Write

        What is NOT migrated
        ────────────────────
        • User membership      — users themselves are not migrated by this script
        • Tag filters          — reference source host/group IDs which differ in dest
        """
        print("  [Usergroups] Fetching usergroups from source...")

        # ── 1. Fetch all source usergroups with rights ─────────────────────────
        try:
            src_groups = self.source.usergroup.get(
                output=["usrgrpid", "name", "gui_access",
                        "users_status", "debug_mode"],
                selectRights="extend",                # host-group rights in 6.4
                selectTemplateGroupRights="extend",   # template-group rights
            )
        except Exception as exc:
            print(f"  [Usergroups] ERROR: could not fetch from source: {exc}")
            self.results["usergroups"]["failed"] += 1
            return

        self.counts["usergroups"]["src_total"] = len(src_groups)
        print(f"  [Usergroups] Found {len(src_groups)} usergroup(s) in source.")

        # ── Optional single-group filter ───────────────────────────────────────
        if self.usergroup_filter:
            src_groups = [g for g in src_groups
                          if g["name"] == self.usergroup_filter]
            if not src_groups:
                print(f"  [Usergroups] Usergroup '{self.usergroup_filter}' "
                      f"not found in source.")
                return
            print(f"  [Usergroups] Filtered to: '{self.usergroup_filter}'.")

        if not src_groups:
            return

        # ── 2. Bulk-resolve group IDs → names in source ────────────────────────
        try:
            src_hg_map = {
                g["groupid"]: g["name"]
                for g in self.source.hostgroup.get(output=["groupid", "name"])
            }
        except Exception as exc:
            print(f"  [Usergroups] WARNING: could not fetch source host groups: {exc}")
            src_hg_map = {}

        try:
            src_tg_map = {
                g["groupid"]: g["name"]
                for g in self.source.templategroup.get(output=["groupid", "name"])
            }
        except Exception as exc:
            print(f"  [Usergroups] WARNING: could not fetch source template groups: {exc}")
            src_tg_map = {}

        # ── 3. Bulk-resolve group names → IDs in destination ──────────────────
        try:
            dst_hg_map = {
                g["name"]: g["groupid"]
                for g in self.dest.hostgroup.get(output=["groupid", "name"])
            }
        except Exception as exc:
            print(f"  [Usergroups] WARNING: could not fetch dest host groups: {exc}")
            dst_hg_map = {}

        try:
            dst_tg_map = {
                g["name"]: g["groupid"]
                for g in self.dest.templategroup.get(output=["groupid", "name"])
            }
        except Exception as exc:
            print(f"  [Usergroups] WARNING: could not fetch dest template groups: {exc}")
            dst_tg_map = {}

        # ── 4. Iterate, resolve, create/update ────────────────────────────────
        # Human-readable permission labels (same values in 6.4 and 7.0)
        _PERM_LABEL = {"0": "Deny", "1": "None", "2": "Read", "3": "Read-Write"}

        ok_count   = 0
        skip_count = 0
        fail_count = 0
        ok_names: List[str] = []

        # Accumulate incomplete rights across all groups for the end-of-run summary.
        # Structure: [(grp_name, "host"|"template", group_name, perm_str), …]
        incomplete_rights: List[tuple] = []

        for grp in src_groups:
            grp_name = grp["name"]

            # --skip-existing: check once, skip if already present
            if self.skip_existing:
                try:
                    if self.dest.usergroup.get(
                            filter={"name": grp_name}, output=["usrgrpid"]):
                        skip_count += 1
                        logger.debug("Usergroup '%s' already exists, skipping.", grp_name)
                        continue
                except Exception as exc:
                    logger.debug("Could not check existence of '%s': %s", grp_name, exc)

            # ── Resolve host-group rights ──────────────────────────────────────
            # 6.4 source returns these under "rights" (selectRights param).
            # 7.0 destination accepts them under "hostgroup_rights".
            dst_hg_rights: List[Dict] = []
            # Each entry: (group_name, perm_label)
            missing_hg: List[tuple] = []

            for right in (grp.get("rights") or []):
                src_id = right["id"]
                perm   = str(right["permission"])
                name   = src_hg_map.get(src_id)
                if not name:
                    logger.debug("Usergroup '%s': unknown source host group id %s",
                                 grp_name, src_id)
                    continue
                dst_id = dst_hg_map.get(name)
                if dst_id:
                    dst_hg_rights.append({"id": dst_id, "permission": perm})
                else:
                    missing_hg.append((name, _PERM_LABEL.get(perm, perm)))

            # ── Resolve template-group rights ──────────────────────────────────
            raw_tg = (grp.get("templategroup_rights")
                      or grp.get("template_group_rights")
                      or [])
            dst_tg_rights: List[Dict] = []
            missing_tg: List[tuple] = []

            for right in raw_tg:
                src_id = right["id"]
                perm   = str(right["permission"])
                name   = src_tg_map.get(src_id)
                if not name:
                    logger.debug("Usergroup '%s': unknown source template group id %s",
                                 grp_name, src_id)
                    continue
                dst_id = dst_tg_map.get(name)
                if dst_id:
                    dst_tg_rights.append({"id": dst_id, "permission": perm})
                else:
                    missing_tg.append((name, _PERM_LABEL.get(perm, perm)))

            # ── Print per-group missing rights immediately ─────────────────────
            if missing_hg:
                print(f"  [Usergroups] '{grp_name}': "
                      f"{len(missing_hg)} host group(s) not in destination — skipped:")
                for gname, plabel in missing_hg:
                    print(f"      - {gname}  [{plabel}]")
                    incomplete_rights.append((grp_name, "host", gname, plabel))

            if missing_tg:
                print(f"  [Usergroups] '{grp_name}': "
                      f"{len(missing_tg)} template group(s) not in destination — skipped:")
                for gname, plabel in missing_tg:
                    print(f"      - {gname}  [{plabel}]")
                    incomplete_rights.append((grp_name, "template", gname, plabel))

            # ── Build 7.0 payload ──────────────────────────────────────────────
            payload = {
                "name":                 grp_name,
                "gui_access":           grp.get("gui_access",   "0"),
                "users_status":         grp.get("users_status", "0"),
                "debug_mode":           grp.get("debug_mode",   "0"),
                "hostgroup_rights":     dst_hg_rights,
                "templategroup_rights": dst_tg_rights,
            }

            # ── Create or update ───────────────────────────────────────────────
            try:
                existing = self.dest.usergroup.get(
                    filter={"name": grp_name}, output=["usrgrpid"])

                if existing:
                    payload["usrgrpid"] = existing[0]["usrgrpid"]
                    self.dest.usergroup.update(**payload)
                    action = "updated"
                else:
                    self.dest.usergroup.create(**payload)
                    action = "created"

                ok_count += 1
                ok_names.append(grp_name)
                logger.debug("Usergroup '%s' %s (hg_rights=%d, tg_rights=%d).",
                             grp_name, action,
                             len(dst_hg_rights), len(dst_tg_rights))

            except Exception as exc:
                fail_count += 1
                reason = str(exc)
                print(f"  [Usergroups] FAIL '{grp_name}': {reason}")
                self.results["usergroups"]["errors"].append(
                    {"name": grp_name, "reason": reason})
                logger.debug("Usergroup '%s' failed: %s", grp_name, reason)

        # ── End-of-run summary of incomplete rights ────────────────────────────
        if incomplete_rights:
            # Group by usergroup name for a clean table
            from collections import defaultdict
            by_grp: Dict[str, List[tuple]] = defaultdict(list)
            for ug_name, kind, gname, plabel in incomplete_rights:
                by_grp[ug_name].append((kind, gname, plabel))

            print(f"\n  [Usergroups] ── Incomplete rights summary "
                  f"({len(incomplete_rights)} right(s) dropped across "
                  f"{len(by_grp)} usergroup(s)) ──")
            for ug_name, entries in by_grp.items():
                print(f"    Usergroup: {ug_name}")
                for kind, gname, plabel in entries:
                    kind_label = "Host group     " if kind == "host" else "Template group "
                    print(f"      {kind_label} not in dest: {gname}  [{plabel}]")
            print()

        # ── Persist results ────────────────────────────────────────────────────
        self.results["usergroups"]["migrated"] += ok_count
        self.results["usergroups"]["skipped"]  += skip_count
        self.results["usergroups"]["failed"]   += fail_count
        self.results["usergroups"]["names"].extend(ok_names)

        try:
            self.counts["usergroups"]["dst_total"] = int(
                self.dest.usergroup.get(countOutput=True))
        except Exception:
            pass

        print(f"  [Usergroups] Done: {ok_count} created/updated, "
              f"{skip_count} skipped, {fail_count} failed.")

    # =======================================================================
    # Utilities
    # =======================================================================

    def _ensure_groups_in_dest(
            self, src_groups: List[Dict], name_key: str,
            getter, creator, label: str):
        """
        Ensure every group from src_groups exists in destination.
        Uses a single bulk fetch of all dest groups instead of one call per group,
        to avoid session timeouts on large group lists.

        getter(name) is still accepted for API compatibility but is NOT called
        in a loop — it is only used as a fallback if the bulk path fails.
        creator(name) -> result
        """
        # ── bulk approach: fetch all dest groups in one call then diff ───────
        try:
            # Derive the dest API object from the creator's closure isn't
            # possible generically, so we call getter once with a sentinel to
            # get the result type, then fall back to the loop if bulk fails.
            # Instead, use the dest api directly via the label heuristic.
            if "template group" in label:
                dest_all = self.dest.templategroup.get(output=["name"])
            elif "host group" in label:
                dest_all = self.dest.hostgroup.get(output=["name"])
            else:
                raise ValueError("unknown label — use per-group fallback")

            dest_names = {g["name"] for g in dest_all}
            missing    = [g[name_key] for g in src_groups
                          if g[name_key] not in dest_names]

            created = 0
            for name in missing:
                try:
                    creator(name)
                    created += 1
                    logger.debug("Created %s '%s' in destination.", label, name)
                except Exception as exc:
                    logger.debug("Could not create %s '%s': %s", label, name, exc)

            if created:
                print(f"    Created {created} missing {label}(s) in destination "
                      f"({len(dest_names)} already existed).")
            return

        except Exception as bulk_exc:
            logger.debug("Bulk group check failed (%s), falling back to per-group: %s",
                         label, bulk_exc)

        # ── per-group fallback (original behaviour) ───────────────────────────
        created = skipped = 0
        for grp in src_groups:
            name = grp[name_key]
            try:
                if not getter(name):
                    creator(name)
                    logger.debug("Created %s '%s' in destination.", label, name)
                    created += 1
                else:
                    skipped += 1
            except Exception as exc:
                logger.debug("Could not ensure %s '%s': %s", label, name, exc)
        if created:
            print(f"    Created {created} missing {label}(s) in destination "
                  f"({skipped} already existed).")

    def _fail(self, migration_type: str, msg: str, exc: Exception):
        """Record a top-level failure for a migration type."""
        full = f"{msg}: {exc}"
        print(f"  [{migration_type.capitalize()}] ERROR: {full}")
        self.results[migration_type]["failed"] += 1
        self.results[migration_type]["errors"].append({"reason": full})

    # =======================================================================
    # Summary
    # =======================================================================

    def print_summary(self, types_run: List[str]):
        """Print per-type statistics to console only. All detail is in the log file."""
        for t in types_run:
            r = self.results[t]
            c = self.counts.get(t, {})

            # Source line
            if t == "hosts":
                src_line = (f"  [{'Source':8}] [{t.capitalize():12}] "
                            f"Total: {c.get('src_total', '?'):5}  "
                            f"Enabled: {c.get('src_enabled', '?'):5}  "
                            f"Disabled: {c.get('src_disabled', '?'):5}")
                dst_line = (f"  [{'Dest':8}] [{t.capitalize():12}] "
                            f"Total: {c.get('dst_total', '?'):5}  "
                            f"Enabled: {c.get('dst_enabled', '?'):5}  "
                            f"Disabled: {c.get('dst_disabled', '?'):5}")
            else:
                src_line = (f"  [{'Source':8}] [{t.capitalize():12}] "
                            f"Total: {c.get('src_total', '?'):5}")
                dst_line = (f"  [{'Dest':8}] [{t.capitalize():12}] "
                            f"Total: {c.get('dst_total', '?'):5}")

            print(src_line)
            print(dst_line)
            print(f"  [{'Migration':8}] [{t.capitalize():12}] "
                  f"Migrated: {r['migrated']:4}  "
                  f"Skipped: {r['skipped']:4}  "
                  f"Failed: {r['failed']:4}")
            print()


# ---------------------------------------------------------------------------
# Migration health-check comparator
# ---------------------------------------------------------------------------

# All valid section keys (used for --compare argument validation)
COMPARE_ALL_SECTIONS = [
    "hosts", "templates", "items", "item-types", "unsup-types",
    "triggers", "discovery-rules", "unsup-items", "unsup-rules",
    "graphs", "host-groups", "maps", "dashboards", "proxies", "user-groups",
]

# Item type IDs that exist in 6.4 but were unified in 7.0
_ITEM_TYPE_NAMES = {
    0:  "Zabbix agent",
    1:  "SNMPv1",           # 6.4 only — maps to type 20 in 7.0
    2:  "Zabbix trapper",
    3:  "Simple check",
    4:  "SNMPv2c",          # 6.4 only — maps to type 20 in 7.0
    5:  "Zabbix internal",
    6:  "SNMPv3",           # 6.4 only — maps to type 20 in 7.0
    7:  "Zabbix agent (active)",
    9:  "Web item",
    10: "External check",
    11: "Database monitor",
    12: "IPMI agent",
    13: "SSH agent",
    14: "Telnet agent",
    15: "Calculated",
    16: "JMX agent",
    17: "SNMP trap",
    18: "Dependent",
    19: "HTTP agent",
    20: "SNMP (unified)",   # 7.0 only — replaces 1+4+6 from 6.4
    21: "Script",
}

# Groups of (src_types, dst_types, label) for cross-version comparison.
# Types 1/4/6 in 6.4 → type 20 in 7.0 (SNMP was split into three, then unified).
_ITEM_TYPE_GROUPS = [
    ((0,),    (0,),   "Zabbix agent"),
    ((1,4,6), (20,),  "SNMP (v1+v2c+v3 → unified)"),
    ((7,),    (7,),   "Zabbix agent (active)"),
    ((2,),    (2,),   "Zabbix trapper"),
    ((17,),   (17,),  "SNMP trap"),
    ((5,),    (5,),   "Zabbix internal"),
    ((3,),    (3,),   "Simple check"),
    ((15,),   (15,),  "Calculated"),
    ((18,),   (18,),  "Dependent"),
    ((19,),   (19,),  "HTTP agent"),
    ((21,),   (21,),  "Script"),
    ((9,),    (9,),   "Web item"),
    ((10,),   (10,),  "External check"),
    ((11,),   (11,),  "Database monitor"),
    ((12,),   (12,),  "IPMI agent"),
    ((13,),   (13,),  "SSH agent"),
    ((14,),   (14,),  "Telnet agent"),
    ((16,),   (16,),  "JMX agent"),
]


class ZabbixComparator:
    """
    Collects monitoring statistics from two Zabbix instances (source 6.4 and
    destination 7.0) and prints a side-by-side comparison to validate that a
    migration is complete.

    Usage:
        comp = ZabbixComparator(src_api, dst_api, cia_name)
        comp.run()                              # all sections
        comp.run(["hosts", "items"])            # selected sections only
    """

    # ── colour helpers for terminal output ──────────────────────────────────
    _RED    = "\033[91m"
    _YEL    = "\033[93m"
    _GRN    = "\033[92m"
    _RST    = "\033[0m"

    def __init__(self, src_api, dst_api, cia_name: str):
        self.src  = src_api
        self.dst  = dst_api
        self.cia  = cia_name
        self._warnings: List[str] = []

    # ── public entry point ───────────────────────────────────────────────────

    def run(self, sections: Optional[List[str]] = None):
        """
        sections: list of section keys from COMPARE_ALL_SECTIONS, or None = all.
        Report sections (unsup-items, unsup-rules) print directly; they have no
        src/dst table.
        """
        if sections is None or sections == []:
            sections = COMPARE_ALL_SECTIONS

        # Normalise: lowercase, strip spaces
        sections = [s.lower().strip() for s in sections]
        unknown = [s for s in sections if s not in COMPARE_ALL_SECTIONS]
        if unknown:
            print(f"  [WARN] Unknown compare section(s): {', '.join(unknown)}")
            print(f"  Valid sections: {', '.join(COMPARE_ALL_SECTIONS)}")
            sections = [s for s in sections if s in COMPARE_ALL_SECTIONS]

        # Master list: (key, display-title, method, kind)
        # kind = "table"  → method returns List[Tuple]; rendered with _print_table
        # kind = "report" → method prints output itself (no src/dst symmetry needed)
        all_sections = [
            ("hosts",           "HOSTS",                          self._section_hosts,                 "table"),
            ("templates",       "TEMPLATES",                      self._section_templates,             "table"),
            ("items",           "ITEMS",                          self._section_items,                 "table"),
            ("item-types",      "ITEM TYPES — enabled",           self._section_item_types,            "table"),
            ("unsup-types",     "ITEM TYPES — unsupported",       self._section_unsupported_item_types,"table"),
            ("triggers",        "TRIGGERS",                       self._section_triggers,              "table"),
            ("discovery-rules", "DISCOVERY RULES",                self._section_discovery_rules,       "table"),
            ("unsup-items",     "TOP UNSUPPORTED ITEMS (by tpl)", self._report_top_unsupported_items,  "report"),
            ("unsup-rules",     "TOP UNSUPPORTED DISC. RULES",    self._report_top_unsupported_rules,  "report"),
            ("graphs",          "GRAPHS (custom)",                self._section_graphs,                "table"),
            ("host-groups",     "HOST GROUPS",                    self._section_host_groups,           "table"),
            ("maps",            "MAPS",                           self._section_maps,                  "table"),
            ("dashboards",      "DASHBOARDS",                     self._section_dashboards,            "table"),
            ("proxies",         "PROXIES",                        self._section_proxies,               "table"),
            ("user-groups",     "USER GROUPS",                    self._section_user_groups,           "table"),
        ]

        print(f"\n{'═' * 74}")
        print(f"  Migration Health Check — CIA: {self.cia}")
        active_keys = ", ".join(sections) if len(sections) < len(COMPARE_ALL_SECTIONS) else "all"
        print(f"  Sections: {active_keys}")
        print(f"{'═' * 74}")

        for key, title, fn, kind in all_sections:
            if key not in sections:
                continue
            print(f"\n  {'─' * 72}")
            print(f"  {title}")
            print(f"  {'─' * 72}")
            try:
                if kind == "table":
                    rows = fn()
                    self._print_table(rows)
                else:
                    fn()   # prints directly
            except Exception as exc:
                import traceback
                print(f"  [ERROR in {title}: {exc}]")
                print(traceback.format_exc())

        if self._warnings:
            print(f"\n  {'═' * 72}")
            print(f"  ⚠  DISCREPANCIES  ({len(self._warnings)} found)")
            print(f"  {'═' * 72}")
            for w in self._warnings:
                print(f"  {self._YEL}!{self._RST}  {w}")

        print(f"\n{'═' * 74}")

    # ── table rendering ──────────────────────────────────────────────────────

    def _print_table(self, rows: List[Tuple]):
        """
        rows: list of (label, src_val, dst_val) or (label,) for separators.
        Negative diff is always red + added to warnings.
        Positive diff is yellow (informational; may be expected).
        """
        COL_LBL = 46
        COL_VAL = 9

        hdr = (f"  {'Metric':<{COL_LBL}}  "
               f"{'Source':>{COL_VAL}}  {'Dest':>{COL_VAL}}  {'Diff':>{COL_VAL}}")
        print(hdr)
        print(f"  {'·' * (COL_LBL + COL_VAL * 3 + 8)}")

        for row in rows:
            if len(row) == 1:
                print(f"  {row[0]}")
                continue

            label, src_v, dst_v = row

            if isinstance(src_v, int) and isinstance(dst_v, int):
                diff = dst_v - src_v
                if diff == 0:
                    diff_str = f"{'=':>{COL_VAL}}"
                    colour   = self._GRN
                elif diff > 0:
                    diff_str = f"{'+' + str(diff):>{COL_VAL}}"
                    colour   = self._YEL
                else:
                    diff_str = f"{str(diff):>{COL_VAL}}"
                    colour   = self._RED
                    self._warnings.append(f"{label}: src={src_v} dst={dst_v} (Δ{diff})")
                print(f"  {label:<{COL_LBL}}  {src_v:>{COL_VAL}}  {dst_v:>{COL_VAL}}  "
                      f"{colour}{diff_str}{self._RST}")
            else:
                match = "=" if str(src_v) == str(dst_v) else "≠"
                print(f"  {label:<{COL_LBL}}  {str(src_v):>{COL_VAL}}  {str(dst_v):>{COL_VAL}}  "
                      f"  {match}")

    # ── stat-collection helpers ──────────────────────────────────────────────

    def _cnt(self, api, method: str, **kwargs) -> int:
        """Call <method> with countOutput=True and return the integer result."""
        fn = api
        for part in method.split("."):
            fn = getattr(fn, part)
        result = fn(countOutput=True, **kwargs)
        return int(result)

    @staticmethod
    def _build_transitively_used_templates(api) -> set:
        """
        Return the set of templateids that are 'in use', defined as:
          - directly linked to ≥1 regular host (flags=0), OR
          - are an ancestor (parent/grandparent/…) of any such template.

        This avoids counting nested/shared parent templates as orphans simply
        because no host links to them directly.
        """
        # Fetch all templates with their parent template links
        all_tpls = api.template.get(
            output=["templateid"],
            selectParentTemplates=["templateid"]
        )
        # Map: templateid → list of parent templateids (templates it inherits from)
        tpl_parents: Dict[str, List[str]] = {
            t["templateid"]: [p["templateid"] for p in t.get("parentTemplates", [])]
            for t in all_tpls
        }

        # Seed: templates that are directly linked to at least one regular host
        linked_tpls = api.template.get(
            output=["templateid"],
            filter={},
            real_hosts=True          # only templates used by real hosts
        )
        used: set = {t["templateid"] for t in linked_tpls}

        # Walk upward: if template T is used, all its parents are also used
        queue = list(used)
        while queue:
            tid = queue.pop()
            for parent_id in tpl_parents.get(tid, []):
                if parent_id not in used:
                    used.add(parent_id)
                    queue.append(parent_id)

        return used

    # ── individual sections ──────────────────────────────────────────────────

    def _section_hosts(self) -> List[Tuple]:
        """
        Counts regular hosts (flags=0) only.
        Direct/proxy split:
          - Source (6.4): proxyid=0 means no proxy
          - Dest   (7.0): proxyid=0 AND proxy_groupid=0 means truly server-direct
            (Zabbix 7.0 introduced proxy groups; hosts in a proxy group have
             proxyid=0 but proxy_groupid≠0 — they'd be wrongly counted as "direct"
             if we only filter on proxyid)
        """
        s_en  = self._cnt(self.src, "host.get", filter={"status": "0", "flags": "0"})
        d_en  = self._cnt(self.dst, "host.get", filter={"status": "0", "flags": "0"})
        s_dis = self._cnt(self.src, "host.get", filter={"status": "1", "flags": "0"})
        d_dis = self._cnt(self.dst, "host.get", filter={"status": "1", "flags": "0"})

        s_wtpl = self._cnt(self.src, "host.get",
                           filter={"status": "0", "flags": "0"}, templated_hosts=True)
        d_wtpl = self._cnt(self.dst, "host.get",
                           filter={"status": "0", "flags": "0"}, templated_hosts=True)
        s_lld  = self._cnt(self.src, "host.get", filter={"flags": "4"})
        d_lld  = self._cnt(self.dst, "host.get", filter={"flags": "4"})

        rows = [
            ("Total (enabled)",                    s_en,             d_en),
            ("Total (disabled)",                   s_dis,            d_dis),
            ("  ↳ Enabled — with template(s)",     s_wtpl,           d_wtpl),
            ("  ↳ Enabled — no templates",         max(0,s_en-s_wtpl), max(0,d_en-d_wtpl)),
            ("Discovered by LLD (not migrated)",   s_lld,            d_lld),
        ]

        # Proxy breakdown
        try:
            src_proxy_ids = [p["proxyid"]
                             for p in self.src.proxy.get(output=["proxyid"])]
            s_proxy = (self._cnt(self.src, "host.get",
                                 filter={"status": "0", "flags": "0"},
                                 proxyids=src_proxy_ids)
                       if src_proxy_ids else 0)

            dst_proxy_ids = [p["proxyid"]
                             for p in self.dst.proxy.get(output=["proxyid"])]
            d_proxy = (self._cnt(self.dst, "host.get",
                                 filter={"status": "0", "flags": "0"},
                                 proxyids=dst_proxy_ids)
                       if dst_proxy_ids else 0)

            # Source 6.4: direct = proxyid=0
            s_direct = self._cnt(self.src, "host.get",
                                 filter={"status": "0", "flags": "0", "proxyid": "0"})
            # Dest 7.0: direct = proxyid=0 AND proxy_groupid=0
            # (proxy_groupid field exists only in 7.0; ignored on 6.4 side)
            try:
                d_direct = self._cnt(self.dst, "host.get",
                                     filter={"status": "0", "flags": "0",
                                             "proxyid": "0", "proxy_groupid": "0"})
            except Exception:
                d_direct = s_en - d_proxy  # fallback

            rows += [
                ("  ↳ Enabled — monitored via proxy",   s_proxy,  d_proxy),
                ("  ↳ Enabled — direct (server only)",  s_direct, d_direct),
            ]
        except Exception:
            pass  # proxy info is informational; don't fail the whole section

        return rows

    def _section_templates(self) -> List[Tuple]:
        s_total = self._cnt(self.src, "template.get")
        d_total = self._cnt(self.dst, "template.get")

        # "In use" = linked to host directly OR as an ancestor of a linked template
        s_used  = self._build_transitively_used_templates(self.src)
        d_used  = self._build_transitively_used_templates(self.dst)

        s_linked_direct = self._cnt(self.src, "template.get", real_hosts=True)
        d_linked_direct = self._cnt(self.dst, "template.get", real_hosts=True)

        s_used_cnt   = len(s_used)
        d_used_cnt   = len(d_used)
        s_orphan_cnt = s_total - s_used_cnt
        d_orphan_cnt = d_total - d_used_cnt

        return [
            ("Total",                                  s_total,         d_total),
            ("  ↳ Directly linked to ≥1 host",        s_linked_direct, d_linked_direct),
            ("  ↳ Used (direct + nested ancestors)",   s_used_cnt,      d_used_cnt),
            ("  ↳ True orphan (not used anywhere)",    s_orphan_cnt,    d_orphan_cnt),
        ]

    def _section_items(self) -> List[Tuple]:
        """Regular items (flags=0) on non-LLD hosts."""
        base = dict(host_flags=["0"])
        s_en  = self._cnt(self.src, "item.get", filter={"status":"0","flags":"0"}, **base)
        d_en  = self._cnt(self.dst, "item.get", filter={"status":"0","flags":"0"}, **base)
        s_dis = self._cnt(self.src, "item.get", filter={"status":"1","flags":"0"}, **base)
        d_dis = self._cnt(self.dst, "item.get", filter={"status":"1","flags":"0"}, **base)
        s_uns = self._cnt(self.src, "item.get",
                          filter={"status":"0","flags":"0","state":"1"}, **base)
        d_uns = self._cnt(self.dst, "item.get",
                          filter={"status":"0","flags":"0","state":"1"}, **base)
        s_lld = self._cnt(self.src, "item.get", filter={"flags":"4"}, **base)
        d_lld = self._cnt(self.dst, "item.get", filter={"flags":"4"}, **base)
        s_tpl = self._cnt(self.src, "item.get",
                          filter={"status":"0","flags":"0"}, templated=True, **base)
        d_tpl = self._cnt(self.dst, "item.get",
                          filter={"status":"0","flags":"0"}, templated=True, **base)
        return [
            ("Regular items — enabled",             s_en,           d_en),
            ("Regular items — disabled",            s_dis,          d_dis),
            ("  ↳ Enabled — unsupported",           s_uns,          d_uns),
            ("  ↳ Enabled — from templates",        s_tpl,          d_tpl),
            ("  ↳ Enabled — direct (no template)",  s_en - s_tpl,   d_en - d_tpl),
            ("LLD-discovered items (all states)",   s_lld,          d_lld),
        ]

    def _section_item_types(self) -> List[Tuple]:
        """Break down ENABLED regular items by monitoring type."""
        rows = [("  (enabled regular items, non-LLD hosts)",)]
        for src_types, dst_types, label in _ITEM_TYPE_GROUPS:
            try:
                s_cnt = sum(
                    self._cnt(self.src, "item.get",
                              filter={"status":"0","flags":"0","type":str(t)},
                              host_flags=["0"])
                    for t in src_types
                )
                d_cnt = sum(
                    self._cnt(self.dst, "item.get",
                              filter={"status":"0","flags":"0","type":str(t)},
                              host_flags=["0"])
                    for t in dst_types
                )
                if s_cnt > 0 or d_cnt > 0:
                    rows.append((f"  {label}", s_cnt, d_cnt))
            except Exception:
                rows.append((f"  {label}", "?", "?"))
        return rows

    def _section_unsupported_item_types(self) -> List[Tuple]:
        """Break down UNSUPPORTED items (state=1) by monitoring type."""
        rows = [("  (unsupported items, non-LLD hosts)",)]
        for src_types, dst_types, label in _ITEM_TYPE_GROUPS:
            try:
                s_cnt = sum(
                    self._cnt(self.src, "item.get",
                              filter={"status":"0","flags":"0","state":"1","type":str(t)},
                              host_flags=["0"])
                    for t in src_types
                )
                d_cnt = sum(
                    self._cnt(self.dst, "item.get",
                              filter={"status":"0","flags":"0","state":"1","type":str(t)},
                              host_flags=["0"])
                    for t in dst_types
                )
                if s_cnt > 0 or d_cnt > 0:
                    rows.append((f"  {label}", s_cnt, d_cnt))
            except Exception:
                rows.append((f"  {label}", "?", "?"))
        return rows

    def _section_triggers(self) -> List[Tuple]:
        s_en   = self._cnt(self.src, "trigger.get",
                           filter={"status":"0","flags":"0"}, only_true=False)
        d_en   = self._cnt(self.dst, "trigger.get",
                           filter={"status":"0","flags":"0"}, only_true=False)
        s_dis  = self._cnt(self.src, "trigger.get",
                           filter={"status":"1","flags":"0"}, only_true=False)
        d_dis  = self._cnt(self.dst, "trigger.get",
                           filter={"status":"1","flags":"0"}, only_true=False)
        s_prob = self._cnt(self.src, "trigger.get",
                           filter={"status":"0","value":"1","flags":"0"}, only_true=False)
        d_prob = self._cnt(self.dst, "trigger.get",
                           filter={"status":"0","value":"1","flags":"0"}, only_true=False)
        s_lld  = self._cnt(self.src, "trigger.get",
                           filter={"flags":"4"}, only_true=False)
        d_lld  = self._cnt(self.dst, "trigger.get",
                           filter={"flags":"4"}, only_true=False)
        return [
            ("Enabled (regular)",         s_en,   d_en),
            ("Disabled (regular)",        s_dis,  d_dis),
            ("  ↳ Currently in PROBLEM",  s_prob, d_prob),
            ("LLD-discovered triggers",   s_lld,  d_lld),
        ]

    def _section_discovery_rules(self) -> List[Tuple]:
        s_en  = self._cnt(self.src, "discoveryrule.get", filter={"status":"0"})
        d_en  = self._cnt(self.dst, "discoveryrule.get", filter={"status":"0"})
        s_dis = self._cnt(self.src, "discoveryrule.get", filter={"status":"1"})
        d_dis = self._cnt(self.dst, "discoveryrule.get", filter={"status":"1"})
        s_uns = self._cnt(self.src, "discoveryrule.get",
                          filter={"status":"0","state":"1"})
        d_uns = self._cnt(self.dst, "discoveryrule.get",
                          filter={"status":"0","state":"1"})
        return [
            ("Enabled",                   s_en,  d_en),
            ("Disabled",                  s_dis, d_dis),
            ("  ↳ Enabled — unsupported", s_uns, d_uns),
        ]

    def _section_graphs(self) -> List[Tuple]:
        s_tot = self._cnt(self.src, "graph.get", filter={"flags":"0"})
        d_tot = self._cnt(self.dst, "graph.get", filter={"flags":"0"})
        return [("Custom graphs (flags=0)", s_tot, d_tot)]

    def _section_host_groups(self) -> List[Tuple]:
        s_tot  = self._cnt(self.src, "hostgroup.get", real_hosts=True)
        d_tot  = self._cnt(self.dst, "hostgroup.get", real_hosts=True)
        src_grps = self.src.hostgroup.get(output=["groupid"], real_hosts=True)
        dst_grps = self.dst.hostgroup.get(output=["groupid"], real_hosts=True)
        s_nonempty = sum(
            1 for g in src_grps
            if int(self.src.host.get(countOutput=True, groupids=g["groupid"],
                                     filter={"status":"0","flags":"0"})) > 0
        )
        d_nonempty = sum(
            1 for g in dst_grps
            if int(self.dst.host.get(countOutput=True, groupids=g["groupid"],
                                     filter={"status":"0","flags":"0"})) > 0
        )
        return [
            ("Total (real-host groups)", s_tot,              d_tot),
            ("  ↳ Non-empty",           s_nonempty,         d_nonempty),
            ("  ↳ Empty",               s_tot-s_nonempty,   d_tot-d_nonempty),
        ]

    def _section_maps(self) -> List[Tuple]:
        return [("Total", self._cnt(self.src,"map.get"), self._cnt(self.dst,"map.get"))]

    def _section_dashboards(self) -> List[Tuple]:
        return [("Total", self._cnt(self.src,"dashboard.get"), self._cnt(self.dst,"dashboard.get"))]

    def _section_proxies(self) -> List[Tuple]:
        try:
            s_act = self._cnt(self.src, "proxy.get", filter={"status":"5"})
            s_pas = self._cnt(self.src, "proxy.get", filter={"status":"6"})
        except Exception:
            s_act = self._cnt(self.src, "proxy.get"); s_pas = 0
        try:
            d_act = self._cnt(self.dst, "proxy.get", filter={"operating_mode":"0"})
            d_pas = self._cnt(self.dst, "proxy.get", filter={"operating_mode":"1"})
        except Exception:
            d_act = self._cnt(self.dst, "proxy.get"); d_pas = 0
        return [("Active proxies", s_act, d_act), ("Passive proxies", s_pas, d_pas)]

    def _section_user_groups(self) -> List[Tuple]:
        return [("Total", self._cnt(self.src,"usergroup.get"),
                          self._cnt(self.dst,"usergroup.get"))]

    # ── report sections (print directly, no src/dst table) ──────────────────

    def _report_top_unsupported(self, fetch_fn_name: str,
                                 label_singular: str,
                                 top_n: int = 5):
        """
        Generic top-N unsupported object report, shown for both src and dst.
        fetch_fn_name: 'item.get' or 'discoveryrule.get'
        """
        from collections import Counter

        COL_T = 52
        COL_C = 7

        for tag, api in [("Source", self.src), ("Dest  ", self.dst)]:
            fn = api
            for part in fetch_fn_name.split("."):
                fn = getattr(fn, part)

            if fetch_fn_name == "item.get":
                objects = fn(
                    output=["name", "templateid"],
                    filter={"status": "0", "flags": "0", "state": "1"},
                    host_flags=["0"],
                    limit=50000
                )
            else:  # discoveryrule.get
                objects = fn(
                    output=["name", "templateid"],
                    filter={"status": "0", "state": "1"},
                    limit=50000
                )

            total = len(objects)
            if total == 0:
                print(f"\n  [{tag}]  No unsupported {label_singular}s found.")
                continue

            counts: "Counter[str]" = Counter()
            direct_cnt = 0
            for obj in objects:
                tid = obj.get("templateid", "0") or "0"
                if tid != "0":
                    counts[tid] += 1
                else:
                    direct_cnt += 1

            # Resolve template names for top N
            top_n_list = counts.most_common(top_n)
            tids        = [t[0] for t, _ in [(x, None) for x in top_n_list]]
            # Fix: most_common returns (key, count) tuples
            top_n_list  = counts.most_common(top_n)
            tids        = [tid for tid, _ in top_n_list]
            tpl_names   = {}
            if tids:
                tpl_data = api.template.get(output=["name"], templateids=tids)
                tpl_names = {t["templateid"]: t["name"] for t in tpl_data}

            print(f"\n  [{tag}]  Total unsupported {label_singular}s: {total}"
                  f"  (from templates: {total - direct_cnt}, direct: {direct_cnt})")
            print(f"  {'─' * (COL_T + COL_C + 6)}")
            print(f"  {'Template':<{COL_T}}  {'Count':>{COL_C}}")
            print(f"  {'·' * (COL_T + COL_C + 4)}")
            for tid, cnt in top_n_list:
                tname = tpl_names.get(tid, f"<templateid {tid}>")
                # Truncate long template names
                if len(tname) > COL_T - 2:
                    tname = tname[:COL_T - 5] + "..."
                print(f"  {tname:<{COL_T}}  {cnt:>{COL_C}}")
            if direct_cnt > 0:
                print(f"  {'(direct — no template)':<{COL_T}}  {direct_cnt:>{COL_C}}")

            # Bonus: also show the top 5 most-common item/rule *names* (what is broken)
            name_counts: "Counter[str]" = Counter(
                obj["name"] for obj in objects
                if (obj.get("templateid") or "0") != "0"
            )
            top_names = name_counts.most_common(top_n)
            if top_names:
                print(f"\n  [{tag}]  Most common unsupported {label_singular} names:")
                print(f"  {'·' * (COL_T + COL_C + 4)}")
                for name, cnt in top_names:
                    if len(name) > COL_T - 2:
                        name = name[:COL_T - 5] + "..."
                    print(f"  {name:<{COL_T}}  {cnt:>{COL_C}}")

    def _report_top_unsupported_items(self):
        self._report_top_unsupported("item.get", "item")

    def _report_top_unsupported_rules(self):
        self._report_top_unsupported("discoveryrule.get", "discovery rule")


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class MissingObjectsError(Exception):
    def __init__(self, missing_objects: List[str]):
        self.missing_objects = missing_objects
        super().__init__(f"Missing {len(missing_objects)} objects")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_migrate_types(raw: List[str]) -> List[str]:
    """Expand 'all' and deduplicate while preserving MIGRATION_ORDER."""
    expanded = set()
    for item in raw:
        if item == "all":
            expanded.update(MIGRATION_ORDER)
        else:
            expanded.add(item)
    return [t for t in MIGRATION_ORDER if t in expanded]


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Zabbix objects from 6.4 to 7.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Migration order when 'all' is selected:
  1. templates  2. hosts  3. maps  4. dashboards

Examples:
  # Pull latest code from Bitbucket (standalone)
  python zabbix_migration_70.py --pull-repository

  # Pull then immediately run a full migration
  python zabbix_migration_70.py --pull-repository --env ppr --cia biz01 --migrate all

  # Migrate everything for one CIA
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate all

  # Migrate only templates and hosts
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate templates hosts

  # Migrate dashboards for all CIAs, skip existing ones
  python zabbix_migration_70.py --env prd --cia all --migrate dashboards --skip-existing

  # Migrate a specific dashboard by name
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate dashboards \\
      --dashboard "CVS UAT Monitoring"

  # Full migration with debug output
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate all --debug

  # Health-check only: compare source vs destination stats (no migration)
  python zabbix_migration_70.py --env ppr --cia biz01 --compare

  # Migrate everything then immediately run the health-check
  python zabbix_migration_70.py --env ppr --cia biz01 --migrate all --compare

Config files (same directory as this script):
  zabbix_credential.yml          username / password
  zabbix_instances_ppr.yml       CIA source/destination URLs for PPR
  zabbix_instances_prd.yml       CIA source/destination URLs for PRD
  ../projects_branch.yml         repo name + branch for --pull-repository
        """
    )
    parser.add_argument(
        "--pull-repository", nargs="?", const="", metavar="PROJECT_NAME",
        help=(
            "Pull latest code from Bitbucket before running. "
            "Optionally pass the project name (e.g. --pull-repository zabbix-python-scripts); "
            "if omitted, the current folder name is used. "
            "Branch is read from projects_branch.yml found by walking up from the script dir. "
            "Can be used standalone or combined with --env / --cia / --migrate."
        )
    )
    parser.add_argument(
        "--env", default=None, choices=["ppr", "prd"],
        help="Target environment (ppr or prd) — required when --migrate is used"
    )
    parser.add_argument(
        "--cia", default=None,
        help="CIA name (e.g. biz01) or 'all' — required when --migrate is used"
    )
    parser.add_argument(
        "--migrate", default=None, nargs="+",
        choices=["templates", "hosts", "maps", "dashboards", "usergroups", "all"],
        metavar="TYPE",
        help="Object type(s) to migrate: templates hosts maps dashboards usergroups all"
    )
    parser.add_argument(
        "--dashboard", default=None, metavar="NAME",
        help="(dashboards only) Migrate a single dashboard by exact name"
    )
    parser.add_argument(
        "--host", default=None, metavar="NAME",
        help="(hosts only) Migrate a single host by exact name"
    )
    parser.add_argument(
        "--usergroup", default=None, metavar="NAME",
        help="(usergroups only) Migrate a single user group by exact name"
    )
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="Skip objects that already exist in destination (applies to all types)"
    )
    parser.add_argument(
        "--compare", nargs="*", default=None,
        metavar="SECTION",
        help=(
            "Run a migration health-check comparing source vs destination stats. "
            "Pass no value for all sections, or specify one or more section names. "
            f"Available: {', '.join(COMPARE_ALL_SECTIONS)}.  "
            "Examples: --compare   OR   --compare hosts items unsup-items"
        )
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--debug-json", action="store_true",
        help=(
            "Dump the raw JSON payload sent to the API into debug_payload.json "
            "before each import call — useful to diagnose serialization errors"
        )
    )
    args = parser.parse_args()

    # Logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    # ── --pull-repository ────────────────────────────────────────────────────
    if args.pull_repository is not None:
        print("\n" + "=" * 70)
        print("  Git Pull")
        print("=" * 70)
        ok = pull_repository(repo_name=args.pull_repository or None)
        print("=" * 70)
        if not ok:
            sys.exit(1)
        if not args.migrate:
            sys.exit(0)

    # ── Validate migration/compare args ─────────────────────────────────────
    if args.migrate or args.compare is not None:
        missing = []
        if not args.env:
            missing.append("--env")
        if not args.cia:
            missing.append("--cia")
        if missing:
            print(
                f"ERROR: {' and '.join(missing)} "
                f"{'is' if len(missing) == 1 else 'are'} required when --migrate or --compare is used.",
                file=sys.stderr
            )
            sys.exit(1)
    else:
        # Neither --pull-repository nor --migrate nor --compare was given
        if args.pull_repository is None:
            parser.print_help()
            sys.exit(1)
        sys.exit(0)

    # Determine which migration types to run (in canonical order)
    types_to_run = parse_migrate_types(args.migrate) if args.migrate else []
    if args.migrate and not types_to_run:
        print("ERROR: no valid migration types specified.", file=sys.stderr)
        sys.exit(1)

    # Load config
    try:
        creds = load_credentials()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        config = load_instances(args.env)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    cia_map: Dict = config["cia"]

    if args.cia == "all":
        cia_names = list(cia_map.keys())
    else:
        if args.cia not in cia_map:
            print(
                f"ERROR: CIA '{args.cia}' not found. "
                f"Available: {', '.join(cia_map.keys())}",
                file=sys.stderr
            )
            sys.exit(1)
        cia_names = [args.cia]

    # Header
    print("\n" + "=" * 70)
    print(f"  Zabbix Migration 6.4 -> 7.0")
    print(f"  env={args.env}  cia={args.cia}", end="")
    if types_to_run:
        print(f"  migrate={' '.join(types_to_run)}", end="")
    if args.compare is not None:
        sections_disp = ", ".join(args.compare) if args.compare else "all"
        print(f"  compare={sections_disp}", end="")
    print()
    if args.dashboard:
        print(f"  dashboard filter='{args.dashboard}'")
    if args.host:
        print(f"  host filter='{args.host}'")
    if args.usergroup:
        print(f"  usergroup filter='{args.usergroup}'")
    if args.skip_existing:
        print("  mode=skip-existing")
    print("=" * 70)

    # Global totals
    global_results: Dict[str, Dict] = {
        t: {"migrated": 0, "skipped": 0, "failed": 0}
        for t in MIGRATION_ORDER
    }
    global_counts: Dict[str, Dict] = {t: {} for t in MIGRATION_ORDER}

    mlog = MigrationLog(
        env=args.env,
        cia=args.cia,
        types_run=types_to_run,
        dashboard_filter=args.dashboard,
    )

    for cia_name in cia_names:
        cfg        = cia_map[cia_name]
        source_url = cfg["url_export"]
        dest_url   = cfg["url_import"]

        print(f"\n{'─' * 70}")
        print(f"  CIA   : {cia_name}")
        print(f"  Source: {source_url}")
        print(f"  Dest  : {dest_url}")
        print(f"{'─' * 70}")

        migrator = None
        try:
            migrator = ZabbixMigrator(
                source_url=source_url,
                dest_url=dest_url,
                username=creds["username"],
                password=creds["password"],
                cia_name=cia_name,
                skip_existing=args.skip_existing,
                dashboard_filter=args.dashboard,
                host_filter=args.host,
                usergroup_filter=args.usergroup,
                debug_json=args.debug_json,
            )

            for mtype in types_to_run:
                print(f"\n  -- {mtype.upper()} --")
                if mtype == "templates":
                    migrator.migrate_templates()
                elif mtype == "hosts":
                    migrator.migrate_hosts()
                elif mtype == "maps":
                    migrator.migrate_maps()
                elif mtype == "dashboards":
                    migrator.migrate_dashboards()
                elif mtype == "usergroups":
                    migrator.migrate_usergroups()

            # Run comparison after migration (or standalone when no --migrate given)
            if args.compare is not None:
                comp = ZabbixComparator(
                    src_api=migrator.source,
                    dst_api=migrator.dest,
                    cia_name=cia_name,
                )
                # args.compare == [] means --compare with no args → all sections
                # args.compare == ["hosts", ...] → selected sections only
                comp.run(sections=args.compare if args.compare else None)

        except Exception as exc:
            print(f"  FATAL for CIA '{cia_name}': {exc}", file=sys.stderr)
            for t in types_to_run:
                global_results[t]["failed"] += 1

        finally:
            if migrator:
                print(f"\n  Summary for CIA '{cia_name}':")
                migrator.print_summary(types_to_run)
                mlog.section(cia_name, migrator)
                for t in types_to_run:
                    for k in ("migrated", "skipped", "failed"):
                        global_results[t][k] += migrator.results[t][k]
                    # Aggregate source/dest counts (sum totals across CIAs)
                    for k, v in migrator.counts.get(t, {}).items():
                        if isinstance(v, int) and v >= 0:
                            global_counts[t][k] = global_counts[t].get(k, 0) + v
                migrator.logout()

    # Global migration summary — only if migration was actually run
    if types_to_run:
        print("\n" + "=" * 70)
        print("  Global Summary")
        print("=" * 70)
        for t in types_to_run:
            r  = global_results[t]
            gc = global_counts[t]
            if t == "hosts":
                print(f"  [Source   ] [{t.capitalize():12}] "
                      f"Total: {gc.get('src_total','?'):5}  "
                      f"Enabled: {gc.get('src_enabled','?'):5}  "
                      f"Disabled: {gc.get('src_disabled','?'):5}")
                print(f"  [Dest     ] [{t.capitalize():12}] "
                      f"Total: {gc.get('dst_total','?'):5}  "
                      f"Enabled: {gc.get('dst_enabled','?'):5}  "
                      f"Disabled: {gc.get('dst_disabled','?'):5}")
            else:
                print(f"  [Source   ] [{t.capitalize():12}] "
                      f"Total: {gc.get('src_total','?'):5}")
                print(f"  [Dest     ] [{t.capitalize():12}] "
                      f"Total: {gc.get('dst_total','?'):5}")
            print(f"  [Migration] [{t.capitalize():12}] "
                  f"Migrated: {r['migrated']:4}  "
                  f"Skipped: {r['skipped']:4}  "
                  f"Failed: {r['failed']:4}")
            print()
        print("=" * 70)

    # Always flush full detail to log file
    if types_to_run:
        mlog.write(global_results)


if __name__ == "__main__":
    main()
