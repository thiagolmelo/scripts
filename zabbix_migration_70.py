#!/usr/bin/env python3
# Version history at bottom of file — search SCRIPT_VERSION
"""
zabbix_migration_70.py
Migrates objects from Zabbix 6.4 to Zabbix 7.0.

Supported object types (migration order):
  0. regexps    - global regular expressions (Administration > General > Regex)
  Note: usergroups must be run explicitly — not included in 'all'.
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

# All Zabbix/pilalerte endpoints sit behind an internal CA — verify=False is
# used throughout this script, so silence the resulting per-request warning.
try:
    import requests as _requests_for_warnings
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    _requests_for_warnings.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

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

# ---------------------------------------------------------------------------
# Script version — bump this on every change so the printed header makes it
# easy to confirm which build is actually running.
# Format: YYYY-MM-DD.N  (N = patch number within the day)
# ---------------------------------------------------------------------------
SCRIPT_VERSION = "2026-07-02.1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Canonical order for all object types
MIGRATION_ORDER = ["regexps", "templates", "hosts", "maps", "dashboards", "usergroups"]
# Types included when --migrate all is used (usergroups excluded — run explicitly)
MIGRATION_ALL   = ["regexps", "templates", "hosts", "maps", "dashboards"]

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

# Zabbix 6.4 tag filter fields use format:  tags.tag.N / tags.operator.N / tags.value.N
# Zabbix 7.0 uses the reversed format:       tags.N.tag  / tags.N.operator  / tags.N.value
# We transform the name on the fly instead of stripping the field.
_TAG_FIELD_RE = re.compile(r'^tags\.(tag|operator|value)\.(\d+)$')

# Zabbix 6.4 itemvalue threshold fields:  thresholds.color.N / thresholds.threshold.N
# Zabbix 7.0 reversed format:             thresholds.N.color / thresholds.N.threshold
# Same index-reversal pattern as tags.*.
_THRESHOLD_FIELD_RE = re.compile(r'^thresholds\.(color|threshold)\.(\d+)$')

# Zabbix 6.4 svggraph / override field format: ds.PROP.DS.ITEM  or  ds.PROP.DS
# Zabbix 7.0 format:                           ds.DS.PROP.ITEM  or  ds.DS.PROP
# Same restructuring applies to override (or.*) fields.
# svggraph/graph dataset and override fields changed structure between 6.4 and 7.0:
# 6.4: ds.FIELD.N         → 7.0: ds.N.FIELD
# 6.4: ds.FIELD.N.M       → 7.0: ds.N.FIELD.M
# 6.4: or.FIELD.N         → 7.0: or.N.FIELD
# 6.4: or.FIELD.N.M       → 7.0: or.N.FIELD.M
# Regex captures: prefix(ds|or) . field . dataset_idx [. item_idx]
_DS_OR_FIELD_RE = re.compile(r'^(ds|or)\.([^.]+)\.(\d+)(?:\.(.+))?$')

# svggraph/graph widget fields that in 6.4 were stored as type 3 (HOST ID)
# but in 7.0 expect type 1 (STRING — hostname or pattern).
# When resolving names→IDs for these fields we convert the type and send the
# hostname string directly instead of looking up the destination hostid.
_HOST_AS_STRING_RE = re.compile(
    r'^(ds\.\d+\.hosts\.\d+|or\.\d+\.hosts\.\d+|problemhosts\.\d+)$'
)

# Grid: 6.4 = 24 cols (max_columns=24), 7.0 = 72 cols (max_columns=72).
# Scale factor = 72/24 = 3.0  (horizontal only; vertical is identical).
GRID_SCALE = 3.0

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
    "host_groups":     {"createMissing": True,  "updateExisting": False},
    # ── host skeleton + template linkage ────────────────────────────────────
    # Full import: host shell (interfaces, groups, macros, inventory),
    # template linkage, AND locally-created objects (items, triggers, graphs,
    # discovery rules, web scenarios).
    # createMissing=True / updateExisting=False → create only, never overwrite.
    # Re-runs are safe: existing objects are skipped, new ones are added.
    "hosts":           {"createMissing": True,  "updateExisting": True},
    "templateLinkage": {"createMissing": True,  "deleteMissing": False},
    "items":           {"createMissing": True,  "updateExisting": False, "deleteMissing": False},
    "triggers":        {"createMissing": True,  "updateExisting": False, "deleteMissing": False},
    "graphs":          {"createMissing": True,  "updateExisting": False, "deleteMissing": False},
    "discoveryRules":  {"createMissing": True,  "updateExisting": False, "deleteMissing": False},
    "httptests":       {"createMissing": True,  "updateExisting": False, "deleteMissing": False},
    "valueMaps":       {"createMissing": True,  "updateExisting": False},
}

MAP_IMPORT_RULES = {
    # maps   : the network maps themselves (selements, links, shapes, etc.)
    # images : background images referenced by map selements (elementtype=4)
    # Note: icon_maps is NOT a valid import rule key in Zabbix 7.0 API —
    #       it raises "unexpected parameter /rules/icon_maps". Icon mappings
    #       are embedded in the export XML/JSON and handled transparently.
    "maps":   {"createMissing": True, "updateExisting": True},
    "images": {"createMissing": True, "updateExisting": False},
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
    """Load Zabbix credentials from zabbix_credential.yml.

    Required keys : username, password
    Optional keys : pilalert_token  (used for pilalerte owner resolution)
    """
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
                 debug_json: bool = False,
                 debug_dashboard: bool = False,
                 include_disabled_hosts: bool = False,
                 debug_widget_fields: bool = False,
                 pilalert_token: str = ""):
        self.cia_name               = cia_name
        self.skip_existing          = skip_existing
        self.dashboard_filter       = dashboard_filter
        self.host_filter            = host_filter
        self.usergroup_filter       = usergroup_filter
        self.debug_json             = debug_json
        self.debug_dashboard        = debug_dashboard
        self.include_disabled_hosts = include_disabled_hosts
        self.debug_widget_fields   = debug_widget_fields
        self.pilalert_token         = pilalert_token   # Basic token for pilalerte API
        self._source_url       = source_url  # kept for raw API calls
        self._dest_url         = dest_url   # kept for raw API calls (bypass pyzabbix)

        # Per-type result counters
        self.results: Dict[str, Dict] = {
            t: {"migrated": 0, "skipped": 0, "failed": 0, "errors": [], "names": [], "widget_warnings": []}
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
        self.source = ZabbixAPI(url=source_url, validate_certs=False)  # internal CA — skip SSL verify
        self.source.login(user=username, password=password)
        logger.debug("Source login OK.")

        logger.debug("Connecting to destination: %s", dest_url)
        self.dest = ZabbixAPI(url=dest_url, validate_certs=False)  # internal CA — skip SSL verify
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
                                  headers={"Content-Type": "application/json"}, timeout=30,
                                  verify=False)   # internal CA — skip SSL verify
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
            self.source = ZabbixAPI(url=self._source_url, validate_certs=False)
            self.source.login(user=self._username, password=self._password)
        except Exception as exc:
            logger.debug("pyzabbix source re-login failed: %s", exc)
        try:
            self.dest = ZabbixAPI(url=self._dest_url, validate_certs=False)
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
            pool  = all_hosts if self.include_disabled_hosts else enabled
            match = [h for h in pool if h["name"] == self.host_filter]
            if not match:
                hint = "" if self.include_disabled_hosts \
                    else " (or is disabled — add --include-disabled-hosts)"
                print(f"  [Hosts] Host '{self.host_filter}' not found{hint} in source.")
                return
            enabled  = match
            disabled = []
            print(f"  [Hosts] Filtered to single host: '{self.host_filter}'.")

        print(f"  [Hosts] Source — total: {len(all_hosts)}, "
              f"enabled: {len(enabled)}, disabled: {len(disabled)}.")

        if disabled:
            if self.include_disabled_hosts:
                print(f"  [Hosts] Including {len(disabled)} disabled host(s) "
                      f"(--include-disabled-hosts).")
                enabled = enabled + disabled
            else:
                self.disabled_hosts = [h["name"] for h in disabled]
                self.results["hosts"]["skipped"] += len(disabled)
                print(f"  [Hosts] Skipping {len(disabled)} disabled host(s) "
                      f"(use --include-disabled-hosts to migrate them too).")

        if not enabled:
            print("  [Hosts] No hosts to import.")
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
            # Normalise both sides: collapse multiple spaces, strip, lowercase
            def _norm(s: str) -> str:
                import re as _re
                return _re.sub(r"\s+", " ", (s or "").strip()).lower()

            needle_norm = _norm(self.dashboard_filter)

            # 1. Exact normalised match
            exact = [d for d in dashboards
                     if _norm(d.get("name", "")) == needle_norm]
            if exact:
                dashboards = exact
            else:
                # 2. Substring normalised match
                dashboards = [d for d in dashboards
                              if needle_norm in _norm(d.get("name", ""))]
            if not dashboards:
                print(f"  [Dashboards] Dashboard '{self.dashboard_filter}' not found in source.")
                return
            print(f"  [Dashboards] Filtered to {len(dashboards)} dashboard(s) "
                  f"matching '{self.dashboard_filter}'")

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

            print("    - Expanding shared group members via pilalerte/dest Zabbix...")
            group_extras = self._expand_shared_groups_via_members(dashboard)
            seen_ids = {g["usrgrpid"] for g in extra_groups}
            for g in group_extras:
                if g["usrgrpid"] not in seen_ids:
                    extra_groups.append(g)
                    seen_ids.add(g["usrgrpid"])

            print("    - Converting widget IDs to names...")
            converted = self._resolve_names(dashboard)

            if self.debug_widget_fields:
                import json as _json
                safe = name.replace("/", "_").replace(" ", "_")[:60]
                # Stage 1: raw source fields
                src_widgets = [{"name": w.get("name"), "type": w.get("type"),
                                "fields": w.get("fields", [])}
                               for pg in dashboard.get("pages", [])
                               for w in pg.get("widgets", [])]
                # Stage 2: after IDs → names
                cvt_widgets = [{"name": w.get("name"), "type": w.get("type"),
                                "fields": w.get("fields", [])}
                               for pg in converted.get("pages", [])
                               for w in pg.get("widgets", [])]
                with open(f"dbg_{safe}_1_src.json", "w") as _f:
                    _json.dump(src_widgets, _f, indent=2, default=str)
                with open(f"dbg_{safe}_2_converted.json", "w") as _f:
                    _json.dump(cvt_widgets, _f, indent=2, default=str)
                print(f"    [debug] Dumped stage-1 (raw src) and stage-2 (converted) to dbg_{safe}_1_src.json / _2_converted.json")

            print("    - Resolving names to destination IDs...")
            resolved, hard_missing, soft_warnings = self._resolve_ids(converted)

            if self.debug_widget_fields:
                res_widgets = [{"name": w.get("name"), "type": w.get("type"),
                                "fields": w.get("fields", [])}
                               for pg in resolved.get("pages", [])
                               for w in pg.get("widgets", [])]
                with open(f"dbg_{safe}_3_resolved.json", "w") as _f:
                    _json.dump(res_widgets, _f, indent=2, default=str)
                print(f"    [debug] Dumped stage-3 (resolved dest IDs) to dbg_{safe}_3_resolved.json")

            # Soft warnings: shared groups not found in destination — drop them,
            # log quietly, and continue creating the dashboard.
            if soft_warnings:
                for w in soft_warnings:
                    logger.info("[Dashboard '%s'] %s", name, w)

            # Widget object warnings — widgets with unresolved references are
            # dropped from the dashboard but the dashboard is still created.
            if hard_missing:
                print(f"    ! {len(hard_missing)} widget object(s) not found in "
                      f"destination — affected widgets dropped, dashboard still created:")
                for obj in hard_missing:
                    print(f"      - {obj}")
                self.results["dashboards"]["widget_warnings"].append({
                    "name": name,
                    "missing": hard_missing
                })

            print("    - Creating dashboard...")
            self._create_dashboard(resolved, owner_userid, extra_groups)
            self.results["dashboards"]["migrated"] += 1
            self.results["dashboards"]["names"].append(name)

            # --debug-dashboard: dump source + destination full details to JSON
            if self.debug_dashboard:
                self._dump_dashboard_debug(dashboard, name)

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
        Determine the owner userid and any extra sharing groups for destination.

        Steps:
          1. Look up original owner username in source.
          2. Try to find the same user in destination → use their ID directly.
          3. If not found:
             a. Use fallback owner FALLBACK_OWNER as the technical owner.
             b. Call pilalerte API to get the user's sun_groups.
                - Tries the username as-is and its ADM/non-ADM variant.
             c. Resolve each sun_group to a destination usergroup and add as
                a Read-Write sharing entry.
             d. If pilalerte is unavailable or returns nothing, fall back to
                the user's Zabbix source groups instead.
        """
        extra_groups: List[Dict] = []

        # ── 1. Resolve username from source ───────────────────────────────────
        src_username: Optional[str] = None
        if source_userid:
            try:
                data = self.source.user.get(
                    userids=source_userid, output=["username"])
                src_username = data[0]["username"] if data else None
            except Exception as exc:
                logger.debug("Could not get source user %s: %s", source_userid, exc)

        # ── 2. Find user in destination (exact match) ─────────────────────────
        if src_username:
            try:
                dest_data = self.dest.user.get(
                    filter={"username": src_username}, output=["userid"])
                if dest_data:
                    logger.debug("Owner '%s' found in destination.", src_username)
                    return dest_data[0]["userid"], []
            except Exception as exc:
                logger.debug("Error looking up '%s' in destination: %s",
                             src_username, exc)

        # ── 3. Owner not in destination — use fallback + resolve sharing ──────
        print(f"    ! Owner '{src_username or source_userid}' not found in destination.")
        print(f"      Using fallback owner: '{FALLBACK_OWNER}'")

        fallback_id = self._get_fallback_owner_id()

        if src_username:
            # Try pilalerte first
            extra_groups = self._sharing_from_pilalerte(src_username)

            # Also look up dest Zabbix groups for the user (Bxxxxx / ADMBxxxxx)
            # These are added on top of pilalerte results (no duplicates)
            dest_groups = self._sharing_from_dest_zabbix(src_username)
            existing_ids = {g["usrgrpid"] for g in extra_groups}
            for g in dest_groups:
                if g["usrgrpid"] not in existing_ids:
                    extra_groups.append(g)
                    existing_ids.add(g["usrgrpid"])

            # If still nothing, fall back to source Zabbix groups
            if not extra_groups and source_userid:
                extra_groups = self._resolve_owner_groups_for_sharing(
                    source_userid, src_username)

        return fallback_id, extra_groups

    # ── Pilalerte helpers ──────────────────────────────────────────────────────

    PILALERTE_BASE = "https://pilalerte.prd.mycloud.intrabpce.fr"

    def _pilalerte_sun_groups(self, username: str) -> List[str]:
        """
        Query pilalerte for the given username and return all unique sun_group
        values found in data.team_cia[].

        Also tries the ADM/non-ADM username variant automatically:
          - "admb0026038"  → also tries "b0026038"
          - "b0026038"     → also tries "adm" + "b0026038"  (case-insensitive)

        Returns an empty list when pilalert_token is not configured, the user
        is not found, or any network error occurs.
        """
        import requests as _req
        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            _req.packages.urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass

        if not self.pilalert_token:
            logger.debug("pilalert_token not configured — skipping pilalerte lookup.")
            return []

        headers = {"Authorization": f"Basic {self.pilalert_token}"}
        base    = self.PILALERTE_BASE.rstrip("/")
        sun_groups: List[str] = []

        # Build the list of logins to try (original + ADM variant)
        logins_to_try: List[str] = [username]
        lower = username.lower()
        if lower.startswith("adm"):
            logins_to_try.append(username[3:])          # "admB0026038" → "B0026038"
        else:
            logins_to_try.append("adm" + username)      # "B0026038" → "admB0026038"

        seen_logins: set = set()
        for login in logins_to_try:
            if login.lower() in seen_logins:
                continue
            seen_logins.add(login.lower())

            url = f"{base}/api/user/{login}"
            try:
                resp = _req.get(url, headers=headers, timeout=10,
                                verify=False)   # internal CA — skip SSL verify
                if resp.status_code == 404:
                    logger.debug("pilalerte: user '%s' not found (404).", login)
                    continue
                resp.raise_for_status()
                payload = resp.json()
                team_cia = (payload.get("data") or {}).get("team_cia") or []
                for entry in team_cia:
                    sg = entry.get("sun_group", "").strip()
                    if sg and sg not in sun_groups:
                        sun_groups.append(sg)
                logger.debug("pilalerte: user '%s' → sun_groups %s", login, sun_groups)
            except Exception as exc:
                # Print the real error so it is visible without --debug
                print(f"      [pilalerte] WARNING: request for '{login}' failed: {exc}")
                logger.debug("pilalerte request for '%s' failed: %s", login, exc)

        return sun_groups

    def _sharing_from_pilalerte(self, username: str) -> List[Dict]:
        """
        Resolve pilalerte sun_groups to destination usergroup IDs and return
        a list of dashboard sharing entries with Read-Write permission.
        """
        sun_groups = self._pilalerte_sun_groups(username)
        if not sun_groups:
            return []

        sharing: List[Dict] = []
        print(f"      pilalerte returned {len(sun_groups)} sun_group(s) for '{username}':")
        for sg in sun_groups:
            try:
                dest_grp = self.dest.usergroup.get(
                    filter={"name": sg}, output=["usrgrpid"])
                if dest_grp:
                    sharing.append({
                        "usrgrpid":   dest_grp[0]["usrgrpid"],
                        "permission": PERM_READ_WRITE,
                        "_name":      sg,
                    })
                    print(f"        + '{sg}' → shared with Edit permission")
                else:
                    print(f"        - '{sg}' not found in destination — skipped")
            except Exception as exc:
                logger.debug("Error resolving sun_group '%s': %s", sg, exc)

        return sharing

    def _sharing_from_dest_zabbix(self, username: str) -> List[Dict]:
        """
        Look up the user in destination Zabbix (trying both the original username
        and its ADM/non-ADM variant) and return their usergroups as Read-Write
        sharing entries.

        This mirrors the ADMBxxxxx <-> Bxxxxx equivalence logic used by pilalerte:
          - "ADMB0026038" → also tries "B0026038"
          - "B0026038"    → also tries "ADMB0026038"
        """
        # Build both variants to try
        logins_to_try: List[str] = [username]
        lower = username.lower()
        if lower.startswith("adm"):
            logins_to_try.append(username[3:])       # "ADMB0026038" → "B0026038"
        else:
            logins_to_try.append("adm" + username)   # "B0026038" → "ADMB0026038"

        sharing: List[Dict] = []
        seen_grp_ids: set = set()
        found_login: Optional[str] = None

        for login in logins_to_try:
            try:
                dest_user = self.dest.user.get(
                    filter={"username": login}, output=["userid", "username"])
                if not dest_user:
                    logger.debug("dest Zabbix: user '%s' not found.", login)
                    continue
                found_login = dest_user[0]["username"]
                dest_userid = dest_user[0]["userid"]

                groups = self.dest.usergroup.get(
                    userids=dest_userid, output=["usrgrpid", "name"])
                for grp in groups:
                    if grp["usrgrpid"] not in seen_grp_ids:
                        sharing.append({
                            "usrgrpid":   grp["usrgrpid"],
                            "permission": PERM_READ_WRITE,
                            "_name":      grp["name"],
                        })
                        seen_grp_ids.add(grp["usrgrpid"])
            except Exception as exc:
                logger.debug("dest Zabbix group lookup for '%s' failed: %s",
                             login, exc)

        if sharing:
            print(f"      dest Zabbix user '{found_login}' → "
                  f"{len(sharing)} group(s) added as Edit shares:")
            for g in sharing:
                print(f"        + '{g['_name']}'")

        return sharing

    def _expand_shared_groups_via_members(self, dashboard: Dict) -> List[Dict]:
        """
        For each usergroup the dashboard is shared with in the source:
          0. (NEW) Try a direct name match in destination — if the group exists
             there by the same name, add it immediately with its original
             permission.  Groups not found are skipped (soft, non-fatal).
          1. Fetch all members of that group from source Zabbix.
          2. For each member, call pilalerte + dest Zabbix group lookup.
          3. Return all unique dest usergroup IDs as sharing entries.
        Steps 1-2 run on top of step 0 regardless of whether a direct match
        was found, so pilalerte-derived groups are always added as well.
        """
        src_groups = dashboard.get("userGroups") or []
        if not src_groups:
            return []

        collected: Dict[str, Dict] = {}   # usrgrpid -> sharing entry (dedup)
        processed_users: set = set()       # avoid calling pilalerte twice per user
        direct_matched: int = 0
        direct_skipped: int = 0

        for grp in src_groups:
            grp_id = grp.get("usrgrpid")
            if not grp_id:
                continue

            try:
                grp_data = self.source.usergroup.get(
                    usrgrpids=grp_id, output=["name"])
                grp_name = grp_data[0]["name"] if grp_data else str(grp_id)
            except Exception:
                grp_name = str(grp_id)

            # ── Step 0: direct name match ──────────────────────────────────
            # Check whether the source group exists in destination by the same
            # name.  If yes, add it with the original source permission so that
            # Read-only / Read-write is preserved exactly as configured.
            # If not, log a soft skip and continue to the member-expansion path.
            src_permission = grp.get("permission", PERM_READ_WRITE)
            try:
                dest_grp = self.dest.usergroup.get(
                    filter={"name": grp_name}, output=["usrgrpid"])
                if dest_grp:
                    dest_gid = dest_grp[0]["usrgrpid"]
                    if dest_gid not in collected:
                        collected[dest_gid] = {
                            "usrgrpid":   dest_gid,
                            "permission": src_permission,
                            "_name":      grp_name,
                        }
                    direct_matched += 1
                    print(f"      [direct] '{grp_name}' → found in destination "
                          f"(permission={src_permission}) ✓")
                else:
                    direct_skipped += 1
                    logger.debug("Direct match: group '%s' not in destination — skipped.",
                                 grp_name)
            except Exception as exc:
                direct_skipped += 1
                logger.debug("Direct match lookup failed for '%s': %s", grp_name, exc)

            # ── Steps 1-2: member-based expansion ─────────────────────────
            # Always run regardless of whether the direct match succeeded so
            # that pilalerte sun_groups are also added on top.
            try:
                members = self.source.user.get(
                    usrgrpids=grp_id, output=["userid", "username"])
            except Exception as exc:
                logger.debug("Could not fetch members of group '%s': %s",
                             grp_name, exc)
                continue

            print(f"      Group '{grp_name}': {len(members)} member(s) — "
                  f"resolving dest usergroups via members...")

            for member in members:
                uname = member.get("username", "")
                if not uname or uname.lower() in processed_users:
                    continue
                processed_users.add(uname.lower())

                for entry in self._sharing_from_pilalerte(uname):
                    gid = entry["usrgrpid"]
                    if gid not in collected:
                        collected[gid] = entry

                for entry in self._sharing_from_dest_zabbix(uname):
                    gid = entry["usrgrpid"]
                    if gid not in collected:
                        collected[gid] = entry

        result = list(collected.values())
        print(f"      -> Direct matches: {direct_matched} added, "
              f"{direct_skipped} not found in destination (skipped).")
        if result:
            print(f"      -> {len(result)} unique dest usergroup(s) total "
                  f"(direct + member expansion from {len(processed_users)} member(s)):")
            for g in result:
                print(f"        + '{g.get('_name', g['usrgrpid'])}'")
        else:
            print(f"      -> No dest usergroups resolved (direct or via members).")

        return result

    def _get_fallback_owner_id(self) -> str:
        """Return the userid of FALLBACK_OWNER in destination, raise if not found."""
        try:
            data = self.dest.user.get(
                filter={"username": FALLBACK_OWNER}, output=["userid"])
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
        Fallback when pilalerte is unavailable: get the source user's Zabbix
        usergroups and return those that also exist in destination as Read-Write
        sharing entries.
        """
        sharing: List[Dict] = []
        try:
            src_groups = self.source.usergroup.get(
                userids=source_userid, output=["usrgrpid", "name"])
        except Exception as exc:
            logger.debug("Could not get usergroups for '%s': %s", src_username, exc)
            return sharing

        print(f"      (pilalerte unavailable) Resolving source Zabbix groups for "
              f"'{src_username}' ({len(src_groups)} group(s)):")

        for grp in src_groups:
            gname = grp["name"]
            try:
                dest_grp = self.dest.usergroup.get(
                    filter={"name": gname}, output=["usrgrpid"])
                if dest_grp:
                    sharing.append({
                        "usrgrpid":   dest_grp[0]["usrgrpid"],
                        "permission": PERM_READ_WRITE,
                        "_name":      gname,
                    })
                    print(f"        + '{gname}' exists in destination → "
                          "shared with Edit permission")
                else:
                    print(f"        - '{gname}' NOT found in destination → skipped")
            except Exception as exc:
                logger.debug("Error resolving group '%s': %s", gname, exc)

        return sharing

    # -----------------------------------------------------------------------
    # Dashboard: name/ID resolution (phase 1 — source side)
    # -----------------------------------------------------------------------

    def _resolve_names(self, dashboard: Dict) -> Dict:
        """Convert every object ID in a dashboard to a portable name."""
        converted = dashboard.copy()

        # Shared users — resolve source userid → username for portability.
        # Users absent in destination will be soft-warned and dropped at
        # the _resolve_ids stage; the dashboard is still created.
        converted["users"] = []
        if dashboard.get("users"):
            for user in dashboard["users"]:
                try:
                    data = self.source.user.get(
                        userids=user["userid"], output=["username"])
                    if data:
                        converted["users"].append({
                            "username":   data[0]["username"],
                            "permission": user["permission"],
                        })
                except Exception:
                    pass

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
                        itemids=fval, output=["key_", "name"], selectHosts=["host"])
                    if data:
                        cf["value_name"] = data[0]["key_"]
                        cf["item_name"]  = data[0]["name"]   # fallback for svggraph
                        cf["host_name"]  = data[0]["hosts"][0]["host"]
                    else:
                        cf["value_name"] = _INACCESSIBLE

                elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:
                    data = self.source.itemprototype.get(
                        itemids=fval, output=["key_", "name"], selectHosts=["host"])
                    if data:
                        cf["value_name"] = data[0]["key_"]
                        cf["item_name"]  = data[0]["name"]   # fallback for svggraph
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

        # Shared users — resolve username → dest userid (soft-warn if missing).
        converted["users"] = []
        if dashboard.get("users"):
            for user in dashboard["users"]:
                uname = user.get("username", "")
                data = self.dest.user.get(
                    filter={"username": uname}, output=["userid"])
                if data:
                    converted["users"].append({
                        "userid":     data[0]["userid"],
                        "permission": user["permission"],
                        "_name":      uname,   # stripped before API call
                    })
                else:
                    sof
