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

import yaml
from zabbix_utils import ZabbixAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Migration order when 'all' is requested
MIGRATION_ORDER = ["templates", "hosts", "maps", "dashboards"]

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
TEMPLATE_IMPORT_RULES = {
    # Zabbix 7.0 API uses snake_case for group rules, camelCase for the rest.
    # template_groups pre-created by _ensure_template_groups_for_templates(),
    # but including it here lets the import create any that were missed.
    "template_groups":    {"createMissing": True,  "updateExisting": False},
    "templates":          {"createMissing": True,  "updateExisting": True},
    "templateDashboards": {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "templateLinkage":    {"createMissing": True,  "deleteMissing": False},
    "items":              {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "triggers":           {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "graphs":             {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "discoveryRules":     {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "valueMaps":          {"createMissing": True,  "updateExisting": False},
    "httptests":          {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
}

# Same as TEMPLATE_IMPORT_RULES but with templateDashboards disabled.
# Used in the first of the two-step template import:
#   Step 1 (this): create the template, its items, graphs, triggers, etc.
#   Step 2 (full): now that graphs exist, import again with templateDashboards
#                  so dashboard widgets that reference those graphs can resolve.
# Zabbix 7.0 processes template dashboards before top-level graphs during a
# single import call, so a one-shot import fails with "Cannot find graph …
# used in dashboard".  The two-step approach avoids this ordering issue.
TEMPLATE_IMPORT_RULES_NO_DASHBOARDS = {
    "template_groups":    {"createMissing": True,  "updateExisting": False},
    "templates":          {"createMissing": True,  "updateExisting": True},
    "templateDashboards": {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "templateLinkage":    {"createMissing": True,  "deleteMissing": False},
    "items":              {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "triggers":           {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "graphs":             {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "discoveryRules":     {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
    "valueMaps":          {"createMissing": True,  "updateExisting": False},
    "httptests":          {"createMissing": True,  "updateExisting": True,  "deleteMissing": False},
}

HOST_IMPORT_RULES = {
    # Zabbix 7.0 API uses snake_case for group rules, camelCase for the rest.
    # host_groups pre-created by _ensure_host_groups_for_hosts(), but including
    # it here lets the import create any that were missed.
    #
    # items/triggers/graphs/discoveryRules are intentionally DISABLED:
    # we only import the host skeleton (interfaces, groups, macros) and its
    # template linkages.  Zabbix automatically propagates all template-owned
    # objects when the linkage is created.  Directly-created objects (no
    # templateid) are not recreated — they belong to the source host only.
    "host_groups":     {"createMissing": True,  "updateExisting": False},
    "hosts":           {"createMissing": True,  "updateExisting": True},
    "templateLinkage": {"createMissing": True,  "deleteMissing": False},
    "items":           {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "triggers":        {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "graphs":          {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "discoveryRules":  {"createMissing": False, "updateExisting": False, "deleteMissing": False},
    "valueMaps":       {"createMissing": False, "updateExisting": False},
    "httptests":       {"createMissing": False, "updateExisting": False, "deleteMissing": False},
}

MAP_IMPORT_RULES = {
    "maps":   {"createMissing": True, "updateExisting": True},
    "images": {"createMissing": True, "updateExisting": False},
}

logger = logging.getLogger(__name__)

LOG_FILE = os.path.join(BASE_DIR, "migration.log")


# ---------------------------------------------------------------------------
# Incremental log writer
# ---------------------------------------------------------------------------

class MigrationLog:
    """
    Appends structured, timestamped detail to migration.log.
    Console output shows statistics only; this file keeps the full detail
    for post-run investigation.
    """

    def __init__(self, env: str, cia: str, types_run: List[str],
                 dashboard_filter: str = None):
        self.path       = LOG_FILE
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
                 debug_json: bool = False):
        self.cia_name         = cia_name
        self.skip_existing    = skip_existing
        self.dashboard_filter = dashboard_filter
        self.host_filter      = host_filter
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
                        self._raw_import(fmt="json", source=exported, rules=rules)
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
        print("  [Hosts] Fetching host list from source...")
        try:
            all_hosts = self.source.host.get(
                output=["hostid", "name", "status"]
            )
        except Exception as exc:
            self._fail("hosts", "host.get failed", exc)
            return

        if not all_hosts:
            print("  [Hosts] No hosts found.")
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
                    self._raw_import(fmt="json", source=chunk_exported,
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
                                    self._raw_import(fmt="json", source=h_exp,
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

    def migrate_maps(self):
        """Export all network maps from source and import to destination."""
        print("  [Maps] Fetching map list from source...")
        try:
            maps = self.source.map.get(output=["sysmapid", "name"])
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

        mids = [m["sysmapid"] for m in maps]
        try:
            self._reconnect()
        except Exception as exc:
            print(f"  [Maps] Warning: reconnect before export failed: {exc}")

        try:
            exported = self._raw_export("maps", mids)
        except Exception as exc:
            self._fail("maps", "configuration.export failed", exc)
            return

        try:
            self._raw_import(
                fmt="json",
                source=exported,
                rules=MAP_IMPORT_RULES
            )
            count = len(maps)
            self.results["maps"]["migrated"] += count
            self.results["maps"]["names"].extend(sorted(m["name"] for m in maps))
            print(f"  [Maps] Successfully imported {count} maps.")
            try:
                self.counts["maps"]["dst_total"] = int(self.dest.map.get(countOutput=True))
            except Exception:
                pass
        except Exception as exc:
            self._fail("maps", "configuration.import failed", exc)

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
            resolved, missing = self._resolve_ids(converted)

            if missing:
                print(f"    x Skipped -- {len(missing)} missing objects in destination:")
                for obj in missing:
                    print(f"      - {obj}")
                self.results["dashboards"]["failed"] += 1
                self.results["dashboards"]["errors"].append({
                    "name": name,
                    "reason": "Missing objects in destination",
                    "details": missing
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

        # Shared users
        if dashboard.get("users"):
            converted["users"] = []
            for user in dashboard["users"]:
                try:
                    data = self.source.user.get(
                        userids=user["userid"], output=["username"])
                    if data:
                        converted["users"].append({
                            "username":   data[0]["username"],
                            "permission": user["permission"]
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

    def _resolve_ids(self, dashboard: Dict) -> Tuple[Dict, List[str]]:
        """Convert portable names back to IDs valid in the destination."""
        converted = dashboard.copy()
        missing: List[str] = []

        # Shared users
        if dashboard.get("users"):
            converted["users"] = []
            for user in dashboard["users"]:
                data = self.dest.user.get(
                    filter={"username": user["username"]}, output=["userid"])
                if data:
                    converted["users"].append({
                        "userid":     data[0]["userid"],
                        "permission": user["permission"]
                    })
                else:
                    missing.append(f"Shared user: '{user['username']}'")

        # Shared user groups
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
                    missing.append(f"Shared user group: '{group['name']}'")

        # Pages and widgets
        if dashboard.get("pages"):
            converted["pages"] = []
            for page in dashboard["pages"]:
                cp = page.copy()
                if page.get("widgets"):
                    cp["widgets"] = []
                    for widget in page["widgets"]:
                        w, w_miss = self._widget_names_to_ids(widget)
                        cp["widgets"].append(w)
                        missing.extend(w_miss)
                converted["pages"].append(cp)

        return converted, missing

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

        # Merge existing shared users
        if dashboard.get("users"):
            clean["users"] = dashboard["users"]

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

    def _raw_export(self, object_type: str, ids: List[str]) -> str:
        """
        Call configuration.export via raw HTTP POST on the SOURCE instance,
        bypassing pyzabbix so the result is always a plain JSON string.

        object_type: 'templates', 'hosts', or 'maps'
        ids:         list of id strings to export
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
                "format":  "json",
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
        # result is already a JSON string when format="json"
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
        Call configuration.import via raw HTTP POST, bypassing pyzabbix
        so that rule key names are never mangled.
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
        choices=["templates", "hosts", "maps", "dashboards", "all"],
        metavar="TYPE",
        help="Object type(s) to migrate: templates hosts maps dashboards all"
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
        "--skip-existing", action="store_true",
        help="Skip objects that already exist in destination (applies to all types)"
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

    # ── Validate migration args (only needed when --migrate is used) ─────────
    if args.migrate:
        missing = []
        if not args.env:
            missing.append("--env")
        if not args.cia:
            missing.append("--cia")
        if missing:
            print(
                f"ERROR: {' and '.join(missing)} "
                f"{'is' if len(missing) == 1 else 'are'} required when --migrate is used.",
                file=sys.stderr
            )
            sys.exit(1)
    else:
        # Neither --pull-repository nor --migrate was given
        if args.pull_repository is None:
            parser.print_help()
            sys.exit(1)
        sys.exit(0)

    # Determine which migration types to run (in canonical order)
    types_to_run = parse_migrate_types(args.migrate)
    if not types_to_run:
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
    print(f"  env={args.env}  cia={args.cia}  migrate={' '.join(types_to_run)}")
    if args.dashboard:
        print(f"  dashboard filter='{args.dashboard}'")
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

    # Global summary — console: stats only
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
    mlog.write(global_results)


if __name__ == "__main__":
    main()
