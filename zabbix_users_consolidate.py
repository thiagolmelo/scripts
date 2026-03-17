#!/usr/bin/env python3
# SCRIPT_VERSION = "2026-03-17.1"
"""
zabbix_internal_users.py

Collect all internal (non-LDAP / non-SAML) accounts from every Zabbix instance
described by the standard config files, consolidate them into a single canonical
YAML, and deploy that canonical set back to any instance.

─────────────────────────────────────────────────────────────────────────────
WORKFLOW
─────────────────────────────────────────────────────────────────────────────

  Step 1 — collect from ALL instances (ppr + prd, both source and dest URLs):
    python zabbix_internal_users.py --collect \\
        [--env ppr|prd|all]  [--cia NAME|all] \\
        [--group-filter PATTERN] \\
        --output canonical_users.yml

  Step 2 — human review:
    • Open canonical_users.yml
    • Verify each user entry
    • Replace placeholder passwords with real credentials
    • Remove users that should NOT be deployed everywhere
    • Resolve any _meta.conflicts listed per user

  Step 3 — deploy to target instances:
    python zabbix_internal_users.py --deploy \\
        --input canonical_users.yml \\
        --env ppr|prd  --cia NAME|all \\
        [--target source|dest|all]   (default: all)
        [--dry-run]                  (print actions, no changes)
        [--update-password]          (also push password on UPDATE)
        [--skip-existing]            (skip users that already exist)

─────────────────────────────────────────────────────────────────────────────
CONFIG FILES  (same directory as this script)
─────────────────────────────────────────────────────────────────────────────
  zabbix_credential.yml        username / password for API access
  zabbix_instances_ppr.yml     CIA map: url_export / url_import for PPR
  zabbix_instances_prd.yml     CIA map: url_export / url_import for PRD

─────────────────────────────────────────────────────────────────────────────
INTERNAL-USER DETECTION
─────────────────────────────────────────────────────────────────────────────
  A user is classified as "internal" when ALL of the following are true:
    • userdirectoryid == "0"  (not linked to LDAP / SAML directory)
    • username is not in the built-in exclusion list ("guest")
    • [optional] belongs to at least one group matching --group-filter

  Users whose groups ALL have gui_access=2 (force LDAP) are also excluded
  even if userdirectoryid==0, because they cannot use internal auth in practice.
"""

import os
import re
import sys
import json
import secrets
import string
import argparse
import logging
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

# zabbix_utils must be installed:  pip install zabbix-utils
try:
    from zabbix_utils import ZabbixAPI
except ImportError:
    print("ERROR: zabbix_utils not installed.  Run: pip install zabbix-utils",
          file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_VERSION = "2026-03-17.1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Built-in Zabbix accounts — always excluded from collection and deploy
BUILTIN_USERNAMES: Set[str] = {"guest"}

# Default role names mapped from legacy Zabbix "type" field
# (used as fallback when role.get is unavailable)
_LEGACY_TYPE_NAMES = {
    "1": "User",
    "2": "Admin",
    "3": "Super admin",
}

# gui_access values
GUI_ACCESS_DEFAULT  = "0"
GUI_ACCESS_INTERNAL = "1"
GUI_ACCESS_LDAP     = "2"
GUI_ACCESS_DISABLED = "3"

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Password generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_password(length: int = 20) -> str:
    """
    Generate a cryptographically random password containing at least one
    lowercase letter, one uppercase letter, one digit, and one symbol.
    """
    lower   = string.ascii_lowercase
    upper   = string.ascii_uppercase
    digits  = string.digits
    symbols = "!@#$%^&*"
    pool    = lower + upper + digits + symbols

    while True:
        pwd = "".join(secrets.choice(pool) for _ in range(length))
        if (any(c in lower   for c in pwd) and
                any(c in upper   for c in pwd) and
                any(c in digits  for c in pwd) and
                any(c in symbols for c in pwd)):
            return pwd


# ─────────────────────────────────────────────────────────────────────────────
# Config loaders  (identical contract to zabbix_migration_70.py)
# ─────────────────────────────────────────────────────────────────────────────

def load_credentials() -> Dict:
    path = os.path.join(BASE_DIR, "zabbix_credential.yml")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Credentials file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        creds = yaml.safe_load(f)
    if not creds or "username" not in creds or "password" not in creds:
        raise ValueError(f"'{path}' must contain 'username' and 'password'.")
    return creds


def load_instances(environment: str) -> Dict:
    filename = f"zabbix_instances_{environment}.yml"
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Instances file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if not config or "cia" not in config:
        raise ValueError(f"'{path}' must contain a 'cia' mapping.")
    return config


def build_instance_list(
        envs: List[str],
        cia_filter: Optional[str],
        target: str = "all",        # "source" | "dest" | "all"
) -> List[Tuple[str, str, str]]:
    """
    Return a deduplicated list of (label, url, env) tuples for all matching
    instances.  Duplicate URLs (same source and dest) are collapsed to one entry.
    """
    seen_urls: Set[str] = set()
    instances: List[Tuple[str, str, str]] = []

    for env in envs:
        try:
            config  = load_instances(env)
        except FileNotFoundError:
            logger.debug("No instances file for env '%s' — skipping.", env)
            continue

        cia_map: Dict = config["cia"]
        cia_names = (list(cia_map.keys())
                     if cia_filter in (None, "all")
                     else [cia_filter])

        for cia_name in cia_names:
            if cia_name not in cia_map:
                print(f"  WARNING: CIA '{cia_name}' not found in {env} config.",
                      file=sys.stderr)
                continue

            cfg = cia_map[cia_name]
            pairs: List[Tuple[str, str]] = []

            # ── Collect every URL-like value found under this CIA entry ───────
            # We don't rely on key names at all: any value starting with http(s)
            # is an instance to scan.  Typos like "uurl_import", non-standard
            # key names, and future config changes are all handled transparently.
            cia_urls: List[Tuple[str, str]] = []   # (key_name, url)
            for k, v in cfg.items():
                if isinstance(v, str) and v.strip().lower().startswith("http"):
                    cia_urls.append((k, v.strip()))

            if not cia_urls:
                print(f"  WARNING: CIA '{cia_name}' ({env}) has no URL values "
                      f"— skipping.  Keys found: {list(cfg.keys())}",
                      file=sys.stderr)
                continue

            logger.debug("CIA '%s/%s' — found %d URL(s): %s",
                         env, cia_name, len(cia_urls), cia_urls)

            for k, url in cia_urls:
                pairs.append((f"{env}/{cia_name}/{k}", url))

            for label, url in pairs:
                norm = url.rstrip("/").lower()
                if norm not in seen_urls:
                    seen_urls.add(norm)
                    instances.append((label, url, env))

    return instances


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — COLLECT
# ─────────────────────────────────────────────────────────────────────────────

def collect_from_instance(
        url: str,
        admin_user: str,
        admin_pass: str,
        label: str,
        group_filter: Optional[str] = None,
) -> List[Dict]:
    """
    Fetch all internal users from a single Zabbix instance.

    Returns a list of dicts:
        username, name, surname, autologin, autologout,
        role, groups, _source
    """
    print(f"\n  ── {label}")
    print(f"     URL: {url}")

    # ── Connect ──────────────────────────────────────────────────────────────
    try:
        api = ZabbixAPI(url=url)
        api.login(user=admin_user, password=admin_pass)
    except Exception as exc:
        print(f"  ERROR: could not connect: {exc}")
        return []

    try:
        # Zabbix version (informational)
        try:
            ver = api.apiinfo.version()
            print(f"     Zabbix version: {ver}")
        except Exception:
            pass

        # ── Fetch roles ───────────────────────────────────────────────────────
        role_map: Dict[str, str] = {}   # roleid → name
        try:
            roles    = api.role.get(output=["roleid", "name"])
            role_map = {r["roleid"]: r["name"] for r in roles}
        except Exception as exc:
            logger.debug("role.get failed on %s: %s", label, exc)

        # ── Fetch all users ───────────────────────────────────────────────────
        users_raw = api.user.get(
            output=["userid", "username", "name", "surname",
                    "autologin", "autologout", "roleid",
                    "userdirectoryid", "type"],   # 'type' for legacy fallback
            selectUsrgrps=["usrgrpid", "name", "gui_access"],
        )

    except Exception as exc:
        print(f"  ERROR: user.get failed: {exc}")
        try:
            api.logout()
        except Exception:
            pass
        return []

    finally:
        try:
            api.logout()
        except Exception:
            pass

    # ── Filter ───────────────────────────────────────────────────────────────
    internal: List[Dict] = []
    cnt_ldap    = 0
    cnt_builtin = 0
    cnt_forced_ldap = 0

    for u in users_raw:
        uname = (u.get("username") or u.get("alias") or "").strip()

        # Skip built-in accounts
        if uname.lower() in BUILTIN_USERNAMES:
            cnt_builtin += 1
            continue

        # Skip users linked to an external directory (LDAP / SAML)
        if str(u.get("userdirectoryid", "0")) not in ("0", "", "None"):
            cnt_ldap += 1
            logger.debug("Skipping LDAP/SAML user (userdirectoryid≠0): %s", uname)
            continue

        # Skip users whose ALL groups force LDAP auth (gui_access == "2")
        grp_list = u.get("usrgrps") or []
        if grp_list:
            all_force_ldap = all(
                str(g.get("gui_access", "0")) == GUI_ACCESS_LDAP
                for g in grp_list
            )
            if all_force_ldap:
                cnt_forced_ldap += 1
                logger.debug("Skipping forced-LDAP user (all groups gui_access=2): %s",
                             uname)
                continue

        # Group names
        groups = sorted(g["name"] for g in grp_list)

        # Optional group-name filter (substring match, case-insensitive)
        if group_filter:
            pat = group_filter.lower()
            if not any(pat in g.lower() for g in groups):
                continue

        # Role name: prefer role.get result, fall back to legacy 'type' field
        role_id   = str(u.get("roleid", ""))
        role_name = (role_map.get(role_id)
                     or _LEGACY_TYPE_NAMES.get(str(u.get("type", "")))
                     or f"(roleid:{role_id})")

        internal.append({
            "username":   uname,
            "name":       (u.get("name") or "").strip(),
            "surname":    (u.get("surname") or "").strip(),
            "autologin":  int(u.get("autologin", 0)),
            "autologout": str(u.get("autologout", "0")),
            "role":       role_name,
            "roleid":     role_id,
            "groups":     groups,
            "_source":    label,
        })

    print(f"     Internal users found : {len(internal)}")
    print(f"     Excluded — LDAP/SAML : {cnt_ldap}  "
          f"| forced-LDAP groups: {cnt_forced_ldap}  "
          f"| built-in: {cnt_builtin}")

    return internal


def consolidate_users(all_lists: List[List[Dict]]) -> List[Dict]:
    """
    Merge user records from multiple instances into a single canonical list.

    Deduplication key  : username  (case-insensitive)
    Merge rules
      name / surname   : first non-empty value wins; conflict flagged if both differ
      autologin        : 1 if ANY instance has 1
      autologout       : first non-"0" value wins
      role             : first value wins; conflict flagged if values differ
      groups           : UNION of all groups across all instances
      _found_on        : list of all labels where this username was seen
    """
    canonical: Dict[str, Dict] = {}   # lower-username → record

    for user_list in all_lists:
        for u in user_list:
            key   = u["username"].lower()
            label = u["_source"]

            if key not in canonical:
                canonical[key] = {
                    "username":     u["username"],
                    "name":         u["name"],
                    "surname":      u["surname"],
                    "autologin":    u["autologin"],
                    "autologout":   u["autologout"],
                    "role":         u["role"],
                    "groups":       set(u["groups"]),
                    # internal tracking (not written to final YAML as-is)
                    "_password":    generate_password(),
                    "_found_on":    [label],
                    "_conflicts":   [],
                    "_role_conflict":  False,
                    "_name_conflict":  False,
                }
                continue

            rec = canonical[key]
            rec["_found_on"].append(label)

            # Groups — always union
            rec["groups"].update(u["groups"])

            # autologin — take 1 if any instance has it
            if u["autologin"] == 1:
                rec["autologin"] = 1

            # autologout — prefer non-"0" (timed session)
            if rec["autologout"] == "0" and u["autologout"] not in ("0", ""):
                rec["autologout"] = u["autologout"]

            # name / surname — fill blanks; flag real conflicts
            for field in ("name", "surname"):
                existing_val = (rec[field] or "").strip()
                new_val      = (u[field] or "").strip()
                if new_val and not existing_val:
                    rec[field] = new_val
                elif (existing_val and new_val
                        and existing_val.lower() != new_val.lower()):
                    rec["_name_conflict"] = True
                    msg = (f"{field}: '{existing_val}' vs '{new_val}' "
                           f"[seen on {label}]")
                    if msg not in rec["_conflicts"]:
                        rec["_conflicts"].append(msg)

            # role — flag if different
            if rec["role"] != u["role"] and u["role"]:
                rec["_role_conflict"] = True
                msg = (f"role: '{rec['role']}' vs '{u['role']}' "
                       f"[seen on {label}]")
                if msg not in rec["_conflicts"]:
                    rec["_conflicts"].append(msg)

    # Convert group sets to sorted lists; sort final list alphabetically
    result = []
    for rec in sorted(canonical.values(), key=lambda r: r["username"].lower()):
        rec["groups"] = sorted(rec["groups"])
        result.append(rec)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# YAML writer
# ─────────────────────────────────────────────────────────────────────────────

# Custom YAML representer to output str without unnecessary quotes
class _CleanDumper(yaml.Dumper):
    pass

def _str_representer(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)

_CleanDumper.add_representer(str, _str_representer)


def write_canonical_yaml(
        users: List[Dict],
        output_path: str,
        envs_scanned: List[str],
):
    """Write the consolidated canonical user list to a YAML file."""
    now = datetime.now()
    conflicts_count = sum(1 for u in users if u.get("_conflicts"))

    # Build per-user YAML entries (using OrderedDict preserves key order)
    yaml_users = []
    for u in users:
        entry = OrderedDict([
            ("username",   u["username"]),
            ("name",       u["name"]),
            ("surname",    u["surname"]),
            ("password",   u["_password"]),     # ← random placeholder: CHANGE ME
            ("autologin",  u["autologin"]),
            ("autologout", u["autologout"]),
            ("role",       u["role"]),
            ("groups",     u["groups"]),
        ])

        # _meta block — for human review; ignored by --deploy
        meta = OrderedDict()
        meta["found_on"] = u["_found_on"]
        if u.get("_conflicts"):
            meta["CONFLICTS"] = u["_conflicts"]
        if u.get("_role_conflict"):
            meta["role_conflict_detected"] = True
        if u.get("_name_conflict"):
            meta["name_conflict_detected"] = True
        entry["_meta"] = dict(meta)

        yaml_users.append(dict(entry))

    doc = OrderedDict([
        ("metadata", OrderedDict([
            ("generated_at",          now.strftime("%Y-%m-%dT%H:%M:%S")),
            ("generator",             f"zabbix_internal_users.py v{SCRIPT_VERSION}"),
            ("environments_scanned",  envs_scanned),
            ("total_users",           len(yaml_users)),
            ("users_with_conflicts",  conflicts_count),
        ])),
        ("users", yaml_users),
    ])

    sep = "#" + " ─" * 38
    header_lines = [
        sep,
        "# Canonical internal Zabbix users",
        f"# Generated  : {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Script     : zabbix_internal_users.py v{SCRIPT_VERSION}",
        f"# Users      : {len(yaml_users)}",
        f"# Conflicts  : {conflicts_count}  (see _meta.CONFLICTS in affected entries)",
        sep,
        "#",
        "# INSTRUCTIONS — complete these steps before running --deploy:",
        "#",
        "#   1. Review EVERY entry carefully",
        "#",
        "#   2. Update the 'password' field for each user.",
        "#      Current values are RANDOM PLACEHOLDERS generated by this script.",
        "#      They are used as-is when a user is CREATED on an instance.",
        "#      UPDATE is skipped unless you add --update-password to --deploy.",
        "#",
        "#   3. Remove users that should NOT be deployed to all instances.",
        "#",
        "#   4. Resolve any _meta.CONFLICTS entries listed per user.",
        "#      Conflicts are differences in name/surname/role across instances.",
        "#",
        "#   5. Then run:",
        "#      python zabbix_internal_users.py --deploy \\",
        "#          --input <this file> --env ppr --cia all",
        "#",
        "# NOTE: _meta blocks are informational ONLY — they are ignored by --deploy.",
        "# NOTE: autologin: 1  →  session never expires (recommended for API users).",
        "# NOTE: autologout: '0'  →  session never times out.",
        sep,
        "",
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header_lines))
        yaml.dump(
            dict(doc), f,
            Dumper=_CleanDumper,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
            width=120,
        )

    print(f"\n  ✓ Written: {output_path}")
    print(f"    Users     : {len(yaml_users)}")
    print(f"    Conflicts : {conflicts_count}")
    if conflicts_count:
        print("    ⚠  Review entries marked with _meta.CONFLICTS before deploying.")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — DEPLOY
# ─────────────────────────────────────────────────────────────────────────────

def load_canonical_yaml(input_path: str) -> List[Dict]:
    """Read and validate the canonical YAML produced by --collect."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    with open(input_path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    if not doc or "users" not in doc:
        raise ValueError("YAML must contain a top-level 'users' list.")
    users = doc["users"]
    if not isinstance(users, list):
        raise ValueError("'users' must be a list.")
    return users


def _ensure_groups(
        api,
        group_names: List[str],
        label: str,
        dry_run: bool,
) -> Dict[str, str]:
    """
    Resolve group names → usrgrpid in the destination instance.
    Creates missing groups (gui_access=internal) unless dry_run.

    Returns: {group_name: usrgrpid}
    """
    try:
        existing = api.usergroup.get(output=["usrgrpid", "name"])
        gmap     = {g["name"]: g["usrgrpid"] for g in existing}
    except Exception as exc:
        print(f"  WARNING: could not fetch usergroups on {label}: {exc}")
        gmap = {}

    for gname in group_names:
        if gname in gmap:
            continue
        if dry_run:
            print(f"    [dry-run] Would create missing group: '{gname}'")
        else:
            try:
                result = api.usergroup.create(
                    name=gname,
                    gui_access=GUI_ACCESS_INTERNAL,
                    users_status="0",
                )
                new_id = result["usrgrpids"][0]
                gmap[gname] = new_id
                print(f"    + Created missing group: '{gname}'")
            except Exception as exc:
                print(f"    WARNING: could not create group '{gname}': {exc}")

    return gmap


def deploy_to_instance(
        url: str,
        admin_user: str,
        admin_pass: str,
        label: str,
        canonical_users: List[Dict],
        dry_run: bool          = False,
        update_password: bool  = False,
        skip_existing: bool    = False,
) -> Dict[str, List]:
    """
    Create or update users on a single Zabbix instance from the canonical list.

    Returns: {"created": [...], "updated": [...], "skipped": [...], "failed": [...]}
    """
    result: Dict[str, List] = {
        "created": [], "updated": [], "skipped": [], "failed": []
    }

    print(f"\n  ── {label}")
    print(f"     URL: {url}")
    if dry_run:
        print("     MODE: DRY-RUN — no changes will be made")

    # ── Connect ───────────────────────────────────────────────────────────────
    try:
        api = ZabbixAPI(url=url)
        api.login(user=admin_user, password=admin_pass)
    except Exception as exc:
        print(f"  ERROR: could not connect: {exc}")
        result["failed"].append({"username": "*ALL*", "reason": str(exc)})
        return result

    try:
        ver = api.apiinfo.version()
        print(f"     Zabbix version: {ver}")
    except Exception:
        pass

    # ── Pre-fetch roles ───────────────────────────────────────────────────────
    role_name_to_id: Dict[str, str] = {}
    try:
        roles = api.role.get(output=["roleid", "name"])
        role_name_to_id = {r["name"]: r["roleid"] for r in roles}
    except Exception as exc:
        print(f"  WARNING: could not fetch roles: {exc}")

    # ── Pre-fetch existing users ──────────────────────────────────────────────
    try:
        existing_users = api.user.get(output=["userid", "username"])
        existing_map   = {u["username"].lower(): u["userid"]
                          for u in existing_users}
    except Exception as exc:
        print(f"  ERROR: could not fetch existing users: {exc}")
        try:
            api.logout()
        except Exception:
            pass
        result["failed"].append({"username": "*ALL*", "reason": str(exc)})
        return result

    # ── Collect all group names needed ────────────────────────────────────────
    all_group_names: Set[str] = set()
    for u in canonical_users:
        all_group_names.update(u.get("groups") or [])

    group_map = _ensure_groups(api, sorted(all_group_names), label, dry_run)

    # ── Process each user ─────────────────────────────────────────────────────
    print(f"     Processing {len(canonical_users)} user(s)...")

    for u in canonical_users:
        uname = u.get("username", "").strip()
        if not uname:
            continue

        # Skip built-in accounts (safety guard)
        if uname.lower() in BUILTIN_USERNAMES:
            logger.debug("Skipping built-in account: %s", uname)
            continue

        existing_userid = existing_map.get(uname.lower())

        # --skip-existing
        if existing_userid and skip_existing:
            logger.debug("Skipping (already exists): %s", uname)
            result["skipped"].append(uname)
            continue

        # ── Resolve role ───────────────────────────────────────────────────────
        role_name = u.get("role", "")
        roleid    = role_name_to_id.get(role_name)
        if role_name and not roleid:
            print(f"    WARNING: role '{role_name}' not found for '{uname}' "
                  f"— user will be created without explicit role assignment")

        # ── Resolve groups ─────────────────────────────────────────────────────
        resolved_grps: List[Dict[str, str]] = []
        missing_grps:  List[str] = []
        for gname in (u.get("groups") or []):
            gid = group_map.get(gname)
            if gid:
                resolved_grps.append({"usrgrpid": gid})
            else:
                missing_grps.append(gname)

        if missing_grps:
            print(f"    WARNING: '{uname}' — groups not resolved "
                  f"(will be skipped from assignment): {missing_grps}")

        if not resolved_grps:
            print(f"    x Skipping '{uname}' — no groups could be resolved")
            result["skipped"].append(uname)
            continue

        # ── Build base payload ─────────────────────────────────────────────────
        payload: Dict[str, Any] = {
            "username":   uname,
            "name":       (u.get("name") or "").strip(),
            "surname":    (u.get("surname") or "").strip(),
            "autologin":  str(int(u.get("autologin", 1))),
            "autologout": str(u.get("autologout", "0")),
            "usrgrps":    resolved_grps,
        }
        if roleid:
            payload["roleid"] = roleid

        # ── CREATE ─────────────────────────────────────────────────────────────
        if not existing_userid:
            pwd = (u.get("password") or "").strip() or generate_password()
            create_payload = {**payload, "passwd": pwd}

            if dry_run:
                print(f"    [dry-run] Would CREATE: {uname}"
                      f"  role={role_name}  groups={[g['usrgrpid'] for g in resolved_grps]}")
                result["created"].append(uname)
            else:
                try:
                    api.user.create(**create_payload)
                    print(f"    + Created : {uname}  [role: {role_name}]")
                    result["created"].append(uname)
                except Exception as exc:
                    print(f"    x Failed  : {uname} — {exc}")
                    result["failed"].append({"username": uname, "reason": str(exc)})

        # ── UPDATE ─────────────────────────────────────────────────────────────
        else:
            update_payload = {**payload, "userid": existing_userid}
            if update_password:
                pwd = (u.get("password") or "").strip()
                if pwd:
                    update_payload["passwd"] = pwd

            if dry_run:
                print(f"    [dry-run] Would UPDATE: {uname}"
                      f"  role={role_name}  groups={[g['usrgrpid'] for g in resolved_grps]}")
                result["updated"].append(uname)
            else:
                try:
                    api.user.update(**update_payload)
                    pwd_note = " (password updated)" if update_password else ""
                    print(f"    ~ Updated : {uname}{pwd_note}  [role: {role_name}]")
                    result["updated"].append(uname)
                except Exception as exc:
                    print(f"    x Failed  : {uname} — {exc}")
                    result["failed"].append({"username": uname, "reason": str(exc)})

    try:
        api.logout()
    except Exception:
        pass

    return result


def print_deploy_summary(
        all_results: List[Tuple[str, Dict[str, List]]],
        dry_run: bool,
):
    """Print a consolidated deploy summary table."""
    mode = "[DRY-RUN] " if dry_run else ""
    print(f"\n{'═' * 70}")
    print(f"  {mode}Deploy Summary")
    print(f"{'═' * 70}")
    print(f"  {'Instance':<40}  {'Created':>7}  {'Updated':>7}  "
          f"{'Skipped':>7}  {'Failed':>7}")
    print(f"  {'─' * 40}  {'─' * 7}  {'─' * 7}  {'─' * 7}  {'─' * 7}")

    totals = {"created": 0, "updated": 0, "skipped": 0, "failed": 0}
    for label, res in all_results:
        c = len(res["created"])
        u = len(res["updated"])
        s = len(res["skipped"])
        f = len(res["failed"])
        print(f"  {label:<40}  {c:>7}  {u:>7}  {s:>7}  {f:>7}")
        totals["created"] += c
        totals["updated"] += u
        totals["skipped"] += s
        totals["failed"]  += f

    print(f"  {'─' * 40}  {'─' * 7}  {'─' * 7}  {'─' * 7}  {'─' * 7}")
    print(f"  {'TOTAL':<40}  {totals['created']:>7}  {totals['updated']:>7}  "
          f"{totals['skipped']:>7}  {totals['failed']:>7}")
    print(f"{'═' * 70}")

    if totals["failed"]:
        print(f"\n  ⚠  {totals['failed']} failure(s) detected — details above.")

    failed_details = []
    for label, res in all_results:
        for f in res["failed"]:
            if isinstance(f, dict):
                failed_details.append(f"  [{label}] {f.get('username', '?')}: "
                                      f"{f.get('reason', '')}")
    if failed_details:
        print("\n  Failed entries:")
        for line in failed_details:
            print(line)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect and deploy internal Zabbix users",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Collect from all instances (ppr + prd, source + dest)
  python zabbix_internal_users.py --collect --output canonical_users.yml

  # Collect only from PRD, only accounts in groups containing "api"
  python zabbix_internal_users.py --collect --env prd \\
      --group-filter api --output prd_api_users.yml

  # Collect from a single CIA
  python zabbix_internal_users.py --collect --env ppr --cia biz01 \\
      --output ppr_biz01_users.yml

  # Deploy to all PPR instances (source + dest)
  python zabbix_internal_users.py --deploy --input canonical_users.yml \\
      --env ppr --cia all

  # Deploy to PRD dest only, dry-run first
  python zabbix_internal_users.py --deploy --input canonical_users.yml \\
      --env prd --cia biz01 --target dest --dry-run

  # Deploy and also update passwords from YAML
  python zabbix_internal_users.py --deploy --input canonical_users.yml \\
      --env prd --cia all --update-password
        """
    )

    # ── Mode ─────────────────────────────────────────────────────────────────
    mode_grp = parser.add_mutually_exclusive_group(required=True)
    mode_grp.add_argument(
        "--collect", action="store_true",
        help="Scan instances and write canonical YAML"
    )
    mode_grp.add_argument(
        "--deploy", action="store_true",
        help="Read canonical YAML and create/update users on instances"
    )

    # ── Common ────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--env", default="all",
        help="Environment(s) to scan/deploy: ppr | prd | all  (default: all)"
    )
    parser.add_argument(
        "--cia", default="all",
        help="CIA name or 'all'  (default: all)"
    )

    # ── Collect-specific ──────────────────────────────────────────────────────
    parser.add_argument(
        "--output", default="canonical_users.yml", metavar="FILE",
        help="Output YAML file path  (default: canonical_users.yml)"
    )
    parser.add_argument(
        "--group-filter", default=None, metavar="PATTERN",
        help="Only include users belonging to a group whose name contains PATTERN "
             "(case-insensitive substring match).  "
             "Example: --group-filter api  →  keeps only users in *api* groups."
    )

    # ── Deploy-specific ───────────────────────────────────────────────────────
    parser.add_argument(
        "--input", default="canonical_users.yml", metavar="FILE",
        help="Canonical YAML file to deploy  (default: canonical_users.yml)"
    )
    parser.add_argument(
        "--target", default="all", choices=["source", "dest", "all"],
        help="Which instance URL to target per CIA: source | dest | all  "
             "(default: all)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be done without making any changes"
    )
    parser.add_argument(
        "--update-password", action="store_true",
        help="Also update the password field on existing users (default: only on CREATE)"
    )
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="Skip users that already exist in destination (no update)"
    )

    # ── Misc ──────────────────────────────────────────────────────────────────
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose debug logging"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # ── Load credentials ──────────────────────────────────────────────────────
    try:
        creds = load_credentials()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    # ── Determine environments to process ─────────────────────────────────────
    if args.env == "all":
        envs = ["ppr", "prd"]
    else:
        envs = [args.env]

    # ═════════════════════════════════════════════════════════════════════════
    # MODE: COLLECT
    # ═════════════════════════════════════════════════════════════════════════
    if args.collect:
        print("\n" + "=" * 70)
        print(f"  Zabbix Internal Users — COLLECT  [v{SCRIPT_VERSION}]")
        print(f"  env={args.env}  cia={args.cia}")
        if args.group_filter:
            print(f"  group-filter='{args.group_filter}'")
        print("=" * 70)

        # Build full instance list (source + dest of every CIA in every env)
        instances = build_instance_list(envs, args.cia, target="all")
        if not instances:
            print("ERROR: no instances matched the given --env / --cia.",
                  file=sys.stderr)
            sys.exit(1)

        print(f"\n  Instances to scan: {len(instances)}")

        # Collect from each instance
        all_user_lists: List[List[Dict]] = []
        for label, url, _env in instances:
            user_list = collect_from_instance(
                url=url,
                admin_user=creds["username"],
                admin_pass=creds["password"],
                label=label,
                group_filter=args.group_filter,
            )
            all_user_lists.append(user_list)

        # Consolidate
        print(f"\n  Consolidating...")
        canonical = consolidate_users(all_user_lists)

        raw_total      = sum(len(lst) for lst in all_user_lists)
        conflict_count = sum(1 for u in canonical if u.get("_conflicts"))
        multi_instance = sum(1 for u in canonical if len(u["_found_on"]) > 1)

        print(f"  Raw records collected : {raw_total}")
        print(f"  Unique users          : {len(canonical)}")
        print(f"  Users on >1 instance  : {multi_instance}")
        print(f"  Users with conflicts  : {conflict_count}")

        # Write YAML
        write_canonical_yaml(canonical, args.output, envs)

        print(f"\n  Next step: review '{args.output}', update passwords,")
        print(f"  then run:  python {os.path.basename(__file__)} --deploy "
              f"--input {args.output} --env <env> --cia all")

    # ═════════════════════════════════════════════════════════════════════════
    # MODE: DEPLOY
    # ═════════════════════════════════════════════════════════════════════════
    elif args.deploy:
        print("\n" + "=" * 70)
        print(f"  Zabbix Internal Users — DEPLOY  [v{SCRIPT_VERSION}]")
        print(f"  env={args.env}  cia={args.cia}  target={args.target}")
        if args.dry_run:
            print("  *** DRY-RUN MODE — no changes will be made ***")
        if args.update_password:
            print("  *** --update-password: passwords will be updated on existing users ***")
        print("=" * 70)

        # Load canonical users
        try:
            canonical_users = load_canonical_yaml(args.input)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)

        print(f"\n  Loaded {len(canonical_users)} user(s) from '{args.input}'")

        # Check for placeholder passwords
        placeholder_users = [
            u["username"] for u in canonical_users
            if not (u.get("password") or "").strip()
        ]
        if placeholder_users:
            print(f"\n  WARNING: {len(placeholder_users)} user(s) have empty passwords:")
            for uname in placeholder_users:
                print(f"    - {uname}")
            print("  These users will receive a new random password on CREATE.")

        # Build instance list
        instances = build_instance_list(envs, args.cia, target=args.target)
        if not instances:
            print("ERROR: no instances matched the given --env / --cia / --target.",
                  file=sys.stderr)
            sys.exit(1)

        print(f"\n  Target instances: {len(instances)}")

        # Deploy to each instance
        all_results: List[Tuple[str, Dict[str, List]]] = []
        for label, url, _env in instances:
            res = deploy_to_instance(
                url=url,
                admin_user=creds["username"],
                admin_pass=creds["password"],
                label=label,
                canonical_users=canonical_users,
                dry_run=args.dry_run,
                update_password=args.update_password,
                skip_existing=args.skip_existing,
            )
            all_results.append((label, res))

        print_deploy_summary(all_results, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
