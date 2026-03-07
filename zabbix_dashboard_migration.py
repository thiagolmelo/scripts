#!/usr/bin/env python3
"""
Zabbix Dashboard Migration Script
Migrates dashboards from Zabbix 6.4 to Zabbix 7.0

Official Zabbix 6.4 widget field types (dashboard/object API):
  0  = Integer          (no resolution needed)
  1  = String           (no resolution needed)
  2  = Host group       ← resolve via hostgroup.get
  3  = Host             ← resolve via host.get
  4  = Item             ← resolve via item.get
  5  = Item prototype   ← resolve via itemprototype.get
  6  = Graph            ← resolve via graph.get
  7  = Graph prototype  ← resolve via graphprototype.get
  8  = Map              ← resolve via map.get
  9  = Service
  10 = SLA
  11 = User
  12 = Action
  13 = Media type

Config files (same directory as this script):
  zabbix_credential.yml        → username / password
  zabbix_instances_{env}.yml   → cia.<n>.url_export / url_import

Usage:
  python migrate_dashboards.py --env ppr --cia biz01
  python migrate_dashboards.py --env prd --cia all     # migrates every CIA
  python migrate_dashboards.py --env ppr --cia biz01 --debug
"""

import os
import re
import sys
import argparse
import logging
from typing import Dict, List, Tuple

import yaml
from zabbix_utils import ZabbixAPI

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Sentinel: field references a deleted / inaccessible object → skip silently
_INACCESSIBLE = "__INACCESSIBLE__"

# Official Zabbix 6.4 widget field type constants
FIELD_TYPE_INTEGER        = "0"
FIELD_TYPE_STRING         = "1"
FIELD_TYPE_HOST_GROUP     = "2"   # ← hostgroup.get
FIELD_TYPE_HOST           = "3"   # ← host.get
FIELD_TYPE_ITEM           = "4"   # ← item.get
FIELD_TYPE_ITEM_PROTOTYPE = "5"   # ← itemprototype.get
FIELD_TYPE_GRAPH          = "6"   # ← graph.get
FIELD_TYPE_GRAPH_PROTO    = "7"   # ← graphprototype.get
FIELD_TYPE_MAP            = "8"   # ← map.get

# Zabbix 6.4 tag filter fields (flat format) that break 7.0 API
_TAG_FIELD_RE = re.compile(r'^tags\.(tag|operator|value)\.\d+$')

# Grid scaling: 6.4 = 24 columns, 7.0 = 36 columns (×1.5 horizontal only)
# Vertical grid is identical: y 0-62, height 2-32
GRID_SCALE = 1.5

logger = logging.getLogger(__name__)


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
# Main migrator class
# ---------------------------------------------------------------------------

class DashboardMigrator:
    """Migrates dashboards from a Zabbix 6.4 source to a Zabbix 7.0 destination."""

    def __init__(self, source_url: str, dest_url: str,
                 username: str, password: str, cia_name: str):
        self.cia_name = cia_name
        self.failed_dashboards: List[Dict] = []
        self.migrated_count = 0

        logger.debug("Connecting to source: %s", source_url)
        self.source = ZabbixAPI(url=source_url)
        self.source.login(user=username, password=password)
        logger.debug("Source login OK.")

        logger.debug("Connecting to destination: %s", dest_url)
        self.dest = ZabbixAPI(url=dest_url)
        self.dest.login(user=username, password=password)
        logger.debug("Destination login OK.")

    def logout(self):
        """Gracefully logout from both APIs."""
        try:
            self.source.logout()
        except Exception:
            pass
        try:
            self.dest.logout()
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Fetch
    # -----------------------------------------------------------------------

    def get_all_dashboards(self) -> List[Dict]:
        """Retrieve all dashboards from source."""
        print("  Fetching dashboards from source instance...")
        dashboards = self.source.dashboard.get(
            output="extend",
            selectPages="extend",
            selectUsers="extend",
            selectUserGroups="extend"
        )
        print(f"  Found {len(dashboards)} dashboards.")
        return dashboards

    # -----------------------------------------------------------------------
    # Phase 1: IDs -> portable names  (reading from source)
    # -----------------------------------------------------------------------

    def resolve_object_names(self, dashboard: Dict) -> Dict:
        """Convert every object ID in the dashboard to its portable name."""
        converted = dashboard.copy()

        # --- Users ---
        if dashboard.get("users"):
            converted["users"] = []
            for user in dashboard["users"]:
                data = self.source.user.get(
                    userids=user["userid"],
                    output=["username"]
                )
                if data:
                    converted["users"].append({
                        "username": data[0]["username"],
                        "permission": user["permission"]
                    })
                else:
                    logger.debug("User ID %s not found in source.", user["userid"])

        # --- User groups ---
        if dashboard.get("userGroups"):
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                data = self.source.usergroup.get(
                    usrgrpids=group["usrgrpid"],
                    output=["name"]
                )
                if data:
                    converted["userGroups"].append({
                        "name": data[0]["name"],
                        "permission": group["permission"]
                    })
                else:
                    logger.debug("User group ID %s not found in source.", group["usrgrpid"])

        # --- Pages / widgets ---
        if dashboard.get("pages"):
            converted["pages"] = []
            for page in dashboard["pages"]:
                converted_page = page.copy()
                if page.get("widgets"):
                    converted_page["widgets"] = []
                    for widget in page["widgets"]:
                        converted_page["widgets"].append(
                            self._widget_ids_to_names(widget)
                        )
                converted["pages"].append(converted_page)

        return converted

    def _widget_ids_to_names(self, widget: Dict) -> Dict:
        """
        Resolve every object-reference field in a widget from ID to name.

        Type mapping (official Zabbix 6.4 API docs):
          2 = Host group   3 = Host   4 = Item   5 = Item prototype
          6 = Graph        7 = Graph prototype    8 = Map
        """
        converted = widget.copy()
        wtype = widget.get("type", "?")

        if not widget.get("fields"):
            return converted

        converted["fields"] = []
        for field in widget["fields"]:
            cf = field.copy()
            ftype = str(field.get("type", ""))
            fname = field.get("name", "")
            fval  = field.get("value")

            try:
                if ftype == FIELD_TYPE_HOST_GROUP:          # 2 -> Host group
                    data = self.source.hostgroup.get(
                        groupids=fval,
                        output=["name"]
                    )
                    if data:
                        cf["value_name"] = data[0]["name"]
                        logger.debug("[%s] field '%s': hostgroup %s -> '%s'",
                                     wtype, fname, fval, data[0]["name"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': hostgroup ID %s not found in source",
                                     wtype, fname, fval)

                elif ftype == FIELD_TYPE_HOST:              # 3 -> Host
                    data = self.source.host.get(
                        hostids=fval,
                        output=["host"]
                    )
                    if data:
                        cf["value_name"] = data[0]["host"]
                        logger.debug("[%s] field '%s': host %s -> '%s'",
                                     wtype, fname, fval, data[0]["host"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': host ID %s not found in source",
                                     wtype, fname, fval)

                elif ftype == FIELD_TYPE_ITEM:              # 4 -> Item
                    data = self.source.item.get(
                        itemids=fval,
                        output=["key_"],
                        selectHosts=["host"]
                    )
                    if data:
                        cf["value_name"] = data[0]["key_"]
                        cf["host_name"]  = data[0]["hosts"][0]["host"]
                        logger.debug("[%s] field '%s': item %s -> '%s' on '%s'",
                                     wtype, fname, fval,
                                     cf["value_name"], cf["host_name"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': item ID %s not found in source",
                                     wtype, fname, fval)

                elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:    # 5 -> Item prototype
                    data = self.source.itemprototype.get(
                        itemids=fval,
                        output=["key_"],
                        selectHosts=["host"]
                    )
                    if data:
                        cf["value_name"] = data[0]["key_"]
                        cf["host_name"]  = data[0]["hosts"][0]["host"]
                        logger.debug("[%s] field '%s': item_prototype %s -> '%s'",
                                     wtype, fname, fval, cf["value_name"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': item_prototype ID %s not found",
                                     wtype, fname, fval)

                elif ftype == FIELD_TYPE_GRAPH:             # 6 -> Graph
                    data = self.source.graph.get(
                        graphids=fval,
                        output=["name"],
                        selectHosts=["host"]
                    )
                    if data:
                        cf["value_name"] = data[0]["name"]
                        if data[0].get("hosts"):
                            cf["host_name"] = data[0]["hosts"][0]["host"]
                        logger.debug("[%s] field '%s': graph %s -> '%s'",
                                     wtype, fname, fval, cf["value_name"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': graph ID %s not found in source",
                                     wtype, fname, fval)

                elif ftype == FIELD_TYPE_GRAPH_PROTO:       # 7 -> Graph prototype
                    data = self.source.graphprototype.get(
                        graphids=fval,
                        output=["name"],
                        selectHosts=["host"]
                    )
                    if data:
                        cf["value_name"] = data[0]["name"]
                        if data[0].get("hosts"):
                            cf["host_name"] = data[0]["hosts"][0]["host"]
                        logger.debug("[%s] field '%s': graph_prototype %s -> '%s'",
                                     wtype, fname, fval, cf["value_name"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': graph_prototype ID %s not found",
                                     wtype, fname, fval)

                elif ftype == FIELD_TYPE_MAP:               # 8 -> Map
                    data = self.source.map.get(
                        sysmapids=fval,
                        output=["name"]
                    )
                    if data:
                        cf["value_name"] = data[0]["name"]
                        logger.debug("[%s] field '%s': map %s -> '%s'",
                                     wtype, fname, fval, data[0]["name"])
                    else:
                        cf["value_name"] = _INACCESSIBLE
                        logger.debug("[%s] field '%s': map ID %s not found in source",
                                     wtype, fname, fval)

                else:
                    # Types 0 (Integer) and 1 (String) need no resolution.
                    # Any other numeric type is passed through as-is.
                    logger.debug("[%s] field '%s' type=%s value=%s -> pass-through",
                                 wtype, fname, ftype, fval)

            except Exception as exc:
                logger.debug("[%s] field '%s' type=%s error: %s -- marking inaccessible",
                             wtype, fname, ftype, exc)
                cf["value_name"] = _INACCESSIBLE

            converted["fields"].append(cf)

        return converted

    # -----------------------------------------------------------------------
    # Phase 2: portable names -> IDs in destination
    # -----------------------------------------------------------------------

    def resolve_object_ids(self, dashboard: Dict) -> Dict:
        """Convert portable names back to IDs valid in the destination."""
        converted = dashboard.copy()
        missing: List[str] = []

        # --- Users ---
        if dashboard.get("users"):
            converted["users"] = []
            for user in dashboard["users"]:
                data = self.dest.user.get(
                    filter={"username": user["username"]},
                    output=["userid"]
                )
                if data:
                    converted["users"].append({
                        "userid":     data[0]["userid"],
                        "permission": user["permission"]
                    })
                else:
                    missing.append(f"User: '{user['username']}'")

        # --- User groups ---
        if dashboard.get("userGroups"):
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                data = self.dest.usergroup.get(
                    filter={"name": group["name"]},
                    output=["usrgrpid"]
                )
                if data:
                    converted["userGroups"].append({
                        "usrgrpid":   data[0]["usrgrpid"],
                        "permission": group["permission"]
                    })
                else:
                    missing.append(f"User group: '{group['name']}'")

        # --- Pages / widgets ---
        if dashboard.get("pages"):
            converted["pages"] = []
            for page in dashboard["pages"]:
                converted_page = page.copy()
                if page.get("widgets"):
                    converted_page["widgets"] = []
                    for widget in page["widgets"]:
                        w, w_missing = self._widget_names_to_ids(widget)
                        converted_page["widgets"].append(w)
                        missing.extend(w_missing)
                converted["pages"].append(converted_page)

        if missing:
            raise MissingObjectsError(missing)

        return converted

    def _widget_names_to_ids(self, widget: Dict) -> Tuple[Dict, List[str]]:
        """
        Resolve portable names back to IDs in the destination.
        Fields marked _INACCESSIBLE are silently dropped.
        """
        converted = widget.copy()
        missing: List[str] = []
        wname = widget.get("name", "?")
        wtype = widget.get("type", "?")

        if not widget.get("fields"):
            return converted, missing

        converted["fields"] = []
        for field in widget["fields"]:
            cf = field.copy()
            ftype = str(field.get("type", ""))
            fname = field.get("name", "")

            # Fields without value_name are pass-through (integers, strings, etc.)
            if "value_name" not in field:
                converted["fields"].append(cf)
                continue

            # Silently drop fields that were inaccessible/deleted in the source
            if field["value_name"] == _INACCESSIBLE:
                logger.debug("[%s '%s'] field '%s' marked inaccessible -- dropped",
                             wtype, wname, fname)
                continue

            vname = field["value_name"]
            ctx   = f"widget '{wname}' (type: {wtype}), field '{fname}'"

            try:
                if ftype == FIELD_TYPE_HOST_GROUP:          # 2 -> Host group
                    data = self.dest.hostgroup.get(
                        filter={"name": vname},
                        output=["groupid"]
                    )
                    if data:
                        cf["value"] = data[0]["groupid"]
                    else:
                        missing.append(f"Host group '{vname}' [{ctx}]")

                elif ftype == FIELD_TYPE_HOST:              # 3 -> Host
                    data = self.dest.host.get(
                        filter={"host": vname},
                        output=["hostid"]
                    )
                    if data:
                        cf["value"] = data[0]["hostid"]
                    else:
                        missing.append(f"Host '{vname}' [{ctx}]")

                elif ftype == FIELD_TYPE_ITEM:              # 4 -> Item
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name},
                            output=["hostid"]
                        )
                        if hosts:
                            items = self.dest.item.get(
                                filter={"key_": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["itemid"]
                            )
                            if items:
                                cf["value"] = items[0]["itemid"]
                            else:
                                missing.append(
                                    f"Item '{vname}' on host '{host_name}' [{ctx}]"
                                )
                        else:
                            missing.append(
                                f"Host '{host_name}' (needed for item '{vname}') [{ctx}]"
                            )
                    else:
                        missing.append(f"Item '{vname}' (no host context) [{ctx}]")

                elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:    # 5 -> Item prototype
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name},
                            output=["hostid"]
                        )
                        if hosts:
                            protos = self.dest.itemprototype.get(
                                filter={"key_": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["itemid"]
                            )
                            if protos:
                                cf["value"] = protos[0]["itemid"]
                            else:
                                missing.append(
                                    f"Item prototype '{vname}' on host '{host_name}' [{ctx}]"
                                )
                        else:
                            missing.append(
                                f"Host '{host_name}' (needed for item_prototype '{vname}') [{ctx}]"
                            )
                    else:
                        missing.append(f"Item prototype '{vname}' (no host context) [{ctx}]")

                elif ftype == FIELD_TYPE_GRAPH:             # 6 -> Graph
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name},
                            output=["hostid"]
                        )
                        if hosts:
                            graphs = self.dest.graph.get(
                                filter={"name": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["graphid"]
                            )
                            if graphs:
                                cf["value"] = graphs[0]["graphid"]
                            else:
                                missing.append(
                                    f"Graph '{vname}' on host '{host_name}' [{ctx}]"
                                )
                        else:
                            missing.append(
                                f"Host '{host_name}' (needed for graph '{vname}') [{ctx}]"
                            )
                    else:
                        # Graph without host context: search by name only
                        graphs = self.dest.graph.get(
                            filter={"name": vname},
                            output=["graphid"]
                        )
                        if graphs:
                            cf["value"] = graphs[0]["graphid"]
                        else:
                            missing.append(f"Graph '{vname}' [{ctx}]")

                elif ftype == FIELD_TYPE_GRAPH_PROTO:       # 7 -> Graph prototype
                    host_name = field.get("host_name")
                    if host_name:
                        hosts = self.dest.host.get(
                            filter={"host": host_name},
                            output=["hostid"]
                        )
                        if hosts:
                            protos = self.dest.graphprototype.get(
                                filter={"name": vname},
                                hostids=[hosts[0]["hostid"]],
                                output=["graphid"]
                            )
                            if protos:
                                cf["value"] = protos[0]["graphid"]
                            else:
                                missing.append(
                                    f"Graph prototype '{vname}' on host '{host_name}' [{ctx}]"
                                )
                        else:
                            missing.append(
                                f"Host '{host_name}' (needed for graph_prototype '{vname}') [{ctx}]"
                            )
                    else:
                        missing.append(f"Graph prototype '{vname}' (no host context) [{ctx}]")

                elif ftype == FIELD_TYPE_MAP:               # 8 -> Map
                    data = self.dest.map.get(
                        filter={"name": vname},
                        output=["sysmapid"]
                    )
                    if data:
                        cf["value"] = data[0]["sysmapid"]
                    else:
                        missing.append(f"Map '{vname}' [{ctx}]")

            except Exception as exc:
                missing.append(f"{ctx} -- error: {exc}")

            # Remove helper fields used only during transport
            cf.pop("value_name", None)
            cf.pop("host_name",  None)
            converted["fields"].append(cf)

        return converted, missing

    # -----------------------------------------------------------------------
    # Phase 3: create in destination
    # -----------------------------------------------------------------------

    def _delete_existing_dashboard(self, name: str):
        """Delete a dashboard in the destination if it already exists."""
        existing = self.dest.dashboard.get(
            filter={"name": name},
            output=["dashboardid"]
        )
        if existing:
            did = existing[0]["dashboardid"]
            self.dest.dashboard.delete(did)
            logger.debug("Deleted existing dashboard ID %s ('%s')", did, name)

    @staticmethod
    def _filter_tag_fields(fields: List[Dict]) -> List[Dict]:
        """
        Drop Zabbix 6.4 tag filter fields that are incompatible with 7.0.

        In 6.4: tags.tag.N / tags.operator.N / tags.value.N  (flat format)
        In 7.0: structure changed -- sending the old format raises:
                "Invalid parameter tags/N: unexpected parameter 0"
        Safest approach: drop them. Widget will show all data unfiltered.
        """
        return [f for f in fields if not _TAG_FIELD_RE.match(f.get("name", ""))]

    def create_dashboard(self, dashboard: Dict) -> bool:
        """Build the cleaned payload and create the dashboard in the destination."""
        try:
            self._delete_existing_dashboard(dashboard["name"])

            clean = {
                "name":           dashboard["name"],
                "display_period": int(dashboard.get("display_period", 30)),
                "auto_start":     int(dashboard.get("auto_start", 1)),
            }

            if dashboard.get("users"):
                clean["users"] = dashboard["users"]
            if dashboard.get("userGroups"):
                clean["userGroups"] = dashboard["userGroups"]

            clean["pages"] = []
            for page in dashboard.get("pages", []):
                clean_page = {
                    "name":           page.get("name", ""),
                    "display_period": int(page.get("display_period", 0)),
                    "widgets":        []
                }

                for widget in page.get("widgets", []):
                    # -----------------------------------------------------------
                    # Grid scaling (official Zabbix API docs):
                    #   6.4: x 0-23, width  1-24  (24 columns)
                    #   7.0: x 0-35, width  1-36  (36 columns) -> scale x1.5
                    #   Vertical grid UNCHANGED: y 0-62, height 2-32
                    #
                    # Use start/end rounding to prevent any gap or overlap:
                    #   x     = round(src_x * 1.5)
                    #   width = round((src_x + src_w) * 1.5) - x
                    # -----------------------------------------------------------
                    src_x = int(widget.get("x", 0))
                    src_w = int(widget.get("width", 1))

                    x     = round(src_x * GRID_SCALE)
                    width = round((src_x + src_w) * GRID_SCALE) - x

                    y      = int(widget.get("y", 0))
                    height = int(widget.get("height", 2))

                    # Clamp to 7.0 official limits
                    if x + width > 36:
                        width = 36 - x
                    width  = max(1, min(width, 36))
                    height = max(2, min(height, 32))   # min 2, max 32 per docs

                    clean_widget = {
                        "type":      widget["type"],
                        "name":      widget.get("name", ""),
                        "x":         x,
                        "y":         y,
                        "width":     width,
                        "height":    height,
                        "view_mode": int(widget.get("view_mode", 0)),
                    }

                    if widget.get("fields"):
                        clean_widget["fields"] = self._filter_tag_fields(
                            widget["fields"]
                        )

                    clean_page["widgets"].append(clean_widget)

                clean["pages"].append(clean_page)

            self.dest.dashboard.create(**clean)
            print(f"    + Created: {dashboard['name']}")
            return True

        except Exception as exc:
            print(f"    x Failed to create '{dashboard['name']}': {exc}")
            return False

    # -----------------------------------------------------------------------
    # Orchestration
    # -----------------------------------------------------------------------

    def migrate(self):
        """Run the full migration for one source -> destination pair."""
        try:
            src_ver = self.source.apiinfo.version()
            dst_ver = self.dest.apiinfo.version()
            print(f"  Source version:      {src_ver}")
            print(f"  Destination version: {dst_ver}")
        except Exception as exc:
            print(f"  Warning: could not check versions -- {exc}")

        try:
            dashboards = self.get_all_dashboards()
        except Exception as exc:
            print(f"  Error fetching dashboards: {exc}")
            return

        if not dashboards:
            print("  No dashboards found.")
            return

        print()
        for dashboard in dashboards:
            name = dashboard.get("name", "Unnamed")
            print(f"  Processing: {name}")

            try:
                print("    - Converting IDs to names...")
                converted = self.resolve_object_names(dashboard)

                print("    - Resolving names to destination IDs...")
                resolved = self.resolve_object_ids(converted)

                print("    - Creating dashboard...")
                if self.create_dashboard(resolved):
                    self.migrated_count += 1
                else:
                    self.failed_dashboards.append({
                        "name": name, "reason": "Creation failed"
                    })

            except MissingObjectsError as exc:
                print(f"    x Skipped -- missing objects in destination:")
                for obj in exc.missing_objects:
                    print(f"      - {obj}")
                self.failed_dashboards.append({
                    "name":    name,
                    "reason":  "Missing objects in destination",
                    "details": exc.missing_objects
                })

            except Exception as exc:
                print(f"    x Error: {exc}")
                self.failed_dashboards.append({"name": name, "reason": str(exc)})

            print()

    def print_summary(self):
        """Print a summary of this CIA's migration results."""
        ok  = self.migrated_count
        err = len(self.failed_dashboards)
        print(f"  Migrated: {ok}   Failed: {err}")

        if self.failed_dashboards:
            print("  Failed dashboards:")
            for f in self.failed_dashboards:
                print(f"    - {f['name']}  ->  {f['reason']}")
                if "details" in f:
                    for d in f["details"]:
                        print(f"        - {d}")


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class MissingObjectsError(Exception):
    """Raised when required objects are absent in the destination."""
    def __init__(self, missing_objects: List[str]):
        self.missing_objects = missing_objects
        super().__init__(f"Missing {len(missing_objects)} objects")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Migrate Zabbix dashboards from 6.4 to 7.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Migrate a single CIA in PPR environment
  python migrate_dashboards.py --env ppr --cia biz01

  # Migrate all CIAs in PRD environment
  python migrate_dashboards.py --env prd --cia all

  # Enable verbose debug output
  python migrate_dashboards.py --env ppr --cia biz01 --debug

Config files required in the same directory as this script:
  zabbix_credential.yml          username / password
  zabbix_instances_ppr.yml       CIA URLs for PPR
  zabbix_instances_prd.yml       CIA URLs for PRD
        """
    )
    parser.add_argument(
        "--env", required=True, choices=["ppr", "prd"],
        help="Environment to migrate (ppr or prd)"
    )
    parser.add_argument(
        "--cia", required=True,
        help="CIA name to migrate (e.g. biz01) or 'all' to migrate every CIA"
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging"
    )
    args = parser.parse_args()

    # Logging setup
    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    # Load credentials
    try:
        creds = load_credentials()
    except Exception as exc:
        print(f"ERROR loading credentials: {exc}", file=sys.stderr)
        sys.exit(1)

    # Load instance config
    try:
        config = load_instances(args.env)
    except Exception as exc:
        print(f"ERROR loading instances config: {exc}", file=sys.stderr)
        sys.exit(1)

    cia_map: Dict = config["cia"]

    # Determine which CIAs to process
    if args.cia == "all":
        cia_names = list(cia_map.keys())
    else:
        if args.cia not in cia_map:
            print(
                f"ERROR: CIA '{args.cia}' not found in config. "
                f"Available: {', '.join(cia_map.keys())}",
                file=sys.stderr
            )
            sys.exit(1)
        cia_names = [args.cia]

    # -----------------------------------------------------------------------
    # Main loop -- one migrator per CIA
    # -----------------------------------------------------------------------
    total_migrated = 0
    total_failed   = 0

    print("\n" + "=" * 70)
    print(f"  Zabbix Dashboard Migration  |  env={args.env}  |  "
          f"cia={'all' if args.cia == 'all' else args.cia}")
    print("=" * 70)

    for cia_name in cia_names:
        cia_cfg    = cia_map[cia_name]
        source_url = cia_cfg["url_export"]
        dest_url   = cia_cfg["url_import"]

        print(f"\n{'─' * 70}")
        print(f"  CIA   : {cia_name}")
        print(f"  Source: {source_url}")
        print(f"  Dest  : {dest_url}")
        print(f"{'─' * 70}")

        migrator = None
        try:
            migrator = DashboardMigrator(
                source_url=source_url,
                dest_url=dest_url,
                username=creds["username"],
                password=creds["password"],
                cia_name=cia_name
            )
            migrator.migrate()
            migrator.print_summary()
            total_migrated += migrator.migrated_count
            total_failed   += len(migrator.failed_dashboards)

        except Exception as exc:
            print(f"  FATAL error for CIA '{cia_name}': {exc}", file=sys.stderr)
            total_failed += 1

        finally:
            if migrator:
                migrator.logout()

    # -----------------------------------------------------------------------
    # Global summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  Global Summary")
    print("=" * 70)
    print(f"  Total migrated : {total_migrated}")
    print(f"  Total failed   : {total_failed}")
    print()
    print("  Note: Objects already inaccessible in the source were silently")
    print("        skipped and are NOT counted as failures.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
