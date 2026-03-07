#!/usr/bin/env python3
"""
Zabbix Dashboard Migration Script
Migrates dashboards from Zabbix 6.4 to Zabbix 7.0

Widget field types (official Zabbix 6.4 API docs):
  0  = Integer
  1  = String
  2  = Host group
  3  = Host
  4  = Item
  5  = Item prototype
  6  = Graph
  7  = Graph prototype
  8  = Map
  9  = Service
  10 = SLA
  11 = User
  12 = Action
  13 = Media type
"""

import re
import requests
import argparse
import sys
from typing import Dict, List, Any, Tuple

# Sentinel value to mark inaccessible/deleted objects that should be skipped silently
_INACCESSIBLE = "__INACCESSIBLE__"

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
FIELD_TYPE_SERVICE        = "9"
FIELD_TYPE_SLA            = "10"
FIELD_TYPE_USER           = "11"
FIELD_TYPE_ACTION         = "12"
FIELD_TYPE_MEDIA_TYPE     = "13"

# Tag field pattern used in Zabbix 6.4 (incompatible with 7.0 format)
_TAG_FIELD_RE = re.compile(r'^tags\.(tag|operator|value)\.\d+$')


class ZabbixAPI:
    """Wrapper for Zabbix API calls"""

    def __init__(self, url: str, token: str):
        self.url = url.rstrip('/') + '/api_jsonrpc.php'
        self.token = token
        self.request_id = 0

    def call(self, method: str, params: Dict = None) -> Any:
        """Make a Zabbix API call"""
        self.request_id += 1

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self.request_id,
        }

        if method != "apiinfo.version":
            payload["auth"] = self.token

        try:
            response = requests.post(self.url, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()

            if "error" in result:
                raise Exception(f"Zabbix API error: {result['error']}")

            return result.get("result")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {e}")


class DashboardMigrator:
    """Main class for dashboard migration"""

    def __init__(self, source_api: ZabbixAPI, dest_api: ZabbixAPI):
        self.source = source_api
        self.dest = dest_api
        self.failed_dashboards = []
        self.migrated_count = 0

    # ------------------------------------------------------------------
    # Fetch
    # ------------------------------------------------------------------

    def get_all_dashboards(self) -> List[Dict]:
        """Retrieve all dashboards from source"""
        print("Fetching dashboards from source instance...")
        dashboards = self.source.call("dashboard.get", {
            "output": "extend",
            "selectPages": "extend",
            "selectUsers": "extend",
            "selectUserGroups": "extend"
        })
        print(f"Found {len(dashboards)} dashboards")
        return dashboards

    # ------------------------------------------------------------------
    # Phase 1: resolve IDs -> names (reading from source)
    # ------------------------------------------------------------------

    def resolve_object_names(self, dashboard: Dict) -> Dict:
        """Convert IDs to portable names in dashboard definition"""
        converted = dashboard.copy()

        # Users
        if "users" in dashboard:
            converted["users"] = []
            for user in dashboard["users"]:
                data = self.source.call("user.get", {
                    "userids": user["userid"],
                    "output": ["username"]
                })
                if data:
                    converted["users"].append({
                        "username": data[0]["username"],
                        "permission": user["permission"]
                    })

        # User groups
        if "userGroups" in dashboard:
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                data = self.source.call("usergroup.get", {
                    "usrgrpids": group["usrgrpid"],
                    "output": ["name"]
                })
                if data:
                    converted["userGroups"].append({
                        "name": data[0]["name"],
                        "permission": group["permission"]
                    })

        # Pages / widgets
        if "pages" in dashboard:
            converted["pages"] = []
            for page in dashboard["pages"]:
                converted_page = page.copy()
                if "widgets" in page:
                    converted_page["widgets"] = []
                    for widget in page["widgets"]:
                        try:
                            converted_page["widgets"].append(
                                self._widget_ids_to_names(widget)
                            )
                        except Exception as e:
                            print(f"  Warning: Failed to convert widget: {e}")
                            raise
                converted["pages"].append(converted_page)

        return converted

    def _widget_ids_to_names(self, widget: Dict) -> Dict:
        """
        For every field that references a Zabbix object by ID,
        look up its name in the source and store it alongside the field
        so we can resolve it in the destination later.

        Fields referencing deleted/inaccessible objects are marked with
        _INACCESSIBLE and will be silently dropped at creation time.

        Official Zabbix 6.4 widget field types:
          2 = Host group   3 = Host   4 = Item   5 = Item prototype
          6 = Graph        7 = Graph prototype    8 = Map
        """
        converted = widget.copy()

        if "fields" not in widget:
            return converted

        converted["fields"] = []
        for field in widget["fields"]:
            cf = field.copy()
            ftype = str(field.get("type", ""))

            if ftype == FIELD_TYPE_HOST_GROUP:          # 2 - Host group
                data = self.source.call("hostgroup.get", {
                    "groupids": field["value"],
                    "output": ["name"]
                })
                cf["value_name"] = data[0]["name"] if data else _INACCESSIBLE

            elif ftype == FIELD_TYPE_HOST:              # 3 - Host
                data = self.source.call("host.get", {
                    "hostids": field["value"],
                    "output": ["host"]
                })
                cf["value_name"] = data[0]["host"] if data else _INACCESSIBLE

            elif ftype == FIELD_TYPE_ITEM:              # 4 - Item
                data = self.source.call("item.get", {
                    "itemids": field["value"],
                    "output": ["key_"],
                    "selectHosts": ["host"]
                })
                if data:
                    cf["value_name"] = data[0]["key_"]
                    cf["host_name"]  = data[0]["hosts"][0]["host"]
                else:
                    cf["value_name"] = _INACCESSIBLE

            elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:    # 5 - Item prototype
                data = self.source.call("itemprototype.get", {
                    "itemids": field["value"],
                    "output": ["key_"],
                    "selectHosts": ["host"]
                })
                if data:
                    cf["value_name"] = data[0]["key_"]
                    cf["host_name"]  = data[0]["hosts"][0]["host"]
                else:
                    cf["value_name"] = _INACCESSIBLE

            elif ftype == FIELD_TYPE_GRAPH:             # 6 - Graph
                data = self.source.call("graph.get", {
                    "graphids": field["value"],
                    "output": ["name"],
                    "selectHosts": ["host"]
                })
                if data:
                    cf["value_name"] = data[0]["name"]
                    if data[0].get("hosts"):
                        cf["host_name"] = data[0]["hosts"][0]["host"]
                else:
                    cf["value_name"] = _INACCESSIBLE

            elif ftype == FIELD_TYPE_GRAPH_PROTO:       # 7 - Graph prototype
                data = self.source.call("graphprototype.get", {
                    "graphids": field["value"],
                    "output": ["name"],
                    "selectHosts": ["host"]
                })
                if data:
                    cf["value_name"] = data[0]["name"]
                    if data[0].get("hosts"):
                        cf["host_name"] = data[0]["hosts"][0]["host"]
                else:
                    cf["value_name"] = _INACCESSIBLE

            elif ftype == FIELD_TYPE_MAP:               # 8 - Map
                data = self.source.call("map.get", {
                    "sysmapids": field["value"],
                    "output": ["name"]
                })
                cf["value_name"] = data[0]["name"] if data else _INACCESSIBLE

            else:
                # types 0 (Integer), 1 (String) and others pass through unchanged
                pass

            converted["fields"].append(cf)

        return converted

    # ------------------------------------------------------------------
    # Phase 2: resolve names -> IDs (looking up in destination)
    # ------------------------------------------------------------------

    def resolve_object_ids(self, dashboard: Dict) -> Dict:
        """Convert portable names back to IDs in the destination instance"""
        converted = dashboard.copy()
        missing_objects = []

        # Users
        if "users" in dashboard:
            converted["users"] = []
            for user in dashboard["users"]:
                data = self.dest.call("user.get", {
                    "filter": {"username": user["username"]},
                    "output": ["userid"]
                })
                if data:
                    converted["users"].append({
                        "userid": data[0]["userid"],
                        "permission": user["permission"]
                    })
                else:
                    missing_objects.append(f"User: {user['username']}")

        # User groups
        if "userGroups" in dashboard:
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                data = self.dest.call("usergroup.get", {
                    "filter": {"name": group["name"]},
                    "output": ["usrgrpid"]
                })
                if data:
                    converted["userGroups"].append({
                        "usrgrpid": data[0]["usrgrpid"],
                        "permission": group["permission"]
                    })
                else:
                    missing_objects.append(f"User group: {group['name']}")

        # Pages / widgets
        if "pages" in dashboard:
            converted["pages"] = []
            for page in dashboard["pages"]:
                converted_page = page.copy()
                if "widgets" in page:
                    converted_page["widgets"] = []
                    for widget in page["widgets"]:
                        try:
                            cw, widget_missing = self._widget_names_to_ids(widget)
                            converted_page["widgets"].append(cw)
                            missing_objects.extend(widget_missing)
                        except Exception as e:
                            missing_objects.append(f"Widget conversion error: {e}")
                converted["pages"].append(converted_page)

        if missing_objects:
            raise MissingObjectsError(missing_objects)

        return converted

    def _widget_names_to_ids(self, widget: Dict) -> Tuple[Dict, List[str]]:
        """
        Convert value_name / host_name back to numeric IDs in the destination.
        Fields marked _INACCESSIBLE are silently dropped.
        Fields whose name cannot be found in the destination are reported.
        """
        converted = widget.copy()
        missing = []

        if "fields" not in widget:
            return converted, missing

        converted["fields"] = []
        for field in widget["fields"]:
            cf = field.copy()

            # Only fields that went through name-resolution have "value_name"
            if "value_name" not in field:
                converted["fields"].append(cf)
                continue

            # Silently drop objects that were already gone in the source
            if field["value_name"] == _INACCESSIBLE:
                continue

            ftype = str(field.get("type", ""))

            if ftype == FIELD_TYPE_HOST_GROUP:          # 2 - Host group
                data = self.dest.call("hostgroup.get", {
                    "filter": {"name": field["value_name"]},
                    "output": ["groupid"]
                })
                if data:
                    cf["value"] = data[0]["groupid"]
                else:
                    missing.append(f"Host group: {field['value_name']}")

            elif ftype == FIELD_TYPE_HOST:              # 3 - Host
                data = self.dest.call("host.get", {
                    "filter": {"host": field["value_name"]},
                    "output": ["hostid"]
                })
                if data:
                    cf["value"] = data[0]["hostid"]
                else:
                    missing.append(f"Host: {field['value_name']}")

            elif ftype == FIELD_TYPE_ITEM:              # 4 - Item
                host_name = field.get("host_name")
                if host_name:
                    data = self.dest.call("item.get", {
                        "filter": {"key_": field["value_name"]},
                        "host": host_name,
                        "output": ["itemid"]
                    })
                    if data:
                        cf["value"] = data[0]["itemid"]
                    else:
                        missing.append(f"Item: {field['value_name']} on host {host_name}")
                else:
                    missing.append(f"Item: {field['value_name']} (no host context)")

            elif ftype == FIELD_TYPE_ITEM_PROTOTYPE:    # 5 - Item prototype
                host_name = field.get("host_name")
                if host_name:
                    data = self.dest.call("itemprototype.get", {
                        "filter": {"key_": field["value_name"]},
                        "host": host_name,
                        "output": ["itemid"]
                    })
                    if data:
                        cf["value"] = data[0]["itemid"]
                    else:
                        missing.append(f"Item prototype: {field['value_name']} on host {host_name}")
                else:
                    missing.append(f"Item prototype: {field['value_name']} (no host context)")

            elif ftype == FIELD_TYPE_GRAPH:             # 6 - Graph
                host_name = field.get("host_name")
                if host_name:
                    host_data = self.dest.call("host.get", {
                        "filter": {"host": host_name},
                        "output": ["hostid"]
                    })
                    if host_data:
                        data = self.dest.call("graph.get", {
                            "filter": {"name": field["value_name"]},
                            "hostids": host_data[0]["hostid"],
                            "output": ["graphid"]
                        })
                        if data:
                            cf["value"] = data[0]["graphid"]
                        else:
                            missing.append(f"Graph: {field['value_name']} on host {host_name}")
                    else:
                        missing.append(f"Host: {host_name}")
                else:
                    missing.append(f"Graph: {field['value_name']} (no host context)")

            elif ftype == FIELD_TYPE_GRAPH_PROTO:       # 7 - Graph prototype
                host_name = field.get("host_name")
                if host_name:
                    host_data = self.dest.call("host.get", {
                        "filter": {"host": host_name},
                        "output": ["hostid"]
                    })
                    if host_data:
                        data = self.dest.call("graphprototype.get", {
                            "filter": {"name": field["value_name"]},
                            "hostids": host_data[0]["hostid"],
                            "output": ["graphid"]
                        })
                        if data:
                            cf["value"] = data[0]["graphid"]
                        else:
                            missing.append(f"Graph prototype: {field['value_name']} on host {host_name}")
                    else:
                        missing.append(f"Host: {host_name}")
                else:
                    missing.append(f"Graph prototype: {field['value_name']} (no host context)")

            elif ftype == FIELD_TYPE_MAP:               # 8 - Map
                data = self.dest.call("map.get", {
                    "filter": {"name": field["value_name"]},
                    "output": ["sysmapid"]
                })
                if data:
                    cf["value"] = data[0]["sysmapid"]
                else:
                    missing.append(f"Map: {field['value_name']}")

            # Remove temporary name helpers before sending to API
            cf.pop("value_name", None)
            cf.pop("host_name", None)

            converted["fields"].append(cf)

        return converted, missing

    # ------------------------------------------------------------------
    # Phase 3: create in destination
    # ------------------------------------------------------------------

    def delete_existing_dashboard(self, name: str) -> None:
        """Delete a dashboard by name in destination if it exists"""
        existing = self.dest.call("dashboard.get", {
            "filter": {"name": name},
            "output": ["dashboardid"]
        })
        if existing:
            did = existing[0]["dashboardid"]
            self.dest.call("dashboard.delete", [did])
            print(f"  - Found existing dashboard (ID: {did}), deleting...")

    def _filter_widget_fields(self, fields: List[Dict]) -> List[Dict]:
        """
        Strip widget fields that are incompatible with Zabbix 7.0.

        Zabbix 6.4 tag filter fields (tags.tag.N / tags.operator.N / tags.value.N)
        use a flat structure that was replaced in 7.0. Sending the old format
        causes: "Invalid parameter tags/N: unexpected parameter 0".
        Safest fix: drop them -- the widget will show all data unfiltered.
        """
        return [f for f in fields if not _TAG_FIELD_RE.match(f.get("name", ""))]

    def create_dashboard(self, dashboard: Dict) -> bool:
        """Create dashboard in destination instance"""
        try:
            self.delete_existing_dashboard(dashboard["name"])

            clean_dashboard = {
                "name":           dashboard["name"],
                "display_period": int(dashboard.get("display_period", 30)),
                "auto_start":     int(dashboard.get("auto_start", 1)),
            }

            if dashboard.get("users"):
                clean_dashboard["users"] = dashboard["users"]

            if dashboard.get("userGroups"):
                clean_dashboard["userGroups"] = dashboard["userGroups"]

            if "pages" in dashboard:
                clean_dashboard["pages"] = []
                for page in dashboard["pages"]:
                    clean_page = {
                        "name":           page.get("name", ""),
                        "display_period": int(page.get("display_period", 0)),
                        "widgets":        []
                    }

                    for widget in page.get("widgets", []):
                        # -----------------------------------------------
                        # Grid scaling -- official docs:
                        #   6.4: x 0-23, width 1-24  (24 columns)
                        #   7.0: x 0-35, width 1-36  (36 columns)  x1.5
                        #   height & y: identical in both versions (y 0-62, height 2-32)
                        # Only horizontal dimensions are scaled.
                        # Using start/end rounding to prevent gaps or overlaps.
                        # -----------------------------------------------
                        SCALE = 1.5
                        src_x = int(widget.get("x", 0))
                        src_w = int(widget.get("width", 1))

                        x     = round(src_x * SCALE)
                        width = round((src_x + src_w) * SCALE) - x

                        y      = int(widget.get("y", 0))
                        height = int(widget.get("height", 2))

                        # Clamp to 7.0 limits: x 0-35, width 1-36, height 2-32
                        if x + width > 36:
                            width = 36 - x
                        width  = max(1, min(width, 36))
                        height = max(2, min(height, 32))

                        clean_widget = {
                            "type":      widget["type"],
                            "name":      widget.get("name", ""),
                            "x":         x,
                            "y":         y,
                            "width":     width,
                            "height":    height,
                            "view_mode": int(widget.get("view_mode", 0)),
                        }

                        if "fields" in widget:
                            clean_widget["fields"] = self._filter_widget_fields(widget["fields"])

                        clean_page["widgets"].append(clean_widget)

                    clean_dashboard["pages"].append(clean_page)

            self.dest.call("dashboard.create", clean_dashboard)
            print(f"  Created dashboard: {dashboard['name']}")
            return True

        except Exception as e:
            print(f"  Failed to create dashboard: {e}")
            return False

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def migrate(self):
        """Main migration process"""
        print("\n" + "=" * 60)
        print("Zabbix Dashboard Migration")
        print("=" * 60 + "\n")

        try:
            src_ver = self.source.call("apiinfo.version")
            dst_ver = self.dest.call("apiinfo.version")
            print(f"Source Zabbix version:      {src_ver}")
            print(f"Destination Zabbix version: {dst_ver}\n")
        except Exception as e:
            print(f"Error checking versions: {e}")
            return

        try:
            dashboards = self.get_all_dashboards()
        except Exception as e:
            print(f"Error fetching dashboards: {e}")
            return

        if not dashboards:
            print("No dashboards found to migrate")
            return

        print("\nStarting migration...\n")

        for dashboard in dashboards:
            name = dashboard.get("name", "Unnamed")
            print(f"Processing: {name}")

            try:
                print("  - Converting IDs to names...")
                converted = self.resolve_object_names(dashboard)

                print("  - Resolving IDs in destination...")
                resolved = self.resolve_object_ids(converted)

                print("  - Creating dashboard...")
                if self.create_dashboard(resolved):
                    self.migrated_count += 1
                else:
                    self.failed_dashboards.append({"name": name, "reason": "Creation failed"})

            except MissingObjectsError as e:
                print(f"  Skipping -- missing objects in destination:")
                for obj in e.missing_objects:
                    print(f"    - {obj}")
                self.failed_dashboards.append({
                    "name":    name,
                    "reason":  "Missing objects in destination",
                    "details": e.missing_objects
                })

            except Exception as e:
                print(f"  Error: {e}")
                self.failed_dashboards.append({"name": name, "reason": str(e)})

            print()

        self._print_summary()

    def _print_summary(self):
        """Print migration summary"""
        print("\n" + "=" * 60)
        print("Migration Summary")
        print("=" * 60)
        print(f"Successfully migrated: {self.migrated_count}")
        print(f"Failed:                {len(self.failed_dashboards)}")

        if self.failed_dashboards:
            print("\nFailed Dashboards:")
            for f in self.failed_dashboards:
                print(f"\n  - {f['name']}")
                print(f"    Reason: {f['reason']}")
                if "details" in f:
                    print("    Missing objects (present in source, absent in destination):")
                    for d in f["details"]:
                        print(f"      - {d}")

        print("\n" + "=" * 60)
        print("Note: Objects already inaccessible in the source were")
        print("      silently skipped and are NOT counted as failures.")
        print("=" * 60)


class MissingObjectsError(Exception):
    """Raised when required objects are missing in the destination"""
    def __init__(self, missing_objects: List[str]):
        self.missing_objects = missing_objects
        super().__init__(f"Missing {len(missing_objects)} objects")


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Zabbix dashboards from 6.4 to 7.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example usage:
  python migrate_dashboards.py \\
    --source-url https://zabbix64.example.com \\
    --source-token abc123... \\
    --dest-url https://zabbix70.example.com \\
    --dest-token xyz789...
        """
    )
    parser.add_argument("--source-url",   required=True, help="Source Zabbix 6.4 URL")
    parser.add_argument("--source-token", required=True, help="Source Zabbix API token")
    parser.add_argument("--dest-url",     required=True, help="Destination Zabbix 7.0 URL")
    parser.add_argument("--dest-token",   required=True, help="Destination Zabbix API token")

    args = parser.parse_args()

    try:
        source_api = ZabbixAPI(args.source_url,  args.source_token)
        dest_api   = ZabbixAPI(args.dest_url,    args.dest_token)
        DashboardMigrator(source_api, dest_api).migrate()
    except Exception as e:
        print(f"\nFatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
