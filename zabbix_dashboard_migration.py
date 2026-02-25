#!/usr/bin/env python3
"""
Zabbix Dashboard Migration Script
Migrates dashboards from Zabbix 6.4 to Zabbix 7.0
"""

import json
import requests
import argparse
import sys
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin

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
            "auth": self.token if method != "apiinfo.version" else None
        }
        
        if method == "apiinfo.version":
            del payload["auth"]
        
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
        self.name_cache = {}
        self.id_cache = {}
        self.failed_dashboards = []
        self.migrated_count = 0
        
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
    
    def resolve_object_names(self, dashboard: Dict) -> Dict:
        """Convert IDs to names in dashboard definition"""
        converted = dashboard.copy()
        
        # Convert user IDs to usernames
        if "users" in dashboard:
            converted["users"] = []
            for user in dashboard["users"]:
                user_data = self.source.call("user.get", {
                    "userids": user["userid"],
                    "output": ["username"]
                })
                if user_data:
                    converted["users"].append({
                        "username": user_data[0]["username"],
                        "permission": user["permission"]
                    })
        
        # Convert user group IDs to names
        if "userGroups" in dashboard:
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                group_data = self.source.call("usergroup.get", {
                    "usrgrpids": group["usrgrpid"],
                    "output": ["name"]
                })
                if group_data:
                    converted["userGroups"].append({
                        "name": group_data[0]["name"],
                        "permission": group["permission"]
                    })
        
        # Process dashboard pages and widgets
        if "pages" in dashboard:
            converted["pages"] = []
            for page in dashboard["pages"]:
                converted_page = page.copy()
                
                if "widgets" in page:
                    converted_page["widgets"] = []
                    for widget in page["widgets"]:
                        try:
                            converted_widget = self.convert_widget_ids_to_names(widget)
                            converted_page["widgets"].append(converted_widget)
                        except Exception as e:
                            print(f"  Warning: Failed to convert widget: {e}")
                            raise
                
                converted["pages"].append(converted_page)
        
        return converted
    
    def convert_widget_ids_to_names(self, widget: Dict) -> Dict:
        """Convert widget field IDs to names"""
        converted = widget.copy()
        
        if "fields" in widget:
            converted["fields"] = []
            for field in widget["fields"]:
                converted_field = field.copy()
                
                # Field type reference:
                # 0 = Host, 1 = Tags, 2 = Item, 3 = Item prototype
                # 4 = Host group, 6 = Graph, 7 = Graph prototype
                
                field_type = str(field.get("type", ""))
                
                # Handle Tags (type 1) - special handling for Zabbix 7.0 compatibility
                if field_type == "1":
                    # Tags need special structure for Zabbix 7.0
                    if "value" in field:
                        try:
                            # Parse tag value as JSON
                            tag_data = json.loads(field["value"])
                            # Ensure proper structure with both 'tag' and 'value' keys
                            if isinstance(tag_data, dict):
                                if "tag" not in tag_data:
                                    tag_data["tag"] = ""
                                if "value" not in tag_data:
                                    tag_data["value"] = ""
                                converted_field["value"] = json.dumps(tag_data)
                        except (json.JSONDecodeError, TypeError):
                            # If not JSON or invalid, skip this field
                            pass
                
                # Handle Host group (type 4)
                elif field_type == "4":
                    if "value" in field:
                        group_data = self.source.call("hostgroup.get", {
                            "groupids": field["value"],
                            "output": ["name"]
                        })
                        if group_data:
                            converted_field["value_name"] = group_data[0]["name"]
                            # Keep original ID for reference
                            converted_field["original_id"] = field["value"]
                
                # Handle Host (type 0)
                elif field_type == "0":
                    if "value" in field:
                        host_data = self.source.call("host.get", {
                            "hostids": field["value"],
                            "output": ["host"]
                        })
                        if host_data:
                            converted_field["value_name"] = host_data[0]["host"]
                            converted_field["original_id"] = field["value"]
                
                # Handle Item (type 2)
                elif field_type == "2":
                    if "value" in field:
                        item_data = self.source.call("item.get", {
                            "itemids": field["value"],
                            "output": ["name", "key_"],
                            "selectHosts": ["host"]
                        })
                        if item_data:
                            converted_field["value_name"] = item_data[0]["key_"]
                            converted_field["host_name"] = item_data[0]["hosts"][0]["host"]
                            converted_field["original_id"] = field["value"]
                
                # Handle Graph (type 6)
                elif field_type == "6":
                    if "value" in field:
                        graph_data = self.source.call("graph.get", {
                            "graphids": field["value"],
                            "output": ["name"],
                            "selectHosts": ["host"]
                        })
                        if graph_data:
                            converted_field["value_name"] = graph_data[0]["name"]
                            if graph_data[0].get("hosts"):
                                converted_field["host_name"] = graph_data[0]["hosts"][0]["host"]
                            converted_field["original_id"] = field["value"]
                
                converted["fields"].append(converted_field)
        
        return converted
    
    def resolve_object_ids(self, dashboard: Dict) -> Tuple[Dict, List[str]]:
        """Convert names back to IDs in destination instance"""
        converted = dashboard.copy()
        missing_objects = []
        
        # Convert usernames to user IDs
        if "users" in dashboard:
            converted["users"] = []
            for user in dashboard["users"]:
                user_data = self.dest.call("user.get", {
                    "filter": {"username": user["username"]},
                    "output": ["userid"]
                })
                if user_data:
                    converted["users"].append({
                        "userid": user_data[0]["userid"],
                        "permission": user["permission"]
                    })
                else:
                    missing_objects.append(f"User: {user['username']}")
        
        # Convert user group names to IDs
        if "userGroups" in dashboard:
            converted["userGroups"] = []
            for group in dashboard["userGroups"]:
                group_data = self.dest.call("usergroup.get", {
                    "filter": {"name": group["name"]},
                    "output": ["usrgrpid"]
                })
                if group_data:
                    converted["userGroups"].append({
                        "usrgrpid": group_data[0]["usrgrpid"],
                        "permission": group["permission"]
                    })
                else:
                    missing_objects.append(f"User group: {group['name']}")
        
        # Process dashboard pages and widgets
        if "pages" in dashboard:
            converted["pages"] = []
            for page in dashboard["pages"]:
                converted_page = page.copy()
                
                if "widgets" in page:
                    converted_page["widgets"] = []
                    for widget in page["widgets"]:
                        converted_widget, widget_missing = self.convert_widget_names_to_ids(widget)
                        if widget_missing:
                            missing_objects.extend(widget_missing)
                        else:
                            converted_page["widgets"].append(converted_widget)
                
                converted["pages"].append(converted_page)
        
        return converted, missing_objects
    
    def convert_widget_names_to_ids(self, widget: Dict) -> Tuple[Dict, List[str]]:
        """Convert widget field names to IDs"""
        converted = widget.copy()
        missing_objects = []
        
        if "fields" in widget:
            converted["fields"] = []
            for field in widget["fields"]:
                converted_field = field.copy()
                field_type = str(field.get("type", ""))
                
                # Skip fields that don't need conversion (like tags - type 1)
                if field_type == "1":
                    # Tags - already handled in conversion to names
                    converted["fields"].append(converted_field)
                    continue
                
                # Only process fields that have value_name (need conversion)
                if "value_name" not in field:
                    # No conversion needed, keep as is
                    converted["fields"].append(converted_field)
                    continue
                
                # Handle Host group (type 4)
                if field_type == "4":
                    group_data = self.dest.call("hostgroup.get", {
                        "filter": {"name": field["value_name"]},
                        "output": ["groupid"]
                    })
                    if group_data:
                        converted_field["value"] = group_data[0]["groupid"]
                        # Clean up temporary fields
                        converted_field.pop("value_name", None)
                        converted_field.pop("original_id", None)
                        converted["fields"].append(converted_field)
                    else:
                        missing_objects.append(f"Host group: {field['value_name']}")
                
                # Handle Host (type 0)
                elif field_type == "0":
                    host_data = self.dest.call("host.get", {
                        "filter": {"host": field["value_name"]},
                        "output": ["hostid"]
                    })
                    if host_data:
                        converted_field["value"] = host_data[0]["hostid"]
                        converted_field.pop("value_name", None)
                        converted_field.pop("original_id", None)
                        converted["fields"].append(converted_field)
                    else:
                        missing_objects.append(f"Host: {field['value_name']}")
                
                # Handle Item (type 2)
                elif field_type == "2":
                    if "host_name" in field:
                        item_data = self.dest.call("item.get", {
                            "filter": {"key_": field["value_name"]},
                            "host": field["host_name"],
                            "output": ["itemid"]
                        })
                        if item_data:
                            converted_field["value"] = item_data[0]["itemid"]
                            converted_field.pop("value_name", None)
                            converted_field.pop("host_name", None)
                            converted_field.pop("original_id", None)
                            converted["fields"].append(converted_field)
                        else:
                            missing_objects.append(f"Item: {field['value_name']} on host {field['host_name']}")
                
                # Handle Graph (type 6)
                elif field_type == "6":
                    if "host_name" in field:
                        # Get host first
                        host_data = self.dest.call("host.get", {
                            "filter": {"host": field["host_name"]},
                            "output": ["hostid"]
                        })
                        if host_data:
                            graph_data = self.dest.call("graph.get", {
                                "filter": {"name": field["value_name"]},
                                "hostids": host_data[0]["hostid"],
                                "output": ["graphid"]
                            })
                            if graph_data:
                                converted_field["value"] = graph_data[0]["graphid"]
                                converted_field.pop("value_name", None)
                                converted_field.pop("host_name", None)
                                converted_field.pop("original_id", None)
                                converted["fields"].append(converted_field)
                            else:
                                missing_objects.append(f"Graph: {field['value_name']} on host {field['host_name']}")
                        else:
                            missing_objects.append(f"Host: {field['host_name']}")
                    else:
                        # Graph without host reference
                        converted_field.pop("value_name", None)
                        converted_field.pop("original_id", None)
                        converted["fields"].append(converted_field)
                
                else:
                    # Unknown type, keep as is
                    converted_field.pop("value_name", None)
                    converted_field.pop("original_id", None)
                    converted["fields"].append(converted_field)
        
        return converted, missing_objects
    
    def create_dashboard(self, dashboard: Dict) -> bool:
        """Create dashboard in destination instance"""
        try:
            # Remove source-specific fields
            clean_dashboard = {
                "name": dashboard["name"],
                "display_period": dashboard.get("display_period", "30"),
                "auto_start": dashboard.get("auto_start", "1")
            }
            
            # Add permissions if present
            if "users" in dashboard and dashboard["users"]:
                clean_dashboard["users"] = dashboard["users"]
            
            if "userGroups" in dashboard and dashboard["userGroups"]:
                clean_dashboard["userGroups"] = dashboard["userGroups"]
            
            # Add pages
            if "pages" in dashboard:
                clean_dashboard["pages"] = []
                for page in dashboard["pages"]:
                    clean_page = {
                        "name": page.get("name", ""),
                        "display_period": page.get("display_period", "0"),
                        "widgets": []
                    }
                    
                    # Add widgets
                    if "widgets" in page:
                        for widget in page["widgets"]:
                            clean_widget = {
                                "type": widget["type"],
                                "name": widget.get("name", ""),
                                "x": widget.get("x", "0"),
                                "y": widget.get("y", "0"),
                                "width": widget.get("width", "1"),
                                "height": widget.get("height", "1"),
                                "view_mode": widget.get("view_mode", "0")
                            }
                            
                            if "fields" in widget:
                                clean_widget["fields"] = widget["fields"]
                            
                            clean_page["widgets"].append(clean_widget)
                    
                    clean_dashboard["pages"].append(clean_page)
            
            # Create dashboard
            result = self.dest.call("dashboard.create", clean_dashboard)
            print(f"  ✓ Created dashboard: {dashboard['name']}")
            return True
            
        except Exception as e:
            print(f"  ✗ Failed to create dashboard: {e}")
            return False
    
    def migrate(self):
        """Main migration process"""
        print("\n" + "="*60)
        print("Zabbix Dashboard Migration")
        print("="*60 + "\n")
        
        # Check API versions
        try:
            source_version = self.source.call("apiinfo.version")
            dest_version = self.dest.call("apiinfo.version")
            print(f"Source Zabbix version: {source_version}")
            print(f"Destination Zabbix version: {dest_version}\n")
        except Exception as e:
            print(f"Error checking versions: {e}")
            return
        
        # Get all dashboards
        try:
            dashboards = self.get_all_dashboards()
        except Exception as e:
            print(f"Error fetching dashboards: {e}")
            return
        
        if not dashboards:
            print("No dashboards found to migrate")
            return
        
        print("\nStarting migration...\n")
        
        # Migrate each dashboard
        for dashboard in dashboards:
            dashboard_name = dashboard.get("name", "Unnamed")
            print(f"Processing: {dashboard_name}")
            
            try:
                # Convert IDs to names
                print("  - Converting IDs to names...")
                converted_dashboard = self.resolve_object_names(dashboard)
                
                # Convert names to IDs in destination
                print("  - Resolving IDs in destination...")
                resolved_dashboard, missing_objects = self.resolve_object_ids(converted_dashboard)
                
                if missing_objects:
                    print(f"  ✗ Skipping - Missing objects:")
                    for obj in missing_objects:
                        print(f"    - {obj}")
                    self.failed_dashboards.append({
                        "name": dashboard_name,
                        "reason": "Missing objects",
                        "details": missing_objects
                    })
                else:
                    # Create dashboard
                    print("  - Creating dashboard...")
                    if self.create_dashboard(resolved_dashboard):
                        self.migrated_count += 1
                    else:
                        self.failed_dashboards.append({
                            "name": dashboard_name,
                            "reason": "Creation failed"
                        })
            
            except Exception as e:
                print(f"  ✗ Error: {e}")
                self.failed_dashboards.append({
                    "name": dashboard_name,
                    "reason": str(e)
                })
            
            print()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print migration summary"""
        print("\n" + "="*60)
        print("Migration Summary")
        print("="*60)
        print(f"Successfully migrated: {self.migrated_count}")
        print(f"Failed: {len(self.failed_dashboards)}")
        
        if self.failed_dashboards:
            print("\nFailed Dashboards:")
            for failed in self.failed_dashboards:
                print(f"\n  • {failed['name']}")
                print(f"    Reason: {failed['reason']}")
                if "details" in failed:
                    print("    Missing objects:")
                    for detail in failed["details"]:
                        print(f"      - {detail}")
        
        print("\n" + "="*60)

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
    
    parser.add_argument("--source-url", required=True, 
                       help="Source Zabbix 6.4 URL")
    parser.add_argument("--source-token", required=True,
                       help="Source Zabbix API token")
    parser.add_argument("--dest-url", required=True,
                       help="Destination Zabbix 7.0 URL")
    parser.add_argument("--dest-token", required=True,
                       help="Destination Zabbix API token")
    
    args = parser.parse_args()
    
    try:
        # Initialize API connections
        source_api = ZabbixAPI(args.source_url, args.source_token)
        dest_api = ZabbixAPI(args.dest_url, args.dest_token)
        
        # Run migration
        migrator = DashboardMigrator(source_api, dest_api)
        migrator.migrate()
        
    except Exception as e:
        print(f"\nFatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
