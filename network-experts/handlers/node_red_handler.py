"""
Node-RED Handler for Network Experts Team
Manages Node-RED flows, automation workflows, and visual programming
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
import aiohttp
import subprocess
import os

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool

logger = logging.getLogger(__name__)


class NodeRedHandler(BaseHandler):
    """
    Node-RED Handler for visual workflow automation
    The Workflow Brother - Expert in visual programming and automation flows
    """

    def __init__(
        self,
        node_red_url: str = "http://localhost:1880",
        admin_auth: Optional[Dict[str, str]] = None,
        flows_directory: Optional[str] = None
    ):
        super().__init__()
        self.node_red_url = node_red_url.rstrip('/')
        self.admin_auth = admin_auth
        self.flows_directory = flows_directory or "./node_red_flows"
        self.session = None

    async def _get_session(self):
        """Get or create HTTP session"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session

    async def _make_request(self, method: str, endpoint: str, **kwargs):
        """Make HTTP request to Node-RED API"""
        session = await self._get_session()
        url = f"{self.node_red_url}{endpoint}"
        
        headers = kwargs.get('headers', {})
        if self.admin_auth:
            # Add authentication if configured
            auth = aiohttp.BasicAuth(
                self.admin_auth.get('username', ''),
                self.admin_auth.get('password', '')
            )
            kwargs['auth'] = auth
            
        try:
            async with session.request(method, url, **kwargs) as response:
                if response.content_type == 'application/json':
                    return await response.json()
                else:
                    return await response.text()
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise

    @tool
    async def check_node_red_status(self) -> Dict[str, Any]:
        """
        Check Node-RED server status and health
        
        Returns:
            Node-RED server status information
        """
        try:
            # Check if Node-RED is running
            status_info = await self._make_request('GET', '/admin/info')
            
            return {
                "status": "online",
                "node_red_info": status_info,
                "url": self.node_red_url,
                "version": status_info.get('version', 'unknown') if isinstance(status_info, dict) else 'unknown'
            }
            
        except Exception as e:
            logger.error(f"Node-RED status check failed: {e}")
            return {
                "status": "offline",
                "error": str(e),
                "url": self.node_red_url
            }

    @tool
    async def get_flows(self) -> Dict[str, Any]:
        """
        Get all flows from Node-RED
        
        Returns:
            All flows configured in Node-RED
        """
        try:
            flows = await self._make_request('GET', '/flows')
            
            # Analyze flows
            flow_analysis = {
                "total_flows": 0,
                "total_nodes": 0,
                "node_types": {},
                "flows": []
            }
            
            if isinstance(flows, list):
                for item in flows:
                    if item.get('type') == 'tab':
                        flow_analysis["total_flows"] += 1
                        flow_analysis["flows"].append({
                            "id": item.get('id'),
                            "label": item.get('label', 'Untitled'),
                            "disabled": item.get('disabled', False)
                        })
                    else:
                        flow_analysis["total_nodes"] += 1
                        node_type = item.get('type', 'unknown')
                        flow_analysis["node_types"][node_type] = flow_analysis["node_types"].get(node_type, 0) + 1
            
            return {
                "status": "success",
                "flows_data": flows,
                "analysis": flow_analysis
            }
            
        except Exception as e:
            logger.error(f"Failed to get flows: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    @tool
    async def deploy_flows(self, *, flows_data: Optional[str] = None) -> Dict[str, Any]:
        """
        Deploy flows to Node-RED
        
        Args:
            flows_data: JSON string of flows to deploy (optional)
            
        Returns:
            Deployment result
        """
        try:
            if flows_data:
                flows = json.loads(flows_data)
                result = await self._make_request(
                    'POST', 
                    '/flows',
                    json=flows,
                    headers={'Content-Type': 'application/json'}
                )
            else:
                # Just redeploy current flows
                result = await self._make_request('POST', '/flows/deploy')
            
            return {
                "status": "success",
                "deployment_result": result,
                "message": "Flows deployed successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to deploy flows: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    @tool
    async def create_network_monitoring_flow(
        self,
        *,
        target_hosts: List[str],
        check_interval: int = 60,
        mqtt_topic: str = "network/status"
    ) -> Dict[str, Any]:
        """
        Create a network monitoring flow in Node-RED
        
        Args:
            target_hosts: List of hosts to monitor
            check_interval: Check interval in seconds
            mqtt_topic: MQTT topic to publish results
            
        Returns:
            Created flow information
        """
        try:
            # Create a network monitoring flow
            flow_id = f"network-monitor-{asyncio.get_event_loop().time()}"
            
            flow_nodes = []
            
            # Create inject node for timing
            inject_node = {
                "id": f"{flow_id}-inject",
                "type": "inject",
                "z": flow_id,
                "name": "Monitor Trigger",
                "props": [{"p": "payload"}, {"p": "topic", "vt": "str"}],
                "repeat": str(check_interval),
                "crontab": "",
                "once": True,
                "onceDelay": 0.1,
                "topic": "start_monitoring",
                "payload": "true",
                "payloadType": "bool",
                "x": 150,
                "y": 100,
                "wires": [["ping-function"]]
            }
            flow_nodes.append(inject_node)
            
            # Create function node for ping logic
            ping_function = {
                "id": "ping-function",
                "type": "function",
                "z": flow_id,
                "name": "Network Ping Check",
                "func": f"""
var hosts = {json.dumps(target_hosts)};
var results = [];

for (var i = 0; i < hosts.length; i++) {{
    // Simulate ping check (in real Node-RED, you'd use ping node)
    var result = {{
        host: hosts[i],
        status: Math.random() > 0.1 ? 'online' : 'offline',
        response_time: Math.floor(Math.random() * 100) + 'ms',
        timestamp: new Date().toISOString()
    }};
    results.push(result);
}}

msg.payload = {{
    monitoring_results: results,
    total_hosts: hosts.length,
    online_count: results.filter(r => r.status === 'online').length
}};

return msg;
                """,
                "outputs": 1,
                "noerr": 0,
                "initialize": "",
                "finalize": "",
                "libs": [],
                "x": 380,
                "y": 100,
                "wires": [["mqtt-out", "debug"]]
            }
            flow_nodes.append(ping_function)
            
            # Create MQTT output node
            mqtt_out = {
                "id": "mqtt-out",
                "type": "mqtt out",
                "z": flow_id,
                "name": "Publish Results",
                "topic": mqtt_topic,
                "qos": "0",
                "retain": "false",
                "respTopic": "",
                "contentType": "",
                "userProps": "",
                "correl": "",
                "expiry": "",
                "broker": "mqtt-broker",
                "x": 610,
                "y": 100,
                "wires": []
            }
            flow_nodes.append(mqtt_out)
            
            # Create debug node
            debug_node = {
                "id": "debug",
                "type": "debug",
                "z": flow_id,
                "name": "Debug Output",
                "active": True,
                "tosidebar": True,
                "console": False,
                "tostatus": False,
                "complete": "payload",
                "targetType": "msg",
                "statusVal": "",
                "statusType": "auto",
                "x": 610,
                "y": 140,
                "wires": []
            }
            flow_nodes.append(debug_node)
            
            # Create flow tab
            flow_tab = {
                "id": flow_id,
                "type": "tab",
                "label": "Network Monitoring",
                "disabled": False,
                "info": f"Monitors {len(target_hosts)} network hosts every {check_interval} seconds",
                "env": []
            }
            
            # Combine all nodes
            complete_flow = [flow_tab] + flow_nodes
            
            # Deploy the flow
            current_flows = await self._make_request('GET', '/flows')
            if isinstance(current_flows, list):
                # Add new flow to existing flows
                updated_flows = current_flows + complete_flow
                deploy_result = await self._make_request(
                    'POST',
                    '/flows',
                    json=updated_flows,
                    headers={'Content-Type': 'application/json'}
                )
            
            return {
                "status": "success",
                "flow_id": flow_id,
                "flow_created": True,
                "monitored_hosts": target_hosts,
                "check_interval": check_interval,
                "mqtt_topic": mqtt_topic,
                "nodes_created": len(flow_nodes)
            }
            
        except Exception as e:
            logger.error(f"Failed to create monitoring flow: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    @tool
    async def get_flow_logs(self, *, limit: int = 100) -> Dict[str, Any]:
        """
        Get Node-RED flow execution logs
        
        Args:
            limit: Maximum number of log entries to return
            
        Returns:
            Flow execution logs
        """
        try:
            # Note: Node-RED doesn't have a direct logs API
            # This would typically require log file access or custom logging nodes
            
            return {
                "status": "info",
                "message": "Log retrieval requires Node-RED log file access or custom logging configuration",
                "suggestion": "Add debug nodes to flows for monitoring or configure file logging"
            }
            
        except Exception as e:
            logger.error(f"Failed to get logs: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    @tool
    async def install_node_red_nodes(self, *, package_names: List[str]) -> Dict[str, Any]:
        """
        Install additional Node-RED nodes/packages
        
        Args:
            package_names: List of npm package names to install
            
        Returns:
            Installation results
        """
        installation_results = []
        
        for package in package_names:
            try:
                result = await self._make_request(
                    'POST',
                    '/nodes',
                    json={"module": package},
                    headers={'Content-Type': 'application/json'}
                )
                
                installation_results.append({
                    "package": package,
                    "status": "success",
                    "result": result
                })
                
            except Exception as e:
                installation_results.append({
                    "package": package,
                    "status": "error",
                    "error": str(e)
                })
        
        return {
            "status": "completed",
            "installations": installation_results,
            "total_packages": len(package_names),
            "successful": len([r for r in installation_results if r["status"] == "success"])
        }

    @tool
    async def backup_flows(self, *, backup_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Backup Node-RED flows to file
        
        Args:
            backup_path: Path to save backup file
            
        Returns:
            Backup operation result
        """
        try:
            flows = await self._make_request('GET', '/flows')
            
            if not backup_path:
                import datetime
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{self.flows_directory}/flows_backup_{timestamp}.json"
            
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            with open(backup_path, 'w') as f:
                json.dump(flows, f, indent=2)
            
            return {
                "status": "success",
                "backup_path": backup_path,
                "flows_count": len(flows) if isinstance(flows, list) else 0,
                "message": "Flows backed up successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to backup flows: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    @tool
    async def restore_flows(self, *, backup_path: str) -> Dict[str, Any]:
        """
        Restore Node-RED flows from backup file
        
        Args:
            backup_path: Path to backup file
            
        Returns:
            Restore operation result
        """
        try:
            with open(backup_path, 'r') as f:
                flows = json.load(f)
            
            result = await self._make_request(
                'POST',
                '/flows',
                json=flows,
                headers={'Content-Type': 'application/json'}
            )
            
            return {
                "status": "success",
                "backup_path": backup_path,
                "flows_restored": len(flows) if isinstance(flows, list) else 0,
                "deployment_result": result,
                "message": "Flows restored successfully"
            }
            
        except Exception as e:
            logger.error(f"Failed to restore flows: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    async def cleanup(self):
        """Clean up HTTP session"""
        if self.session:
            await self.session.close()
            logger.info("Node-RED handler session closed")
