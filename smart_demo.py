#!/usr/bin/env python3
"""
Smart Network Experts - Focused and Effective Agents
Author: Ionut-Valentin Baltag (Certified Ethical Hacker)
"""
import asyncio
import json
import os
import subprocess
import socket
import ipaddress
from typing import Dict, Any, List
from datetime import datetime

from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class SmartNetworkScanner(BaseHandler):
    """Simple, focused network scanner - does ONE thing well"""
    
    @tool
    async def scan_network(self, *, network: str = "192.168.1.0/24") -> Dict:
        """
        Scan network for active devices using ping sweep.
        
        Args:
            network: Network CIDR to scan (e.g., "192.168.1.0/24")
            
        Returns:
            Dict with discovered devices and their basic info
        """
        print(f"🔍 Scanning network: {network}")
        
        try:
            # Parse network
            net = ipaddress.IPv4Network(network, strict=False)
            active_devices = []
            
            # Quick ping sweep (first 20 IPs for demo)
            for i, ip in enumerate(net.hosts()):
                if i >= 20:  # Limit for demo
                    break
                    
                # Quick ping test
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', str(ip)],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.returncode == 0:
                    device_info = {
                        "ip": str(ip),
                        "status": "active",
                        "response_time": "< 1s",
                        "hostname": self._get_hostname(str(ip))
                    }
                    active_devices.append(device_info)
                    print(f"✅ Found: {ip}")
            
            return {
                "network": network,
                "scan_time": datetime.now().isoformat(),
                "total_scanned": min(20, len(list(net.hosts()))),
                "active_devices": active_devices,
                "device_count": len(active_devices)
            }
            
        except Exception as e:
            return {
                "error": f"Scan failed: {str(e)}",
                "network": network,
                "active_devices": []
            }
    
    def _get_hostname(self, ip: str) -> str:
        """Try to get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "unknown"


class SmartPortScanner(BaseHandler):
    """Focused port scanner - finds open services"""
    
    @tool
    async def scan_ports(self, *, target: str, ports: str = "22,80,443,21,25,53") -> Dict:
        """
        Scan common ports on target device.
        
        Args:
            target: Target IP address to scan
            ports: Comma-separated list of ports or ranges (default: common ports)
            
        Returns:
            Dict with open ports and services
        """
        print(f"🔍 Scanning ports on: {target}")
        
        try:
            port_list = self._parse_ports(ports)
            open_ports = []
            
            for port in port_list:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                try:
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        service = self._identify_service(port)
                        open_ports.append({
                            "port": port,
                            "service": service,
                            "status": "open"
                        })
                        print(f"✅ Port {port} ({service}) is open")
                except:
                    pass
                finally:
                    sock.close()
            
            return {
                "target": target,
                "scan_time": datetime.now().isoformat(),
                "open_ports": open_ports,
                "total_open": len(open_ports)
            }
            
        except Exception as e:
            return {
                "error": f"Port scan failed: {str(e)}",
                "target": target,
                "open_ports": []
            }
    
    def _identify_service(self, port: int) -> str:
        """Identify common services by port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL"
        }
        return services.get(port, f"Unknown-{port}")
    
    def _parse_ports(self, ports: str) -> List[int]:
        """Parse port string that can contain ranges and individual ports"""
        port_list = []
        
        for port_item in ports.split(','):
            port_item = port_item.strip()
            
            if '-' in port_item:
                # Handle port range like "1-1000"
                try:
                    start, end = port_item.split('-')
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    # Limit range to avoid huge scans
                    if end_port - start_port > 100:
                        end_port = start_port + 100
                    
                    port_list.extend(range(start_port, end_port + 1))
                except ValueError:
                    # If range parsing fails, skip this item
                    continue
            else:
                # Handle single port
                try:
                    port_list.append(int(port_item))
                except ValueError:
                    # If single port parsing fails, skip
                    continue
        
        return port_list


class SmartNodeREDGenerator(BaseHandler):
    """Generates Node-RED flows for network monitoring"""
    
    @tool
    async def create_monitoring_flow(self, *, devices: str, flow_type: str = "ping_monitor") -> Dict:
        """
        Create Node-RED flow for monitoring discovered devices.
        
        Args:
            devices: JSON string of devices to monitor
            flow_type: Type of flow - "ping_monitor", "port_monitor", "alert_system"
            
        Returns:
            Dict with Node-RED flow JSON
        """
        print(f"🔧 Creating Node-RED {flow_type} flow")
        
        try:
            device_list = json.loads(devices) if isinstance(devices, str) else devices
            
            if flow_type == "ping_monitor":
                flow = self._create_ping_monitoring_flow(device_list)
            else:
                flow = self._create_ping_monitoring_flow(device_list)  # Default to ping monitoring
            
            return {
                "flow_type": flow_type,
                "device_count": len(device_list) if isinstance(device_list, list) else 1,
                "created_time": datetime.now().isoformat(),
                "node_red_flow": flow,
                "installation_notes": "Import this JSON into Node-RED to start monitoring"
            }
            
        except Exception as e:
            return {
                "error": f"Flow creation failed: {str(e)}",
                "flow_type": flow_type
            }
    
    def _create_ping_monitoring_flow(self, devices: List[Dict]) -> List[Dict]:
        """Create a simple ping monitoring flow"""
        nodes = []
        
        # Inject node to trigger monitoring
        nodes.append({
            "id": "inject1",
            "type": "inject",
            "name": "Start Monitor",
            "topic": "",
            "payload": "",
            "payloadType": "date",
            "repeat": "60",  # Every minute
            "crontab": "",
            "once": True,
            "x": 100,
            "y": 100,
            "wires": [["ping_all"]]
        })
        
        # Function to ping all devices
        ping_code = f"""
var devices = {json.dumps([d.get('ip', '192.168.1.1') for d in devices[:5]])};
var results = [];

devices.forEach(function(ip) {{
    msg.payload = ip;
    node.send(msg);
}});
"""
        
        nodes.append({
            "id": "ping_all",
            "type": "function",
            "name": "Ping All Devices",
            "func": ping_code,
            "outputs": 1,
            "x": 300,
            "y": 100,
            "wires": [["ping_exec"]]
        })
        
        # Ping execution node
        nodes.append({
            "id": "ping_exec",
            "type": "exec",
            "name": "Execute Ping",
            "command": "ping -c 1",
            "addpay": True,
            "append": "",
            "useSpawn": "false",
            "timer": "",
            "oldrc": "false",
            "x": 500,
            "y": 100,
            "wires": [["result_debug"], [], []]
        })
        
        # Debug output
        nodes.append({
            "id": "result_debug",
            "type": "debug",
            "name": "Ping Results",
            "active": True,
            "tosidebar": True,
            "console": False,
            "tostatus": False,
            "complete": "true",
            "x": 700,
            "y": 100,
            "wires": []
        })
        
        return nodes


class SmartNetworkExperts:
    """Simplified, focused network expert team"""
    
    def __init__(self):
        # Proper LLM configuration like in main.py
        llm_config = {
            "model": "gpt-4o-mini",  # Using cost-effective model
            "llm_type": "openai"
        }
        self.llm_client = LLMClient(llm_config=llm_config)
        self.prompt_template = PromptTemplate()
        
        # Create focused agents
        self.scanner_agent = self._create_scanner_agent()
        self.security_agent = self._create_security_agent()
        self.flow_agent = self._create_flow_agent()
    
    def _create_scanner_agent(self) -> Agent:
        """Create network scanner agent"""
        scanner_engine = Engine(
            handler=SmartNetworkScanner(),
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        return Agent(
            name="NetScanner",
            goal="Perform comprehensive network discovery and analysis, delivering a structured report of active devices and network layout.",
            role="You are an expert Network Reconnaissance Specialist. Your primary function is to meticulously map network infrastructures. Identify all active devices, attempt to determine their hostnames, and provide a clear, concise summary of the network topology, highlighting any critical devices like routers or servers. Use the scan_network tool effectively.",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[scanner_engine],
            description="Expert network scanner that intelligently discovers devices and analyzes network infrastructure"
        )
    
    def _create_security_agent(self) -> Agent:
        """Create security scanner agent"""
        security_engine = Engine(
            handler=SmartPortScanner(),
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        return Agent(
            name="SecScanner",
            goal="Assess the security posture of target devices by identifying open services and potential vulnerabilities, and offer remediation advice.",
            role="You are a diligent Cybersecurity Analyst specializing in vulnerability identification. Given a target IP address, your mission is to perform detailed port scanning using the scan_ports tool, identify all running services, and analyze these services for known vulnerabilities or common misconfigurations. Provide a report with actionable security recommendations.",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[security_engine],
            description="Expert security analyst that intelligently scans for vulnerabilities and provides security recommendations"
        )
    
    def _create_flow_agent(self) -> Agent:
        """Create Node-RED flow generator agent"""
        flow_engine = Engine(
            handler=SmartNodeREDGenerator(),
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        return Agent(
            name="FlowBuilder",
            goal="Generate functional Node-RED JSON flows for network device monitoring and alerting.",
            role="You are a Node-RED Automation Expert. Your expertise lies in designing and generating robust, efficient Node-RED flows for network monitoring and alerting using the create_monitoring_flow tool. Based on the provided list of network devices, create a suitable monitoring flow.",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[flow_engine],
            description="I create Node-RED flows to automate network monitoring and alerting"
        )
    
    async def smart_assessment(self, network: str = "192.168.1.0/24") -> Dict[str, Any]:
        """
        Perform smart, focused network assessment
        """
        print("🧠 Smart Network Experts - Starting Focused Assessment")
        print("=" * 60)
        print(f"🎯 Target: {network}")
        print(f"👤 Lead: Ionut-Valentin Baltag (Certified Ethical Hacker)")
        print("🤖 Smart Agents: NetScanner, SecScanner, FlowBuilder")
        print("=" * 60)
        
        results = {
            "network": network,
            "assessment_type": "Smart & Focused",
            "lead": "Ionut-Valentin Baltag",
            "timestamp": datetime.now().isoformat(),
            "device_discovery_data": {},
            "device_discovery_analysis": "Not performed.",
            "security_scan_data": {},
            "security_scan_analysis": "Not performed.",
            "node_red_flow_data": {},
            "node_red_flow_analysis": "Not performed."
        }
        
        devices_data = {} # To store the structured data from NetScanner

        try:
            # Step 1: Quick network discovery
            print("\n🔍 NetScanner - Discovering devices...")
            scanner_query = f"Conduct a thorough reconnaissance of the network {network}. Identify all active hosts, their details, and summarize the overall network structure."
            scan_result = await self.scanner_agent.execute(query_instruction=scanner_query)
            
            if scan_result:
                devices_data = scan_result.result if hasattr(scan_result, 'result') and scan_result.result is not None else {}
                devices_analysis = scan_result.reason if hasattr(scan_result, 'reason') and scan_result.reason else "No analysis provided by NetScanner."
                results["device_discovery_data"] = json.dumps(devices_data) if not isinstance(devices_data, str) else devices_data
                results["device_discovery_analysis"] = devices_analysis
                print(f"🧠 NetScanner Analysis: {devices_analysis}")
            else:
                results["device_discovery_analysis"] = "NetScanner execution failed to return a result."

            # Step 2: Security check on first active device
            active_devices_list = devices_data.get('active_devices', []) if isinstance(devices_data, dict) else []
            if active_devices_list:
                first_device_ip = active_devices_list[0].get('ip')
                if first_device_ip:
                    print(f"\n🔒 SecScanner - Checking security on {first_device_ip}...")
                    security_query = f"Perform a detailed security assessment of the device at {first_device_ip}. Identify all open ports, the services running on them, and report any potential security risks or vulnerabilities. Provide recommendations if possible."
                    security_result = await self.security_agent.execute(query_instruction=security_query)
                    
                    if security_result:
                        sec_scan_data = security_result.result if hasattr(security_result, 'result') and security_result.result is not None else {}
                        sec_scan_analysis = security_result.reason if hasattr(security_result, 'reason') and security_result.reason else "No analysis provided by SecScanner."
                        results["security_scan_data"] = json.dumps(sec_scan_data) if not isinstance(sec_scan_data, str) else sec_scan_data
                        results["security_scan_analysis"] = sec_scan_analysis
                        print(f"🧠 SecScanner Analysis: {sec_scan_analysis}")
                    else:
                        results["security_scan_analysis"] = "SecScanner execution failed to return a result."
            else:
                results["security_scan_analysis"] = "No active devices found by NetScanner to perform security scan."

            # Step 3: Create monitoring flow
            if active_devices_list:
                # Create a simple, safe string representation instead of JSON
                device_descriptions = []
                for d in active_devices_list:
                    if d.get('ip'):
                        hostname = d.get('hostname', 'unknown')
                        device_descriptions.append(f"IP: {d['ip']} (hostname: {hostname})")
                
                device_info = " | ".join(device_descriptions)
                
                print("\n🔧 FlowBuilder - Creating Node-RED monitoring flow...")
                flow_query = f"Design and generate a Node-RED ping monitoring flow for these network devices: {device_info}. Create a robust monitoring setup that pings each device regularly and provides status updates."
                flow_result = await self.flow_agent.execute(query_instruction=flow_query)
                
                if flow_result:
                    node_red_flow_data = flow_result.result if hasattr(flow_result, 'result') and flow_result.result is not None else {}
                    node_red_flow_analysis = flow_result.reason if hasattr(flow_result, 'reason') and flow_result.reason else "No analysis provided by FlowBuilder."
                    # The result from FlowBuilder should be the Node-RED JSON flow itself
                    results["node_red_flow_data"] = json.dumps(node_red_flow_data) if isinstance(node_red_flow_data, (dict, list)) else str(node_red_flow_data)
                    results["node_red_flow_analysis"] = node_red_flow_analysis
                    print(f"🧠 FlowBuilder Analysis: {node_red_flow_analysis}")
                else:
                    results["node_red_flow_analysis"] = "FlowBuilder execution failed to return a result."
            else:
                results["node_red_flow_analysis"] = "No active devices to create a monitoring flow for."
            
            # Summary
            device_count = len(active_devices_list)
            print(f"\n✅ Assessment Complete!")
            print(f"📊 Found {device_count} active devices")
            if results.get("node_red_flow_data") and results["node_red_flow_data"] != '{}':
                 print(f"🔧 Generated Node-RED monitoring flows")
            
            return results
            
        except Exception as e:
            print(f"❌ Assessment failed: {type(e).__name__}: {e}") # Print type of exception
            results["error"] = f"{type(e).__name__}: {str(e)}"
            import traceback
            results["traceback"] = traceback.format_exc() # Add traceback for better debugging
            return results


async def main():
    """Run the smart network assessment demo"""
    # Check for OpenAI API key
    if not os.getenv('OPENAI_API_KEY'):
        print("❌ Please set OPENAI_API_KEY environment variable")
        return
    
    # Create smart team
    experts = SmartNetworkExperts()
    
    # Run assessment
    results = await experts.smart_assessment("192.168.1.0/24")
    
    # Show results
    print("\n" + "="*60)
    print("📋 SMART ASSESSMENT RESULTS")
    print("="*60)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
