#!/usr/bin/env python3
"""
Offline Network Experts - No LLM Required
Testing core network scanning functionality
"""
import asyncio
import json
import subprocess
import socket
import ipaddress
from typing import Dict, Any, List
from datetime import datetime


class OfflineNetworkScanner:
    """Direct network scanner without LLM"""
    
    async def scan_network(self, network: str = "192.168.1.0/24") -> Dict:
        """Scan network for active devices"""
        print(f"🔍 Scanning network: {network}")
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            active_devices = []
            
            # Quick ping sweep (first 10 IPs for demo)
            for i, ip in enumerate(net.hosts()):
                if i >= 10:  # Limit for demo
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
                "total_scanned": min(10, len(list(net.hosts()))),
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


class OfflinePortScanner:
    """Direct port scanner without LLM"""
    
    async def scan_ports(self, target: str, ports: str = "22,80,443,21,25,53") -> Dict:
        """Scan ports on target device"""
        print(f"🔍 Scanning ports on: {target}")
        
        try:
            port_list = [int(p.strip()) for p in ports.split(',')]
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


class OfflineNodeREDGenerator:
    """Generate Node-RED flows without LLM"""
    
    def create_monitoring_flow(self, devices: List[Dict]) -> Dict:
        """Create Node-RED flow for monitoring"""
        print(f"🔧 Creating Node-RED monitoring flow for {len(devices)} devices")
        
        nodes = []
        
        # Inject node
        nodes.append({
            "id": "inject1",
            "type": "inject",
            "name": "Start Monitor",
            "topic": "",
            "payload": "",
            "payloadType": "date",
            "repeat": "60",
            "crontab": "",
            "once": True,
            "x": 100,
            "y": 100,
            "wires": [["ping_all"]]
        })
        
        # Function to ping devices
        device_ips = [d.get('ip', '192.168.1.1') for d in devices[:5]]
        ping_code = f"""
var devices = {json.dumps(device_ips)};
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
        
        # Ping execution
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
        
        return {
            "flow_type": "ping_monitor",
            "device_count": len(devices),
            "created_time": datetime.now().isoformat(),
            "node_red_flow": nodes,
            "installation_notes": "Import this JSON into Node-RED to start monitoring"
        }


class OfflineNetworkExperts:
    """Network assessment without LLM dependency"""
    
    def __init__(self):
        self.scanner = OfflineNetworkScanner()
        self.port_scanner = OfflinePortScanner()
        self.flow_generator = OfflineNodeREDGenerator()
    
    async def run_assessment(self, network: str = "192.168.1.0/24") -> Dict[str, Any]:
        """Run complete network assessment offline"""
        print("🔧 Offline Network Experts - Starting Assessment")
        print("=" * 60)
        print(f"🎯 Target: {network}")
        print(f"👤 Lead: Ionut-Valentin Baltag (Certified Ethical Hacker)")
        print("🔧 Mode: Direct Scanning (No LLM Required)")
        print("=" * 60)
        
        results = {
            "network": network,
            "assessment_type": "Offline Direct Scan",
            "lead": "Ionut-Valentin Baltag",
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Step 1: Network discovery
            print("\\n🔍 Discovering devices...")
            devices = await self.scanner.scan_network(network)
            results["device_discovery"] = devices
            
            # Step 2: Port scan first device
            if devices and devices.get('active_devices'):
                first_device = devices['active_devices'][0]['ip']
                print(f"\\n🔒 Scanning ports on {first_device}...")
                
                ports = await self.port_scanner.scan_ports(first_device)
                results["security_scan"] = ports
            
            # Step 3: Create Node-RED flow
            print("\\n🔧 Generating Node-RED monitoring flow...")
            flow = self.flow_generator.create_monitoring_flow(
                devices.get('active_devices', [])
            )
            results["node_red_flow"] = flow
            
            # Summary
            device_count = len(devices.get('active_devices', []))
            print(f"\\n✅ Assessment Complete!")
            print(f"📊 Found {device_count} active devices")
            print(f"🔧 Generated Node-RED monitoring flows")
            
            return results
            
        except Exception as e:
            print(f"❌ Assessment failed: {e}")
            results["error"] = str(e)
            return results


async def main():
    """Run offline network assessment"""
    experts = OfflineNetworkExperts()
    results = await experts.run_assessment("192.168.1.0/24")
    
    # Show results
    print("\\n" + "="*60)
    print("📋 OFFLINE ASSESSMENT RESULTS")
    print("="*60)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
