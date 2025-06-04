"""
Network Scanning Handler - Scanner Brother's specialized tools
"""
import asyncio
import ipaddress
import socket
from typing import Dict, List, Optional
import nmap
import ping3
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class NetworkScanHandler(BaseHandler):
    """Handler for network discovery and scanning operations"""
    
    def __init__(self):
        super().__init__()
        self.nm = nmap.PortScanner()
    
    @tool
    async def scan_network_range(
        self, 
        *, 
        network: str,
        scan_type: str = "ping",
        timeout: int = 30
    ) -> Dict:
        """
        Scan a network range for active devices
        
        Args:
            network: Network range in CIDR notation (e.g., "192.168.1.0/24")
            scan_type: Type of scan - "ping", "tcp", "syn", "udp"
            timeout: Scan timeout in seconds
            
        Returns:
            Dictionary containing discovered devices and their details
        """
        try:
            # Validate network format
            network_obj = ipaddress.ip_network(network, strict=False)
            
            if scan_type == "ping":
                scan_args = "-sn"  # Ping scan
            elif scan_type == "tcp":
                scan_args = "-sT"  # TCP connect scan
            elif scan_type == "syn":
                scan_args = "-sS"  # SYN scan
            elif scan_type == "udp":
                scan_args = "-sU"  # UDP scan
            else:
                scan_args = "-sn"  # Default to ping
            
            # Perform the scan
            scan_result = self.nm.scan(
                hosts=str(network_obj),
                arguments=f"{scan_args} --host-timeout {timeout}s"
            )
            
            devices = []
            for host in self.nm.all_hosts():
                host_info = {
                    "ip": host,
                    "hostname": self.nm[host].hostname(),
                    "state": self.nm[host].state(),
                    "mac_address": None,
                    "vendor": None,
                    "open_ports": []
                }
                
                # Get MAC address if available
                if 'mac' in self.nm[host]['addresses']:
                    host_info["mac_address"] = self.nm[host]['addresses']['mac']
                    
                # Get vendor information
                if 'vendor' in self.nm[host]:
                    host_info["vendor"] = list(self.nm[host]['vendor'].values())[0] if self.nm[host]['vendor'] else None
                
                # Get open ports
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    for port in ports:
                        port_state = self.nm[host][protocol][port]['state']
                        if port_state == 'open':
                            service = self.nm[host][protocol][port].get('name', 'unknown')
                            host_info["open_ports"].append({
                                "port": port,
                                "protocol": protocol,
                                "service": service,
                                "version": self.nm[host][protocol][port].get('version', '')
                            })
                
                devices.append(host_info)
            
            return {
                "network": network,
                "scan_type": scan_type,
                "devices_found": len(devices),
                "devices": devices,
                "scan_stats": {
                    "total_hosts": len(self.nm.all_hosts()),
                    "hosts_up": len([d for d in devices if d["state"] == "up"]),
                    "hosts_down": len([d for d in devices if d["state"] == "down"]),
                    "scan_time": scan_result['nmap']['scanstats']['elapsed']
                }
            }
            
        except Exception as e:
            return {
                "error": f"Network scan failed: {str(e)}",
                "network": network,
                "scan_type": scan_type
            }
    
    @tool
    async def port_scan(
        self,
        *,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "tcp"
    ) -> Dict:
        """
        Perform detailed port scan on a specific target
        
        Args:
            target: Target IP address or hostname
            ports: Port range to scan (e.g., "1-1000", "80,443,22")
            scan_type: Type of port scan - "tcp", "syn", "udp"
            
        Returns:
            Dictionary containing port scan results
        """
        try:
            if scan_type == "tcp":
                scan_args = f"-sT -p {ports}"
            elif scan_type == "syn":
                scan_args = f"-sS -p {ports}"
            elif scan_type == "udp":
                scan_args = f"-sU -p {ports}"
            else:
                scan_args = f"-sT -p {ports}"
            
            scan_result = self.nm.scan(target, arguments=scan_args)
            
            if target not in self.nm.all_hosts():
                return {
                    "error": f"Host {target} is not reachable",
                    "target": target
                }
            
            host_data = self.nm[target]
            open_ports = []
            
            for protocol in host_data.all_protocols():
                ports_data = host_data[protocol]
                for port, port_info in ports_data.items():
                    if port_info['state'] == 'open':
                        open_ports.append({
                            "port": port,
                            "protocol": protocol,
                            "service": port_info.get('name', 'unknown'),
                            "version": port_info.get('version', ''),
                            "product": port_info.get('product', ''),
                            "extrainfo": port_info.get('extrainfo', '')
                        })
            
            return {
                "target": target,
                "hostname": host_data.hostname(),
                "state": host_data.state(),
                "open_ports": open_ports,
                "total_open_ports": len(open_ports),
                "scan_type": scan_type,
                "scan_time": scan_result['nmap']['scanstats']['elapsed']
            }
            
        except Exception as e:
            return {
                "error": f"Port scan failed: {str(e)}",
                "target": target
            }
    
    @tool
    async def ping_host(
        self,
        *,
        target: str,
        count: int = 4,
        timeout: float = 3.0
    ) -> Dict:
        """
        Ping a host to check connectivity and measure latency
        
        Args:
            target: Target IP address or hostname
            count: Number of ping packets to send
            timeout: Timeout for each ping in seconds
            
        Returns:
            Dictionary containing ping results
        """
        try:
            ping_results = []
            successful_pings = 0
            total_time = 0.0
            
            for i in range(count):
                response_time = ping3.ping(target, timeout=int(timeout))
                if response_time is not None:
                    successful_pings += 1
                    total_time += response_time
                    ping_results.append({
                        "sequence": i + 1,
                        "time": round(response_time * 1000, 2),  # Convert to ms
                        "status": "success"
                    })
                else:
                    ping_results.append({
                        "sequence": i + 1,
                        "time": None,
                        "status": "timeout"
                    })
            
            packet_loss = ((count - successful_pings) / count) * 100
            avg_time = (total_time / successful_pings * 1000) if successful_pings > 0 else 0
            
            return {
                "target": target,
                "packets_sent": count,
                "packets_received": successful_pings,
                "packet_loss_percent": round(packet_loss, 2),
                "avg_response_time_ms": round(avg_time, 2),
                "ping_results": ping_results,
                "reachable": successful_pings > 0
            }
            
        except Exception as e:
            return {
                "error": f"Ping failed: {str(e)}",
                "target": target,
                "reachable": False
            }
    
    @tool
    async def service_detection(
        self,
        *,
        target: str,
        ports: str = "top-1000"
    ) -> Dict:
        """
        Detect services and versions on open ports
        
        Args:
            target: Target IP address or hostname
            ports: Ports to scan ("top-1000", "1-65535", or specific ports)
            
        Returns:
            Dictionary containing service detection results
        """
        try:
            # Service version detection
            scan_args = f"-sV -p {ports}"
            scan_result = self.nm.scan(target, arguments=scan_args)
            
            if target not in self.nm.all_hosts():
                return {
                    "error": f"Host {target} is not reachable",
                    "target": target
                }
            
            host_data = self.nm[target]
            services = []
            
            for protocol in host_data.all_protocols():
                ports_data = host_data[protocol]
                for port, port_info in ports_data.items():
                    if port_info['state'] == 'open':
                        service_info = {
                            "port": port,
                            "protocol": protocol,
                            "service": port_info.get('name', 'unknown'),
                            "version": port_info.get('version', ''),
                            "product": port_info.get('product', ''),
                            "extrainfo": port_info.get('extrainfo', ''),
                            "confidence": port_info.get('conf', ''),
                            "cpe": port_info.get('cpe', '')
                        }
                        services.append(service_info)
            
            return {
                "target": target,
                "hostname": host_data.hostname(),
                "services": services,
                "total_services": len(services),
                "scan_time": scan_result['nmap']['scanstats']['elapsed']
            }
            
        except Exception as e:
            return {
                "error": f"Service detection failed: {str(e)}",
                "target": target
            }
