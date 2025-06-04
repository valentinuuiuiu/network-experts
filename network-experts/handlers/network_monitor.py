"""
Network Monitor Handler - Watcher Brother's specialized tools
"""
import asyncio
import psutil
import json
import socket
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
import time

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class NetworkMonitorHandler(BaseHandler):
    """Handler for network monitoring and performance analysis"""
    
    def __init__(self):
        super().__init__()
        self.monitoring_active = False
        self.alert_thresholds = {
            "cpu_percent": 80,
            "memory_percent": 85,
            "disk_percent": 90,
            "response_time_ms": 1000
        }
    
    @tool
    async def monitor_network_performance(
        self,
        *,
        interface: str = "auto",
        duration: int = 60,
        include_bandwidth: bool = True
    ) -> Dict:
        """
        Monitor network performance metrics
        
        Args:
            interface: Network interface to monitor (auto for default)
            duration: Monitoring duration in seconds
            include_bandwidth: Include bandwidth utilization metrics
            
        Returns:
            Dictionary containing network performance data
        """
        try:
            performance_data = {
                "interface": interface,
                "monitoring_duration": duration,
                "start_time": str(datetime.now()),
                "metrics": {
                    "bandwidth": {},
                    "latency": {},
                    "packet_loss": {},
                    "connections": {}
                },
                "alerts": [],
                "status": "monitoring"
            }
            
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            stats_before = psutil.net_io_counters(pernic=True)
            
            if interface == "auto":
                # Find the default interface
                interface = await self._get_default_interface()
            
            print(f"📊 Monitoring network performance on {interface} for {duration}s...")
            
            # Initial measurements
            start_time = time.time()
            
            # Monitor for specified duration
            await asyncio.sleep(duration)
            
            # Final measurements
            stats_after = psutil.net_io_counters(pernic=True)
            end_time = time.time()
            actual_duration = end_time - start_time
            
            # Calculate bandwidth metrics
            if include_bandwidth and interface in stats_before and interface in stats_after:
                bytes_sent = stats_after[interface].bytes_sent - stats_before[interface].bytes_sent
                bytes_recv = stats_after[interface].bytes_recv - stats_before[interface].bytes_recv
                
                # Convert to Mbps
                sent_mbps = (bytes_sent * 8) / (actual_duration * 1_000_000)
                recv_mbps = (bytes_recv * 8) / (actual_duration * 1_000_000)
                
                performance_data["metrics"]["bandwidth"] = {
                    "sent_mbps": round(sent_mbps, 2),
                    "received_mbps": round(recv_mbps, 2),
                    "total_mbps": round(sent_mbps + recv_mbps, 2),
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_recv
                }
            
            # Get connection statistics
            connections = psutil.net_connections()
            established_connections = [c for c in connections if c.status == 'ESTABLISHED']
            
            performance_data["metrics"]["connections"] = {
                "total_connections": len(connections),
                "established": len(established_connections),
                "listening": len([c for c in connections if c.status == 'LISTEN']),
                "by_protocol": {
                    "tcp": len([c for c in connections if c.type == socket.SOCK_STREAM]),
                    "udp": len([c for c in connections if c.type == socket.SOCK_DGRAM])
                }
            }
            
            # Latency check to common destinations
            latency_results = await self._check_network_latency()
            performance_data["metrics"]["latency"] = latency_results
            
            # Check for alerts
            alerts = await self._check_performance_alerts(performance_data["metrics"])
            performance_data["alerts"] = alerts
            
            performance_data["end_time"] = str(datetime.now())
            performance_data["status"] = "completed"
            
            return performance_data
            
        except Exception as e:
            return {
                "error": f"Network performance monitoring failed: {str(e)}",
                "interface": interface,
                "status": "failed"
            }
    
    @tool
    async def ping_host(
        self,
        *,
        hostname: str,
        count: int = 4,
        timeout: int = 5
    ) -> Dict:
        """
        Ping a host and return response statistics
        
        Args:
            hostname: Target hostname or IP address
            count: Number of ping packets to send
            timeout: Timeout for each ping in seconds
            
        Returns:
            Dictionary containing ping statistics
        """
        try:
            # Use system ping command for reliable results
            cmd = f"ping -c {count} -W {timeout} {hostname}"
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            ping_results = {
                "hostname": hostname,
                "packets_sent": count,
                "timeout": timeout,
                "statistics": {},
                "status": "unknown"
            }
            
            if process.returncode == 0:
                output = stdout.decode()
                
                # Parse ping output for statistics
                ping_results["status"] = "success"
                ping_results["raw_output"] = output
                
                # Extract statistics from ping output
                lines = output.split('\\n')
                for line in lines:
                    if "packets transmitted" in line:
                        # Parse packet statistics
                        parts = line.split()
                        transmitted = int(parts[0])
                        received = int(parts[3])
                        loss_percent = float(parts[5].rstrip('%'))
                        
                        ping_results["statistics"]["packets_transmitted"] = transmitted
                        ping_results["statistics"]["packets_received"] = received
                        ping_results["statistics"]["packet_loss_percent"] = loss_percent
                    
                    elif "round-trip" in line or "rtt" in line:
                        # Parse timing statistics
                        parts = line.split('=')[-1].strip().split('/')
                        if len(parts) >= 4:
                            ping_results["statistics"]["rtt_min_ms"] = float(parts[0])
                            ping_results["statistics"]["rtt_avg_ms"] = float(parts[1])
                            ping_results["statistics"]["rtt_max_ms"] = float(parts[2])
                            ping_results["statistics"]["rtt_stddev_ms"] = float(parts[3])
            else:
                ping_results["status"] = "failed"
                ping_results["error"] = stderr.decode() if stderr else "Ping failed"
            
            return ping_results
            
        except Exception as e:
            return {
                "error": f"Ping failed: {str(e)}",
                "hostname": hostname,
                "status": "error"
            }
    
    @tool
    async def check_port_connectivity(
        self,
        *,
        hostname: str,
        ports: List[int],
        timeout: int = 5
    ) -> Dict:
        """
        Check connectivity to specific ports on a host
        
        Args:
            hostname: Target hostname or IP address
            ports: List of ports to check
            timeout: Connection timeout in seconds
            
        Returns:
            Dictionary containing port connectivity results
        """
        try:
            connectivity_results = {
                "hostname": hostname,
                "ports_checked": ports,
                "timeout": timeout,
                "results": [],
                "summary": {
                    "total_ports": len(ports),
                    "open_ports": 0,
                    "closed_ports": 0,
                    "filtered_ports": 0
                }
            }
            
            for port in ports:
                port_result = {
                    "port": port,
                    "status": "unknown",
                    "response_time_ms": None,
                    "service": None
                }
                
                try:
                    start_time = time.time()
                    
                    # Try to connect to the port
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    
                    result = sock.connect_ex((hostname, port))
                    end_time = time.time()
                    
                    if result == 0:
                        port_result["status"] = "open"
                        port_result["response_time_ms"] = round((end_time - start_time) * 1000, 2)
                        connectivity_results["summary"]["open_ports"] += 1
                        
                        # Try to identify service
                        try:
                            service_name = socket.getservbyport(port)
                            port_result["service"] = service_name
                        except:
                            port_result["service"] = "unknown"
                    else:
                        port_result["status"] = "closed"
                        connectivity_results["summary"]["closed_ports"] += 1
                    
                    sock.close()
                    
                except socket.timeout:
                    port_result["status"] = "filtered"
                    connectivity_results["summary"]["filtered_ports"] += 1
                except Exception as e:
                    port_result["status"] = "error"
                    port_result["error"] = str(e)
                
                connectivity_results["results"].append(port_result)
            
            return connectivity_results
            
        except Exception as e:
            return {
                "error": f"Port connectivity check failed: {str(e)}",
                "hostname": hostname,
                "ports": ports
            }
    
    async def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            # Get default interface using route command
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\\n')
                for line in lines:
                    if 'dev' in line:
                        parts = line.split()
                        dev_index = parts.index('dev')
                        if dev_index + 1 < len(parts):
                            return parts[dev_index + 1]
            
            # Fallback: use the first active interface
            interfaces = psutil.net_if_stats()
            for interface, stats in interfaces.items():
                if stats.isup and interface != 'lo':
                    return interface
                    
            return "eth0"  # Final fallback
            
        except:
            return "eth0"
    
    async def _check_network_latency(self) -> Dict:
        """Check latency to common destinations"""
        destinations = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222" # OpenDNS
        ]
        
        latency_results = {
            "destinations": [],
            "average_latency_ms": 0,
            "max_latency_ms": 0,
            "min_latency_ms": 999999
        }
        
        total_latency = 0
        successful_pings = 0
        
        for dest in destinations:
            ping_result = await self.ping_host(hostname=dest, count=1, timeout=3)
            
            dest_result = {
                "destination": dest,
                "status": ping_result.get("status", "unknown"),
                "latency_ms": None
            }
            
            if ping_result.get("status") == "success":
                stats = ping_result.get("statistics", {})
                if "rtt_avg_ms" in stats:
                    latency = stats["rtt_avg_ms"]
                    dest_result["latency_ms"] = latency
                    
                    total_latency += latency
                    successful_pings += 1
                    
                    latency_results["max_latency_ms"] = max(latency_results["max_latency_ms"], latency)
                    latency_results["min_latency_ms"] = min(latency_results["min_latency_ms"], latency)
            
            latency_results["destinations"].append(dest_result)
        
        if successful_pings > 0:
            latency_results["average_latency_ms"] = round(total_latency / successful_pings, 2)
        else:
            latency_results["min_latency_ms"] = 0
        
        return latency_results
    
    async def _check_performance_alerts(self, metrics: Dict) -> List[Dict]:
        """Check performance metrics against thresholds"""
        alerts = []
        
        # Check latency alerts
        if "latency" in metrics and "average_latency_ms" in metrics["latency"]:
            avg_latency = metrics["latency"]["average_latency_ms"]
            if avg_latency > self.alert_thresholds["response_time_ms"]:
                alerts.append({
                    "type": "high_latency",
                    "severity": "warning",
                    "message": f"High network latency detected: {avg_latency}ms",
                    "threshold": self.alert_thresholds["response_time_ms"],
                    "actual_value": avg_latency
                })
        
        # Check connection count alerts
        if "connections" in metrics:
            total_connections = metrics["connections"]["total_connections"]
            if total_connections > 1000:  # Arbitrary threshold
                alerts.append({
                    "type": "high_connection_count",
                    "severity": "info",
                    "message": f"High number of network connections: {total_connections}",
                    "actual_value": total_connections
                })
        
        return alerts
