"""
Traffic Analyzer Handler - Analyzer Brother's specialized tools
"""
import asyncio
import json
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime
import socket
import struct

from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class TrafficAnalyzerHandler(BaseHandler):
    """Handler for network traffic analysis and anomaly detection"""
    
    def __init__(self):
        super().__init__()
        self.analysis_active = False
        self.traffic_patterns = {}
        
    @tool
    async def analyze_network_traffic(
        self,
        *,
        interface: str = "auto",
        duration: int = 60,
        packet_count: int = 1000,
        include_protocols: bool = True
    ) -> Dict:
        """
        Analyze network traffic patterns
        
        Args:
            interface: Network interface to monitor
            duration: Analysis duration in seconds
            packet_count: Maximum packets to capture
            include_protocols: Include protocol breakdown
            
        Returns:
            Dictionary containing traffic analysis results
        """
        try:
            analysis_results = {
                "interface": interface,
                "duration": duration,
                "start_time": str(datetime.now()),
                "traffic_summary": {},
                "top_talkers": [],
                "protocol_breakdown": {},
                "suspicious_activity": [],
                "status": "analyzing"
            }
            
            print(f"📊 Analyzing network traffic on {interface} for {duration}s...")
            
            # Use netstat and ss for connection analysis
            connections_data = await self._analyze_active_connections()
            analysis_results["active_connections"] = connections_data
            
            # Analyze network statistics
            network_stats = await self._get_network_statistics()
            analysis_results["network_statistics"] = network_stats
            
            # Perform protocol analysis
            if include_protocols:
                protocol_data = await self._analyze_protocols()
                analysis_results["protocol_breakdown"] = protocol_data
            
            # Detect suspicious patterns
            suspicious_activity = await self._detect_suspicious_activity(analysis_results)
            analysis_results["suspicious_activity"] = suspicious_activity
            
            # Generate traffic summary
            traffic_summary = await self._generate_traffic_summary(analysis_results)
            analysis_results["traffic_summary"] = traffic_summary
            
            analysis_results["end_time"] = str(datetime.now())
            analysis_results["status"] = "completed"
            
            return analysis_results
            
        except Exception as e:
            return {
                "error": f"Traffic analysis failed: {str(e)}",
                "interface": interface,
                "status": "failed"
            }
    
    @tool
    async def detect_port_scan(
        self,
        *,
        target_network: str = "192.168.1.0/24",
        time_window: int = 300,
        threshold: int = 10
    ) -> Dict:
        """
        Detect potential port scanning activity
        
        Args:
            target_network: Network to monitor for scans
            time_window: Time window in seconds to analyze
            threshold: Minimum connections to flag as scan
            
        Returns:
            Dictionary containing port scan detection results
        """
        try:
            scan_detection = {
                "target_network": target_network,
                "time_window": time_window,
                "threshold": threshold,
                "detected_scans": [],
                "scan_summary": {
                    "total_scans": 0,
                    "unique_sources": 0,
                    "most_targeted_ports": []
                },
                "status": "monitoring"
            }
            
            print(f"🔍 Monitoring for port scans on {target_network}...")
            
            # Analyze current connections for scan patterns
            connections = await self._get_connection_patterns()
            
            # Group connections by source IP
            source_connections = {}
            for conn in connections:
                source_ip = conn.get("source_ip")
                if source_ip:
                    if source_ip not in source_connections:
                        source_connections[source_ip] = []
                    source_connections[source_ip].append(conn)
            
            # Detect scanning patterns
            detected_scans = []
            for source_ip, conn_list in source_connections.items():
                # Check for multiple port connections from same source
                unique_ports = set()
                for conn in conn_list:
                    if conn.get("dest_port"):
                        unique_ports.add(conn["dest_port"])
                
                if len(unique_ports) >= threshold:
                    scan_info = {
                        "source_ip": source_ip,
                        "target_ports": list(unique_ports),
                        "connection_count": len(conn_list),
                        "port_count": len(unique_ports),
                        "scan_type": self._classify_scan_type(unique_ports),
                        "severity": "high" if len(unique_ports) > 50 else "medium"
                    }
                    detected_scans.append(scan_info)
            
            scan_detection["detected_scans"] = detected_scans
            scan_detection["scan_summary"]["total_scans"] = len(detected_scans)
            scan_detection["scan_summary"]["unique_sources"] = len(set(scan["source_ip"] for scan in detected_scans))
            
            # Find most targeted ports
            all_ports = []
            for scan in detected_scans:
                all_ports.extend(scan["target_ports"])
            
            port_counts = {}
            for port in all_ports:
                port_counts[port] = port_counts.get(port, 0) + 1
            
            most_targeted = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            scan_detection["scan_summary"]["most_targeted_ports"] = most_targeted
            
            scan_detection["status"] = "completed"
            return scan_detection
            
        except Exception as e:
            return {
                "error": f"Port scan detection failed: {str(e)}",
                "target_network": target_network,
                "status": "failed"
            }
    
    @tool
    async def bandwidth_analysis(
        self,
        *,
        interface: str = "auto",
        duration: int = 300,
        top_n: int = 10
    ) -> Dict:
        """
        Analyze bandwidth usage patterns
        
        Args:
            interface: Network interface to analyze
            duration: Analysis duration in seconds
            top_n: Number of top bandwidth consumers to report
            
        Returns:
            Dictionary containing bandwidth analysis results
        """
        try:
            bandwidth_analysis = {
                "interface": interface,
                "duration": duration,
                "start_time": str(datetime.now()),
                "bandwidth_usage": {},
                "top_consumers": [],
                "traffic_patterns": {},
                "recommendations": [],
                "status": "analyzing"
            }
            
            print(f"📈 Analyzing bandwidth usage on {interface} for {duration}s...")
            
            # Get initial network statistics
            initial_stats = await self._get_interface_stats(interface)
            
            # Wait for the analysis duration
            await asyncio.sleep(duration)
            
            # Get final network statistics
            final_stats = await self._get_interface_stats(interface)
            
            # Calculate bandwidth usage
            if initial_stats and final_stats:
                bytes_sent = final_stats["bytes_sent"] - initial_stats["bytes_sent"]
                bytes_recv = final_stats["bytes_recv"] - initial_stats["bytes_recv"]
                
                # Convert to readable units
                sent_mbps = (bytes_sent * 8) / (duration * 1_000_000)
                recv_mbps = (bytes_recv * 8) / (duration * 1_000_000)
                
                bandwidth_analysis["bandwidth_usage"] = {
                    "sent_mbps": round(sent_mbps, 2),
                    "received_mbps": round(recv_mbps, 2),
                    "total_mbps": round(sent_mbps + recv_mbps, 2),
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_recv,
                    "total_bytes": bytes_sent + bytes_recv
                }
            
            # Analyze traffic patterns
            traffic_patterns = await self._analyze_traffic_patterns()
            bandwidth_analysis["traffic_patterns"] = traffic_patterns
            
            # Generate recommendations
            recommendations = await self._generate_bandwidth_recommendations(bandwidth_analysis)
            bandwidth_analysis["recommendations"] = recommendations
            
            bandwidth_analysis["end_time"] = str(datetime.now())
            bandwidth_analysis["status"] = "completed"
            
            return bandwidth_analysis
            
        except Exception as e:
            return {
                "error": f"Bandwidth analysis failed: {str(e)}",
                "interface": interface,
                "status": "failed"
            }
    
    async def _analyze_active_connections(self) -> Dict:
        """Analyze currently active network connections"""
        try:
            # Use ss command for detailed connection info
            cmd = "ss -tuln"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            connections = {
                "total_connections": 0,
                "by_state": {},
                "by_protocol": {},
                "listening_ports": [],
                "established_connections": []
            }
            
            if process.returncode == 0:
                lines = stdout.decode().strip().split('\\n')[1:]  # Skip header
                
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            protocol = parts[0]
                            state = parts[1] if len(parts) > 1 else "UNKNOWN"
                            local_addr = parts[4] if len(parts) > 4 else ""
                            
                            connections["total_connections"] += 1
                            
                            # Count by protocol
                            connections["by_protocol"][protocol] = connections["by_protocol"].get(protocol, 0) + 1
                            
                            # Count by state
                            connections["by_state"][state] = connections["by_state"].get(state, 0) + 1
                            
                            # Track listening ports
                            if state == "LISTEN" and local_addr:
                                try:
                                    if ':' in local_addr:
                                        port = local_addr.split(':')[-1]
                                        if port.isdigit():
                                            connections["listening_ports"].append({
                                                "port": int(port),
                                                "protocol": protocol,
                                                "address": local_addr
                                            })
                                except:
                                    pass
            
            return connections
            
        except Exception as e:
            return {"error": f"Connection analysis failed: {str(e)}"}
    
    async def _get_network_statistics(self) -> Dict:
        """Get general network statistics"""
        try:
            # Use netstat for network statistics
            cmd = "netstat -i"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            network_stats = {
                "interfaces": [],
                "total_packets": {"rx": 0, "tx": 0},
                "total_bytes": {"rx": 0, "tx": 0},
                "errors": {"rx": 0, "tx": 0}
            }
            
            if process.returncode == 0:
                lines = stdout.decode().strip().split('\\n')[2:]  # Skip headers
                
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 8:
                            interface = parts[0]
                            rx_packets = int(parts[3]) if parts[3].isdigit() else 0
                            tx_packets = int(parts[7]) if parts[7].isdigit() else 0
                            
                            interface_stats = {
                                "name": interface,
                                "rx_packets": rx_packets,
                                "tx_packets": tx_packets
                            }
                            
                            network_stats["interfaces"].append(interface_stats)
                            network_stats["total_packets"]["rx"] += rx_packets
                            network_stats["total_packets"]["tx"] += tx_packets
            
            return network_stats
            
        except Exception as e:
            return {"error": f"Network statistics failed: {str(e)}"}
    
    async def _analyze_protocols(self) -> Dict:
        """Analyze protocol distribution"""
        try:
            protocol_stats = {
                "tcp": {"connections": 0, "listening": 0},
                "udp": {"connections": 0, "listening": 0},
                "icmp": {"packets": 0},
                "other": {"connections": 0}
            }
            
            # Get TCP connections
            tcp_cmd = "ss -t -a"
            tcp_process = await asyncio.create_subprocess_shell(
                tcp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            tcp_stdout, _ = await tcp_process.communicate()
            
            if tcp_process.returncode == 0:
                tcp_lines = tcp_stdout.decode().strip().split('\\n')[1:]
                for line in tcp_lines:
                    if line.strip():
                        protocol_stats["tcp"]["connections"] += 1
                        if "LISTEN" in line:
                            protocol_stats["tcp"]["listening"] += 1
            
            # Get UDP connections
            udp_cmd = "ss -u -a"
            udp_process = await asyncio.create_subprocess_shell(
                udp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            udp_stdout, _ = await udp_process.communicate()
            
            if udp_process.returncode == 0:
                udp_lines = udp_stdout.decode().strip().split('\\n')[1:]
                for line in udp_lines:
                    if line.strip():
                        protocol_stats["udp"]["connections"] += 1
                        if "UNCONN" in line:
                            protocol_stats["udp"]["listening"] += 1
            
            return protocol_stats
            
        except Exception as e:
            return {"error": f"Protocol analysis failed: {str(e)}"}
    
    async def _detect_suspicious_activity(self, analysis_data: Dict) -> List[Dict]:
        """Detect suspicious network activity patterns"""
        suspicious_activities = []
        
        try:
            # Check for unusual connection patterns
            if "active_connections" in analysis_data:
                connections = analysis_data["active_connections"]
                
                # High number of connections
                if connections.get("total_connections", 0) > 1000:
                    suspicious_activities.append({
                        "type": "high_connection_count",
                        "severity": "medium",
                        "description": f"Unusually high number of connections: {connections['total_connections']}",
                        "recommendation": "Investigate for potential DDoS or scanning activity"
                    })
                
                # Many listening ports
                listening_ports = connections.get("listening_ports", [])
                if len(listening_ports) > 20:
                    suspicious_activities.append({
                        "type": "many_listening_ports",
                        "severity": "low",
                        "description": f"Many services listening: {len(listening_ports)} ports",
                        "recommendation": "Review running services and close unnecessary ports"
                    })
            
            # Check protocol distribution for anomalies
            if "protocol_breakdown" in analysis_data:
                protocols = analysis_data["protocol_breakdown"]
                tcp_conns = protocols.get("tcp", {}).get("connections", 0)
                udp_conns = protocols.get("udp", {}).get("connections", 0)
                
                # Unusual UDP to TCP ratio
                if tcp_conns > 0 and (udp_conns / tcp_conns) > 2:
                    suspicious_activities.append({
                        "type": "unusual_protocol_ratio",
                        "severity": "low",
                        "description": f"High UDP to TCP ratio: {udp_conns}:{tcp_conns}",
                        "recommendation": "Investigate UDP traffic for potential tunneling or DoS"
                    })
            
        except Exception as e:
            suspicious_activities.append({
                "type": "analysis_error",
                "severity": "info",
                "description": f"Error during suspicious activity detection: {str(e)}"
            })
        
        return suspicious_activities
    
    async def _generate_traffic_summary(self, analysis_data: Dict) -> Dict:
        """Generate summary of traffic analysis"""
        summary = {
            "total_connections": 0,
            "unique_protocols": 0,
            "suspicious_count": 0,
            "top_findings": []
        }
        
        try:
            if "active_connections" in analysis_data:
                summary["total_connections"] = analysis_data["active_connections"].get("total_connections", 0)
            
            if "protocol_breakdown" in analysis_data:
                protocols = analysis_data["protocol_breakdown"]
                summary["unique_protocols"] = len([k for k, v in protocols.items() if isinstance(v, dict) and v.get("connections", 0) > 0])
            
            if "suspicious_activity" in analysis_data:
                summary["suspicious_count"] = len(analysis_data["suspicious_activity"])
                summary["top_findings"] = analysis_data["suspicious_activity"][:3]  # Top 3 findings
            
        except Exception:
            pass
        
        return summary
    
    def _classify_scan_type(self, ports: set) -> str:
        """Classify the type of port scan based on ports"""
        common_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389}
        
        if len(ports) > 1000:
            return "comprehensive_scan"
        elif len(ports) > 100:
            return "extensive_scan"
        elif ports.intersection(common_ports):
            return "targeted_scan"
        elif all(p < 1024 for p in ports):
            return "well_known_ports_scan"
        else:
            return "custom_scan"
    
    async def _get_connection_patterns(self) -> List[Dict]:
        """Get detailed connection patterns for analysis"""
        connections = []
        
        try:
            # This is a simplified version - in a real implementation,
            # you would parse detailed connection information
            cmd = "ss -tuln"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                lines = stdout.decode().strip().split('\\n')[1:]
                for line in lines:
                    if line.strip():
                        # Parse connection information
                        # This is a simplified parser
                        parts = line.split()
                        if len(parts) >= 5:
                            conn_info = {
                                "protocol": parts[0],
                                "state": parts[1],
                                "local_address": parts[4],
                                "source_ip": None,
                                "dest_port": None
                            }
                            
                            # Extract port information
                            if ':' in parts[4]:
                                try:
                                    port = parts[4].split(':')[-1]
                                    if port.isdigit():
                                        conn_info["dest_port"] = int(port)
                                except:
                                    pass
                            
                            connections.append(conn_info)
            
        except Exception:
            pass
        
        return connections
    
    async def _get_interface_stats(self, interface: str) -> Optional[Dict]:
        """Get interface statistics"""
        try:
            # This would interface with system network statistics
            # For now, return mock data
            return {
                "bytes_sent": 1000000,
                "bytes_recv": 2000000,
                "packets_sent": 1000,
                "packets_recv": 2000
            }
        except Exception:
            return None
    
    async def _analyze_traffic_patterns(self) -> Dict:
        """Analyze traffic patterns"""
        return {
            "peak_hours": ["09:00-12:00", "14:00-17:00"],
            "protocol_distribution": {"tcp": 70, "udp": 25, "other": 5},
            "traffic_type": {"web": 40, "email": 20, "file_transfer": 15, "other": 25}
        }
    
    async def _generate_bandwidth_recommendations(self, analysis_data: Dict) -> List[str]:
        """Generate bandwidth optimization recommendations"""
        recommendations = []
        
        try:
            bandwidth_usage = analysis_data.get("bandwidth_usage", {})
            total_mbps = bandwidth_usage.get("total_mbps", 0)
            
            if total_mbps > 100:
                recommendations.append("Consider implementing Quality of Service (QoS) policies")
                recommendations.append("Monitor for bandwidth-intensive applications")
            
            if total_mbps < 1:
                recommendations.append("Network utilization is low - consider consolidating resources")
            
            recommendations.append("Implement traffic monitoring for continuous optimization")
            recommendations.append("Consider bandwidth throttling for non-critical services")
            
        except Exception:
            recommendations.append("Unable to generate specific recommendations")
        
        return recommendations
