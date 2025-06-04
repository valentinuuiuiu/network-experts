"""
Security Audit Handler - Guardian Brother's specialized tools
"""
import asyncio
import hashlib
import ipaddress
import json
import ssl
import socket
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import subprocess
import re
from datetime import datetime
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class SecurityAuditHandler(BaseHandler):
    """Handler for security assessment and vulnerability analysis"""
    
    def __init__(self):
        super().__init__()
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017]
        self.weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
        
    @tool
    async def vulnerability_scan(
        self,
        *,
        target: str,
        scan_type: str = "basic",
        ports: Optional[str] = None
    ) -> Dict:
        """
        Perform vulnerability scanning on target host
        
        Args:
            target: Target IP address or hostname
            scan_type: Type of scan - "basic", "aggressive", "stealth"
            ports: Specific ports to scan (optional)
            
        Returns:
            Dictionary containing vulnerability scan results
        """
        try:
            vulnerabilities = []
            scan_results = {
                "target": target,
                "scan_type": scan_type,
                "vulnerabilities": [],
                "risk_level": "low",
                "recommendations": []
            }
            
            # Check for common vulnerabilities
            if scan_type in ["basic", "aggressive"]:
                # Check for open ports with known vulnerabilities
                open_ports = await self._check_open_ports(target, ports)
                for port_info in open_ports:
                    vuln = await self._check_port_vulnerabilities(port_info)
                    if vuln:
                        vulnerabilities.extend(vuln)
                
                # Check SSL/TLS vulnerabilities
                ssl_vulns = await self._check_ssl_vulnerabilities(target)
                vulnerabilities.extend(ssl_vulns)
                
                # Check for weak authentication
                auth_vulns = await self._check_weak_authentication(target)
                vulnerabilities.extend(auth_vulns)
            
            if scan_type == "aggressive":
                # Additional aggressive checks
                web_vulns = await self._check_web_vulnerabilities(target)
                vulnerabilities.extend(web_vulns)
            
            # Categorize vulnerabilities by severity
            critical = [v for v in vulnerabilities if v.get("severity") == "critical"]
            high = [v for v in vulnerabilities if v.get("severity") == "high"]
            medium = [v for v in vulnerabilities if v.get("severity") == "medium"]
            low = [v for v in vulnerabilities if v.get("severity") == "low"]
            
            # Determine overall risk level
            if critical:
                risk_level = "critical"
            elif high:
                risk_level = "high"
            elif medium:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            scan_results.update({
                "vulnerabilities": vulnerabilities,
                "risk_level": risk_level,
                "vulnerability_count": {
                    "critical": len(critical),
                    "high": len(high),
                    "medium": len(medium),
                    "low": len(low),
                    "total": len(vulnerabilities)
                },
                "recommendations": self._generate_recommendations(vulnerabilities)
            })
            
            return scan_results
            
        except Exception as e:
            return {
                "error": f"Vulnerability scan failed: {str(e)}",
                "target": target
            }
    
    @tool
    async def ssl_certificate_check(
        self,
        *,
        hostname: str,
        port: int = 443
    ) -> Dict:
        """
        Check SSL certificate validity and security
        
        Args:
            hostname: Target hostname
            port: SSL port (default 443)
            
        Returns:
            Dictionary containing SSL certificate analysis
        """
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Parse certificate details
                    cert_info = {
                        "subject": dict(x[0] for x in cert.get('subject', [])) if cert and cert.get('subject') else {},
                        "issuer": dict(x[0] for x in cert.get('issuer', [])) if cert and cert.get('issuer') else {},
                        "version": cert.get('version') if cert else None,
                        "serial_number": cert.get('serialNumber') if cert else None,
                        "not_before": cert.get('notBefore') if cert else None,
                        "not_after": cert.get('notAfter') if cert else None,
                        "alt_names": [x[1] for x in cert.get('subjectAltName', [])] if cert and cert.get('subjectAltName') else [],
                        "signature_algorithm": cert.get('signatureAlgorithm') if cert else None
                    }
                    
                    # Check cipher security
                    cipher_info = {
                        "name": cipher[0] if cipher else None,
                        "version": cipher[1] if cipher else None,
                        "bits": cipher[2] if cipher else None,
                        "is_weak": any(weak in cipher[0] for weak in self.weak_ciphers) if cipher else False
                    }
                    
                    # Security assessments
                    issues = []
                    
                    # Check expiration
                    import datetime
                    from datetime import datetime as dt
                    
                    if cert and cert.get('notAfter'):
                        expiry_date = dt.strptime(str(cert['notAfter']), '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - dt.now()).days
                        
                        if days_until_expiry < 0:
                            issues.append({
                                "type": "expired_certificate",
                                "severity": "critical",
                                "description": "Certificate has expired"
                            })
                        elif days_until_expiry < 30:
                            issues.append({
                                "type": "expiring_certificate",
                                "severity": "high",
                                "description": f"Certificate expires in {days_until_expiry} days"
                            })
                    
                    # Check weak cipher
                    if cipher_info["is_weak"]:
                        issues.append({
                            "type": "weak_cipher",
                            "severity": "medium",
                            "description": f"Weak cipher in use: {cipher_info['name']}"
                        })
                    
                    return {
                        "hostname": hostname,
                        "port": port,
                        "certificate": cert_info,
                        "cipher": cipher_info,
                        "security_issues": issues,
                        "overall_rating": "secure" if not issues else "issues_found"
                    }
                    
        except Exception as e:
            return {
                "error": f"SSL certificate check failed: {str(e)}",
                "hostname": hostname,
                "port": port
            }
    
    @tool
    async def network_security_assessment(
        self,
        *,
        network: str,
        check_type: str = "comprehensive"
    ) -> Dict:
        """
        Perform comprehensive network security assessment
        
        Args:
            network: Network range in CIDR notation
            check_type: Type of assessment - "basic", "comprehensive", "compliance"
            
        Returns:
            Dictionary containing network security assessment results
        """
        try:
            assessment = {
                "network": network,
                "check_type": check_type,
                "findings": [],
                "risk_score": 0,
                "compliance_status": {},
                "recommendations": []
            }
            
            # Validate network
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Check for common security issues
            if check_type in ["basic", "comprehensive"]:
                # Check for open administrative ports
                admin_ports = await self._check_administrative_ports(network)
                assessment["findings"].extend(admin_ports)
                
                # Check for default credentials
                default_creds = await self._check_default_credentials(network)
                assessment["findings"].extend(default_creds)
                
                # Check for unencrypted services
                unencrypted = await self._check_unencrypted_services(network)
                assessment["findings"].extend(unencrypted)
            
            if check_type == "comprehensive":
                # Additional comprehensive checks
                # Check for rogue devices
                rogue_devices = await self._check_rogue_devices(network)
                assessment["findings"].extend(rogue_devices)
                
                # Check network segmentation
                segmentation = await self._check_network_segmentation(network)
                assessment["findings"].extend(segmentation)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(assessment["findings"])
            assessment["risk_score"] = risk_score
            
            # Generate recommendations
            assessment["recommendations"] = self._generate_network_recommendations(assessment["findings"])
            
            return assessment
            
        except Exception as e:
            return {
                "error": f"Network security assessment failed: {str(e)}",
                "network": network
            }
    
    @tool
    async def compliance_check(
        self,
        *,
        target: str,
        framework: str = "general",
        requirements: Optional[List[str]] = None
    ) -> Dict:
        """
        Check compliance against security frameworks
        
        Args:
            target: Target IP address or hostname
            framework: Compliance framework - "general", "pci", "hipaa", "nist"
            requirements: Specific requirements to check (optional)
            
        Returns:
            Dictionary containing compliance check results
        """
        try:
            compliance_results = {
                "target": target,
                "framework": framework,
                "compliance_checks": [],
                "overall_compliance": 0,
                "failed_checks": [],
                "recommendations": []
            }
            
            # Define compliance checks based on framework
            checks = self._get_compliance_checks(framework)
            
            if requirements:
                # Filter checks based on specific requirements
                checks = [c for c in checks if c["requirement"] in requirements]
            
            # Perform compliance checks
            for check in checks:
                result = await self._perform_compliance_check(target, check)
                compliance_results["compliance_checks"].append(result)
                
                if not result["passed"]:
                    compliance_results["failed_checks"].append(result)
            
            # Calculate overall compliance score
            passed_checks = len([c for c in compliance_results["compliance_checks"] if c["passed"]])
            total_checks = len(compliance_results["compliance_checks"])
            compliance_results["overall_compliance"] = (passed_checks / total_checks * 100) if total_checks > 0 else 0
            
            # Generate recommendations for failed checks
            compliance_results["recommendations"] = [
                f"Fix {check['requirement']}: {check['description']}"
                for check in compliance_results["failed_checks"]
            ]
            
            return compliance_results
            
        except Exception as e:
            return {
                "error": f"Compliance check failed: {str(e)}",
                "target": target,
                "framework": framework
            }
    
    # Private helper methods
    async def _check_open_ports(self, target: str, ports: Optional[str] = None) -> List[Dict]:
        """Check for open ports on target"""
        try:
            # Simple port check implementation
            open_ports = []
            ports_to_check = self.common_ports if not ports else [int(p) for p in ports.split(',')]
            
            for port in ports_to_check:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append({"port": port, "protocol": "tcp", "state": "open"})
                sock.close()
            
            return open_ports
        except Exception:
            return []
    
    async def _check_port_vulnerabilities(self, port_info: Dict) -> List[Dict]:
        """Check for known vulnerabilities on specific ports"""
        vulnerabilities = []
        port = port_info["port"]
        
        # Known vulnerable ports and services
        vulnerable_ports = {
            21: {"service": "FTP", "issues": ["Anonymous access", "Weak encryption"]},
            23: {"service": "Telnet", "issues": ["Unencrypted protocol", "Weak authentication"]},
            135: {"service": "RPC", "issues": ["Buffer overflow vulnerabilities"]},
            445: {"service": "SMB", "issues": ["EternalBlue vulnerability", "Weak authentication"]},
            1433: {"service": "MSSQL", "issues": ["SQL injection", "Weak authentication"]},
            3389: {"service": "RDP", "issues": ["BlueKeep vulnerability", "Brute force attacks"]}
        }
        
        if port in vulnerable_ports:
            service_info = vulnerable_ports[port]
            for issue in service_info["issues"]:
                vulnerabilities.append({
                    "type": "service_vulnerability",
                    "port": port,
                    "service": service_info["service"],
                    "description": issue,
                    "severity": "high" if "vulnerability" in issue.lower() else "medium"
                })
        
        return vulnerabilities
    
    async def _check_ssl_vulnerabilities(self, target: str) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Check common SSL ports
        ssl_ports = [443, 993, 995, 8443]
        
        for port in ssl_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Port is open, check SSL
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cipher = ssock.cipher()
                        if cipher and any(weak in cipher[0] for weak in self.weak_ciphers):
                            vulnerabilities.append({
                                "type": "weak_ssl_cipher",
                                "port": port,
                                "description": f"Weak SSL cipher: {cipher[0]}",
                                "severity": "medium"
                            })
                sock.close()
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_weak_authentication(self, target: str) -> List[Dict]:
        """Check for weak authentication mechanisms"""
        vulnerabilities = []
        
        # Check for services with known default credentials
        default_creds = {
            22: [("admin", "admin"), ("root", "root"), ("admin", "password")],
            23: [("admin", "admin"), ("root", "root")],
            80: [("admin", "admin"), ("admin", "password")],
            21: [("anonymous", ""), ("ftp", "ftp")]
        }
        
        for port, creds in default_creds.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    vulnerabilities.append({
                        "type": "default_credentials_possible",
                        "port": port,
                        "description": f"Service on port {port} may use default credentials",
                        "severity": "high"
                    })
                sock.close()
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_web_vulnerabilities(self, target: str) -> List[Dict]:
        """Check for web application vulnerabilities"""
        vulnerabilities = []
        
        # Check for open web ports
        web_ports = [80, 8080, 8443, 443]
        
        for port in web_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, port))
                if result == 0:
                    vulnerabilities.append({
                        "type": "web_service_detected",
                        "port": port,
                        "description": f"Web service detected on port {port} - requires manual testing",
                        "severity": "info"
                    })
                sock.close()
            except Exception:
                pass
        
        return vulnerabilities
    
    async def _check_administrative_ports(self, network: str) -> List[Dict]:
        """Check for open administrative ports across network"""
        findings = []
        admin_ports = [22, 23, 3389, 5900, 5901]  # SSH, Telnet, RDP, VNC
        
        # This is a simplified implementation
        findings.append({
            "type": "administrative_access",
            "description": "Administrative ports should be restricted",
            "severity": "medium",
            "ports": admin_ports
        })
        
        return findings
    
    async def _check_default_credentials(self, network: str) -> List[Dict]:
        """Check for devices using default credentials"""
        findings = []
        
        findings.append({
            "type": "default_credentials",
            "description": "Devices may be using default credentials",
            "severity": "high",
            "recommendation": "Change all default passwords"
        })
        
        return findings
    
    async def _check_unencrypted_services(self, network: str) -> List[Dict]:
        """Check for unencrypted services"""
        findings = []
        
        unencrypted_ports = [21, 23, 80, 110, 143]  # FTP, Telnet, HTTP, POP3, IMAP
        
        findings.append({
            "type": "unencrypted_services",
            "description": "Unencrypted services detected",
            "severity": "medium",
            "ports": unencrypted_ports,
            "recommendation": "Use encrypted alternatives (SFTP, SSH, HTTPS, etc.)"
        })
        
        return findings
    
    async def _check_rogue_devices(self, network: str) -> List[Dict]:
        """Check for rogue devices on network"""
        findings = []
        
        findings.append({
            "type": "rogue_device_check",
            "description": "Network should be monitored for unauthorized devices",
            "severity": "medium",
            "recommendation": "Implement network access control (NAC)"
        })
        
        return findings
    
    async def _check_network_segmentation(self, network: str) -> List[Dict]:
        """Check network segmentation"""
        findings = []
        
        findings.append({
            "type": "network_segmentation",
            "description": "Network segmentation should be implemented",
            "severity": "medium",
            "recommendation": "Implement VLANs and firewall rules"
        })
        
        return findings
    
    def _calculate_risk_score(self, findings: List[Dict]) -> int:
        """Calculate overall risk score based on findings"""
        score = 0
        severity_scores = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        
        for finding in findings:
            severity = finding.get("severity", "low")
            score += severity_scores.get(severity, 1)
        
        return min(score, 100)  # Cap at 100
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "unknown")
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Generate recommendations
        for vuln_type, vulns in vuln_types.items():
            if vuln_type == "weak_ssl_cipher":
                recommendations.append("Update SSL/TLS configuration to use strong ciphers")
            elif vuln_type == "default_credentials_possible":
                recommendations.append("Change all default passwords and implement strong authentication")
            elif vuln_type == "service_vulnerability":
                recommendations.append("Update vulnerable services and apply security patches")
            elif vuln_type == "web_service_detected":
                recommendations.append("Perform web application security testing")
        
        return recommendations
    
    def _generate_network_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate network security recommendations"""
        recommendations = [
            "Implement network segmentation with VLANs",
            "Deploy network monitoring and intrusion detection",
            "Regularly update and patch all network devices",
            "Implement strong authentication and access controls",
            "Conduct regular security assessments",
            "Maintain an inventory of all network assets"
        ]
        
        return recommendations
    
    def _get_compliance_checks(self, framework: str) -> List[Dict]:
        """Get compliance checks for specific framework"""
        if framework == "pci":
            return [
                {"requirement": "PCI-DSS 2.1", "description": "Change default passwords", "check_type": "password"},
                {"requirement": "PCI-DSS 2.3", "description": "Encrypt non-console admin access", "check_type": "encryption"},
                {"requirement": "PCI-DSS 4.1", "description": "Use strong cryptography", "check_type": "crypto"}
            ]
        elif framework == "nist":
            return [
                {"requirement": "NIST-800-53 AC-2", "description": "Account management", "check_type": "access_control"},
                {"requirement": "NIST-800-53 SC-8", "description": "Transmission confidentiality", "check_type": "encryption"},
                {"requirement": "NIST-800-53 SI-2", "description": "Flaw remediation", "check_type": "patching"}
            ]
        else:
            return [
                {"requirement": "Strong Authentication", "description": "Implement strong authentication", "check_type": "password"},
                {"requirement": "Encryption", "description": "Use encryption for sensitive data", "check_type": "encryption"},
                {"requirement": "Access Control", "description": "Implement proper access controls", "check_type": "access_control"}
            ]
    
    async def _perform_compliance_check(self, target: str, check: Dict) -> Dict:
        """Perform individual compliance check"""
        # Simplified compliance check implementation
        result = {
            "requirement": check["requirement"],
            "description": check["description"],
            "check_type": check["check_type"],
            "passed": False,
            "details": ""
        }
        
        # This would contain actual compliance checking logic
        # For now, we'll return a simplified result
        if check["check_type"] == "password":
            result["passed"] = False
            result["details"] = "Default password check required"
        elif check["check_type"] == "encryption":
            result["passed"] = True
            result["details"] = "Encryption protocols detected"
        elif check["check_type"] == "access_control":
            result["passed"] = False
            result["details"] = "Access control assessment needed"
        
        return result
    
    @tool
    async def network_device_discovery(
        self,
        *,
        network: str = "192.168.1.0/24",
        timeout: int = 5,
        detailed: bool = True
    ) -> Dict:
        """
        Discover all devices on the network using nmap
        
        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            timeout: Timeout for each host probe
            detailed: Include detailed service detection
            
        Returns:
            Dictionary containing discovered devices and their information
        """
        try:
            import nmap
            nm = nmap.PortScanner()
            
            # Validate network CIDR
            ipaddress.IPv4Network(network, strict=False)
            
            discovered_devices = {
                "network": network,
                "scan_time": str(datetime.now()),
                "devices": [],
                "total_devices": 0,
                "node_red_flow": None
            }
            
            # Basic host discovery scan
            print(f"🔍 Scanning network {network} for devices...")
            scan_args = f"-sn --host-timeout {timeout}s"
            if detailed:
                scan_args = f"-sS -sV -O --host-timeout {timeout}s"
            
            result = nm.scan(hosts=network, arguments=scan_args)
            
            devices = []
            for host in nm.all_hosts():
                if nm[host].state() == "up":
                    device_info = {
                        "ip": host,
                        "hostname": nm[host].hostname() or "Unknown",
                        "state": nm[host].state(),
                        "mac_address": None,
                        "vendor": None,
                        "ports": [],
                        "os_info": {},
                        "services": []
                    }
                    
                    # Get MAC address and vendor if available
                    if 'mac' in nm[host]['addresses']:
                        device_info["mac_address"] = nm[host]['addresses']['mac']
                        device_info["vendor"] = nm[host]['vendor'].get(device_info["mac_address"], "Unknown")
                    
                    # Get OS information if available
                    if 'osmatch' in nm[host]:
                        os_matches = nm[host]['osmatch']
                        if os_matches:
                            device_info["os_info"] = {
                                "name": os_matches[0].get('name', 'Unknown'),
                                "accuracy": os_matches[0].get('accuracy', 0),
                                "line": os_matches[0].get('line', 'Unknown')
                            }
                    
                    # Get port and service information if detailed scan
                    if detailed and 'tcp' in nm[host]:
                        for port in nm[host]['tcp']:
                            port_info = {
                                "port": port,
                                "state": nm[host]['tcp'][port]['state'],
                                "service": nm[host]['tcp'][port].get('name', 'unknown'),
                                "version": nm[host]['tcp'][port].get('version', ''),
                                "product": nm[host]['tcp'][port].get('product', '')
                            }
                            device_info["ports"].append(port_info)
                            
                            # Add to services list for easy access
                            if port_info["service"] != "unknown":
                                device_info["services"].append({
                                    "name": port_info["service"],
                                    "port": port,
                                    "version": port_info["version"]
                                })
                    
                    devices.append(device_info)
            
            discovered_devices["devices"] = devices
            discovered_devices["total_devices"] = len(devices)
            
            # Generate Node-RED flow for discovered devices
            discovered_devices["node_red_flow"] = await self._generate_network_monitoring_flow(devices, network)
            
            print(f"✅ Found {len(devices)} devices on network {network}")
            return discovered_devices
            
        except Exception as e:
            return {
                "error": f"Network discovery failed: {str(e)}",
                "network": network,
                "devices": [],
                "total_devices": 0
            }

    @tool
    async def generate_node_red_flow(
        self,
        *,
        devices: List[Dict],
        network: str,
        flow_type: str = "monitoring"
    ) -> Dict:
        """
        Generate Node-RED flow JSON for network monitoring
        
        Args:
            devices: List of discovered devices
            network: Network CIDR
            flow_type: Type of flow - "monitoring", "alerting", "analysis"
            
        Returns:
            Dictionary containing Node-RED flow JSON
        """
        try:
            flow_name = f"Network-{flow_type.title()}-{network.replace('/', '_')}"
            flow_id = hashlib.md5(flow_name.encode()).hexdigest()[:8]
            
            nodes = []
            node_id_counter = 1
            
            # Create inject node for periodic scanning
            inject_node = {
                "id": f"inject-{node_id_counter}",
                "type": "inject",
                "z": flow_id,
                "name": "Trigger Scan",
                "repeat": "300",  # Every 5 minutes
                "crontab": "",
                "once": True,
                "topic": "",
                "payload": json.dumps({"network": network}),
                "payloadType": "json",
                "x": 120,
                "y": 80,
                "wires": [[f"function-{node_id_counter + 1}"]]
            }
            nodes.append(inject_node)
            node_id_counter += 1
            
            # Create function node for device monitoring
            function_code = f"""
// Network Experts - Device Monitoring Function
const network = msg.payload.network || '{network}';
const devices = {json.dumps(devices, indent=2)};

msg.payload = {{
    timestamp: new Date().toISOString(),
    network: network,
    devices: devices,
    active_devices: devices.length,
    scan_type: '{flow_type}'
}};

// Set topic for routing
msg.topic = 'network/devices';

return msg;
"""
            
            function_node = {
                "id": f"function-{node_id_counter}",
                "type": "function",
                "z": flow_id,
                "name": "Process Devices",
                "func": function_code,
                "outputs": 1,
                "noerr": 0,
                "x": 320,
                "y": 80,
                "wires": [[f"mqtt-{node_id_counter + 1}", f"debug-{node_id_counter + 2}"]]
            }
            nodes.append(function_node)
            node_id_counter += 1
            
            # Create MQTT output node
            mqtt_node = {
                "id": f"mqtt-{node_id_counter}",
                "type": "mqtt out",
                "z": flow_id,
                "name": "Publish to MQTT",
                "topic": "network_experts/devices",
                "qos": "1",
                "retain": "false",
                "broker": "mqtt-broker",
                "x": 540,
                "y": 60,
                "wires": []
            }
            nodes.append(mqtt_node)
            node_id_counter += 1
            
            # Create debug node
            debug_node = {
                "id": f"debug-{node_id_counter}",
                "type": "debug",
                "z": flow_id,
                "name": "Debug Output",
                "active": True,
                "tosidebar": True,
                "console": False,
                "tostatus": False,
                "complete": "payload",
                "x": 540,
                "y": 100,
                "wires": []
            }
            nodes.append(debug_node)
            node_id_counter += 1
            
            # Add device-specific monitoring nodes
            y_offset = 160
            for i, device in enumerate(devices[:5]):  # Limit to first 5 devices
                device_ip = device.get('ip', 'unknown')
                
                # Ping monitor for each device
                ping_node = {
                    "id": f"ping-{node_id_counter}",
                    "type": "ping",
                    "z": flow_id,
                    "name": f"Ping {device_ip}",
                    "host": device_ip,
                    "timer": "30",  # 30 seconds
                    "x": 120,
                    "y": y_offset,
                    "wires": [[f"switch-{node_id_counter + 1}"]]
                }
                nodes.append(ping_node)
                node_id_counter += 1
                
                # Switch node to filter ping results
                switch_node = {
                    "id": f"switch-{node_id_counter}",
                    "type": "switch",
                    "z": flow_id,
                    "name": "Check Status",
                    "property": "payload",
                    "rules": [
                        {"t": "false", "v": "", "vt": ""},
                        {"t": "else"}
                    ],
                    "checkall": "true",
                    "repair": False,
                    "outputs": 2,
                    "x": 320,
                    "y": y_offset,
                    "wires": [[f"alert-{node_id_counter + 1}"], [f"ok-{node_id_counter + 2}"]]
                }
                nodes.append(switch_node)
                node_id_counter += 1
                
                # Alert node for device down
                alert_node = {
                    "id": f"alert-{node_id_counter}",
                    "type": "function",
                    "z": flow_id,
                    "name": "Device Down Alert",
                    "func": f"""
msg.payload = {{
    alert: 'DEVICE_DOWN',
    device: '{device_ip}',
    hostname: '{device.get('hostname', 'Unknown')}',
    timestamp: new Date().toISOString(),
    severity: 'HIGH'
}};
msg.topic = 'network_experts/alerts';
return msg;
""",
                    "outputs": 1,
                    "x": 540,
                    "y": y_offset - 20,
                    "wires": [[f"mqtt-alert-{node_id_counter + 2}"]]
                }
                nodes.append(alert_node)
                node_id_counter += 1
                
                # OK status node
                ok_node = {
                    "id": f"ok-{node_id_counter}",
                    "type": "function",
                    "z": flow_id,
                    "name": "Device OK",
                    "func": f"""
msg.payload = {{
    status: 'DEVICE_UP',
    device: '{device_ip}',
    hostname: '{device.get('hostname', 'Unknown')}',
    timestamp: new Date().toISOString(),
    response_time: msg.ping || 0
}};
msg.topic = 'network_experts/status';
return msg;
""",
                    "outputs": 1,
                    "x": 540,
                    "y": y_offset + 20,
                    "wires": [[f"mqtt-status-{node_id_counter + 1}"]]
                }
                nodes.append(ok_node)
                node_id_counter += 1
                
                # MQTT alert output
                mqtt_alert_node = {
                    "id": f"mqtt-alert-{node_id_counter}",
                    "type": "mqtt out",
                    "z": flow_id,
                    "name": "Alert MQTT",
                    "topic": "",
                    "qos": "2",
                    "retain": "true",
                    "broker": "mqtt-broker",
                    "x": 760,
                    "y": y_offset - 20,
                    "wires": []
                }
                nodes.append(mqtt_alert_node)
                node_id_counter += 1
                
                # MQTT status output
                mqtt_status_node = {
                    "id": f"mqtt-status-{node_id_counter}",
                    "type": "mqtt out",
                    "z": flow_id,
                    "name": "Status MQTT",
                    "topic": "",
                    "qos": "1",
                    "retain": "false",
                    "broker": "mqtt-broker",
                    "x": 760,
                    "y": y_offset + 20,
                    "wires": []
                }
                nodes.append(mqtt_status_node)
                node_id_counter += 1
                
                y_offset += 80
            
            # Create the complete flow
            flow_json = [
                {
                    "id": flow_id,
                    "type": "tab",
                    "label": flow_name,
                    "disabled": False,
                    "info": f"Network monitoring flow for {network}\\nGenerated by Network Experts Team\\nDevices monitored: {len(devices)}"
                }
            ]
            
            # Add all nodes to the flow
            for node in nodes:
                flow_json.append(node)
            
            # Add MQTT broker configuration
            mqtt_broker_config = {
                "id": "mqtt-broker",
                "type": "mqtt-broker",
                "name": "Network Experts MQTT",
                "broker": "localhost",
                "port": "1883",
                "clientid": f"network-experts-{flow_id}",
                "usetls": False,
                "compatmode": False,
                "keepalive": "60",
                "cleansession": True,
                "birthTopic": "network_experts/status",
                "birthQos": "1",
                "birthPayload": "online",
                "closeTopic": "network_experts/status",
                "closeQos": "1",
                "closePayload": "offline",
                "willTopic": "network_experts/status",
                "willQos": "1",
                "willPayload": "offline"
            }
            flow_json.append(mqtt_broker_config)
            
            return {
                "flow_name": flow_name,
                "flow_id": flow_id,
                "node_count": len(nodes),
                "device_count": len(devices),
                "flow_json": flow_json,
                "mqtt_topics": [
                    "network_experts/devices",
                    "network_experts/alerts", 
                    "network_experts/status"
                ],
                "deployment_instructions": {
                    "1": "Copy the flow_json to Node-RED",
                    "2": "Import the flow using Ctrl+I",
                    "3": "Deploy the flow",
                    "4": "Monitor MQTT topics for network data"
                }
            }
            
        except Exception as e:
            return {
                "error": f"Node-RED flow generation failed: {str(e)}",
                "devices": len(devices) if devices else 0
            }

    async def _generate_network_monitoring_flow(self, devices: List[Dict], network: str) -> Dict:
        """Helper method to generate network monitoring flow"""
        return await self.generate_node_red_flow(devices=devices, network=network, flow_type="monitoring")
