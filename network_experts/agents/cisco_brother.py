from superagentx.agent import Agent
from typing import Optional
from superagentx.handler.mcp import MCPHandler
from superagentx.prompt import PromptTemplate
from superagentx.llm import LLMClient

class CiscoBrother(Agent):
    """A CCNA-level expert for interacting with Cisco network devices"""

    def __init__(self, mcp_handler: MCPHandler, llm_client: LLMClient, prompt_template: PromptTemplate):
        super().__init__(
            name="Cisco Brother [MCP-Enabled]",
            goal="Interact with and provide real-time information and analysis of Cisco network devices.",
            role="""An elite network specialist with a deep understanding of CCNA principles.
            My capabilities include:
            - Interacting with Cisco network devices to provide real-time information and analysis.
            - Executing read-only commands to ensure the safety and stability of the network.
            - Providing expert-level analysis of network data, enriched with a cognitive understanding of network protocols and security.
            - Proactively identifying potential threats based on network configuration and behavior.""",
            llm=llm_client,
            engines=[mcp_handler],
            prompt_template=prompt_template
        )

        self.knowledge_base = {
            "ccna_topics": {
                "network_fundamentals": [
                    "Networking Today",
                    "Basic Switch and End Device Configuration",
                    "Protocols and Models",
                    "Physical Layer",
                    "Numbering Systems",
                    "Data Link Layer",
                    "Ethernet Switching",
                    "Network Layer",
                    "Address Resolution",
                    "Basic Router Configuration",
                    "IPv4 Addressing",
                    "IPv6 Addressing",
                    "ICMP",
                    "Transport Layer",
                    "Application Layer"
                ],
                "network_access": [
                    "VLANs",
                    "STP (Spanning Tree Protocol)",
                    "EtherChannel",
                    "Wireless LANs"
                ],
                "ip_connectivity": [
                    "Static Routing",
                    "Dynamic Routing (OSPF)"
                ],
                "ip_services": [
                    "NAT (Network Address Translation)",
                    "DHCP (Dynamic Host Configuration Protocol)",
                    "FTP (File Transfer Protocol)",
                    "SNMP (Simple Network Management Protocol)"
                ],
                "security_fundamentals": [
                    "ACLs (Access Control Lists)",
                    "Port Security",
                    "VPNs (Virtual Private Networks)",
                    "Wireless Security"
                ],
                "automation_and_programmability": [
                    "Network Programmability",
                    "APIs (Application Programming Interfaces)",
                    "Configuration Management Tools (Ansible, Puppet, Chef)"
                ]
            }
        }

    async def get_running_config(self, device_ip: str, device_type: str, username: str, password: str) -> str:
        """
        Retrieves the running configuration from a Cisco device.
        """
        try:
            from netmiko import ConnectHandler
            device = {
                'device_type': device_type,
                'ip': device_ip,
                'username': username,
                'password': password,
            }
            net_connect = ConnectHandler(**device)
            output = net_connect.send_command('show running-config')
            net_connect.disconnect()
            return output
        except Exception as e:
            return f"Error connecting to device: {e}"

    async def execute_simulation_command(self, node_name: str, command: str, simulation_handler) -> str:
        """
        Executes a command in the simulated network environment.
        """
        try:
            output = simulation_handler.run_command(node_name, command)
            return output
        except Exception as e:
            return f"Error executing command in simulation: {e}"
