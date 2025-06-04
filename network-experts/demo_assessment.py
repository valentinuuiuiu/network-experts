#!/usr/bin/env python3
"""
Network Experts Team Demo - Live Network Assessment
Author: Ionut-Valentin Baltag (Certified Ethical Hacker)
"""
import asyncio
import json
import os
from typing import Dict, Any

from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx.agentxpipe import AgentXPipe

# Import our Network Expert handlers
from network_experts.handlers.security_audit import SecurityAuditHandler
from network_experts.handlers.network_monitor import NetworkMonitorHandler
from network_experts.handlers.traffic_analyzer import TrafficAnalyzerHandler


class NetworkExpertsTeam:
    """The Network Experts Brothers - Professional Network Assessment Team"""
    
    def __init__(self):
        # Initialize LLM client (ensure OPENAI_API_KEY is set)
        self.llm_config = {
            'model': 'gpt-4',
            'llm_type': 'openai'
        }
        self.llm_client = LLMClient(llm_config=self.llm_config)
        self.prompt_template = PromptTemplate()
        
        # Initialize handlers
        self.security_handler = SecurityAuditHandler()
        self.monitor_handler = NetworkMonitorHandler()
        self.traffic_handler = TrafficAnalyzerHandler()
        
        # Create the expert agents
        self.agents = self._create_expert_agents()
        
    def _create_expert_agents(self) -> Dict[str, Agent]:
        """Create the specialized network expert agents"""
        
        # Guardian Brother - Security Expert
        security_engine = Engine(
            handler=self.security_handler,
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        guardian_agent = Agent(
            name="Guardian",
            goal="Assess network security and identify vulnerabilities",
            role="Security Expert and Penetration Tester",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[security_engine],
            description="Expert in network security assessment and vulnerability analysis"
        )
        
        # Watcher Brother - Network Monitor
        monitor_engine = Engine(
            handler=self.monitor_handler,
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        watcher_agent = Agent(
            name="Watcher",
            goal="Monitor network performance and device status",
            role="Network Monitoring Specialist",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[monitor_engine],
            description="Specialist in real-time network monitoring and performance analysis"
        )
        
        # Analyzer Brother - Traffic Expert
        traffic_engine = Engine(
            handler=self.traffic_handler,
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        analyzer_agent = Agent(
            name="Analyzer",
            goal="Analyze network traffic patterns and detect anomalies",
            role="Traffic Analysis Expert",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[traffic_engine],
            description="Expert in network traffic analysis and anomaly detection"
        )
        
        return {
            "guardian": guardian_agent,
            "watcher": watcher_agent,
            "analyzer": analyzer_agent
        }
    
    async def assess_network(self, target_network: str = "192.168.1.0/24") -> Dict[str, Any]:
        """
        Complete network assessment by the Network Experts team
        
        Args:
            target_network: Network CIDR to assess (default: 192.168.1.0/24)
            
        Returns:
            Complete assessment report with Node-RED flows
        """
        print("🚀 Network Experts Team - Starting Network Assessment")
        print("=" * 60)
        print(f"👤 Lead by: Ionut-Valentin Baltag (Certified Ethical Hacker)")
        print(f"🎯 Target Network: {target_network}")
        print("👥 Team Members: Guardian, Watcher, Analyzer")
        print("=" * 60)
        
        assessment_results = {
            "network": target_network,
            "team_lead": "Ionut-Valentin Baltag",
            "certification": "HackerX Ethical Hacking - Leveraging AI for Hacking",
            "assessment_time": "",
            "device_discovery": {},
            "security_audit": {},
            "network_monitoring": {},
            "traffic_analysis": {},
            "node_red_flows": {},
            "recommendations": []
        }
        
        try:
            # Step 1: Guardian discovers devices and performs security audit
            print("\\n🛡️  Guardian Brother - Starting Device Discovery & Security Audit")
            discovery_result = await self.agents["guardian"].execute(
                query_instruction=f"Discover all devices on network {target_network} and perform a comprehensive security audit. Include detailed device information and create Node-RED monitoring flows."
            )
            if discovery_result is not None and hasattr(discovery_result, 'result'):
                assessment_results["device_discovery"] = discovery_result.result
            else:
                assessment_results["device_discovery"] = discovery_result
            
            # Step 2: Watcher sets up network monitoring
            print("\\n👁️  Watcher Brother - Setting Up Network Monitoring")
            monitoring_result = await self.agents["watcher"].execute(
                query_instruction=f"Set up comprehensive network monitoring for {target_network}. Monitor device availability, performance metrics, and create alerting systems."
            )
            if monitoring_result is not None and hasattr(monitoring_result, 'result'):
                assessment_results["network_monitoring"] = monitoring_result.result
            else:
                assessment_results["network_monitoring"] = monitoring_result
            
            # Step 3: Analyzer examines traffic patterns
            print("\\n📊 Analyzer Brother - Analyzing Network Traffic")
            traffic_result = await self.agents["analyzer"].execute(
                query_instruction=f"Analyze network traffic patterns on {target_network}. Identify top talkers, protocols, and any suspicious activity."
            )
            if traffic_result is not None and hasattr(traffic_result, 'result'):
                assessment_results["traffic_analysis"] = traffic_result.result
            else:
                assessment_results["traffic_analysis"] = traffic_result
            
            # Generate comprehensive Node-RED flows
            print("\\n🔧 Generating Node-RED Integration Flows")
            assessment_results["node_red_flows"] = await self._generate_comprehensive_flows(assessment_results)
            
            # Generate final recommendations
            assessment_results["recommendations"] = await self._generate_recommendations(assessment_results)
            
            print("\\n✅ Network Assessment Complete!")
            return assessment_results
            
        except Exception as e:
            print(f"❌ Assessment failed: {str(e)}")
            assessment_results["error"] = str(e)
            return assessment_results
    
    async def _generate_comprehensive_flows(self, assessment_data: Dict) -> Dict[str, Any]:
        """Generate comprehensive Node-RED flows for the entire network"""
        flows = {
            "monitoring_flow": {},
            "security_flow": {},
            "alerting_flow": {},
            "dashboard_flow": {}
        }
        
        try:
            # Extract device data for flow generation
            devices = []
            if "device_discovery" in assessment_data:
                discovery_data = assessment_data["device_discovery"]
                if isinstance(discovery_data, dict) and "devices" in discovery_data:
                    devices = discovery_data["devices"]
            
            if devices:
                # Generate monitoring flow
                flows["monitoring_flow"] = await self.security_handler.generate_node_red_flow(
                    devices=devices,
                    network=assessment_data.get("network", "192.168.1.0/24"),
                    flow_type="monitoring"
                )
                
                # Generate security alerting flow
                flows["security_flow"] = await self._generate_security_flow(devices, assessment_data)
                
                # Generate dashboard flow
                flows["dashboard_flow"] = await self._generate_dashboard_flow(devices, assessment_data)
            
        except Exception as e:
            flows["error"] = {"message": f"Flow generation failed: {str(e)}"}
        
        return flows
    
    async def _generate_security_flow(self, devices: list, assessment_data: Dict) -> Dict:
        """Generate security-focused Node-RED flow"""
        # Implementation for security-specific flow
        return {
            "flow_type": "security_monitoring",
            "mqtt_topics": [
                "network_experts/security/vulnerabilities",
                "network_experts/security/threats",
                "network_experts/security/compliance"
            ],
            "status": "generated"
        }
    
    async def _generate_dashboard_flow(self, devices: list, assessment_data: Dict) -> Dict:
        """Generate dashboard Node-RED flow"""
        # Implementation for dashboard flow
        return {
            "flow_type": "network_dashboard",
            "widgets": ["device_map", "traffic_chart", "security_alerts"],
            "status": "generated"
        }
    
    async def _generate_recommendations(self, assessment_data: Dict) -> list:
        """Generate security and performance recommendations"""
        recommendations = [
            {
                "category": "Security",
                "priority": "High",
                "recommendation": "Implement network segmentation to isolate critical devices",
                "rationale": "Based on device discovery results"
            },
            {
                "category": "Monitoring", 
                "priority": "Medium",
                "recommendation": "Deploy continuous network monitoring with MQTT integration",
                "rationale": "Real-time visibility into network health"
            },
            {
                "category": "Performance",
                "priority": "Medium", 
                "recommendation": "Optimize traffic patterns based on analysis results",
                "rationale": "Improve overall network efficiency"
            }
        ]
        return recommendations


async def main():
    """Main demo function"""
    print("🌟 Network Experts Team - Professional Network Assessment")
    print("Lead by: Ionut-Valentin Baltag (Certified Ethical Hacker)")
    print("Certificate: HackerX - Leveraging AI for Hacking\\n")
    
    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️  Please set your OPENAI_API_KEY environment variable")
        print("Example: export OPENAI_API_KEY='your-api-key-here'")
        return
    
    # Initialize the team
    team = NetworkExpertsTeam()
    
    # Get target network from user or use default
    target_network = input("Enter target network (default: 192.168.1.0/24): ").strip()
    if not target_network:
        target_network = "192.168.1.0/24"
    
    # Perform assessment
    results = await team.assess_network(target_network)
    
    # Save results to file
    output_file = f"network_assessment_{target_network.replace('/', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\\n📄 Assessment results saved to: {output_file}")
    
    # Display summary
    print("\\n📋 Assessment Summary:")
    print("-" * 40)
    if "device_discovery" in results:
        device_count = len(results["device_discovery"].get("devices", []))
        print(f"🔍 Devices discovered: {device_count}")
    
    if "recommendations" in results:
        rec_count = len(results["recommendations"])
        print(f"💡 Recommendations: {rec_count}")
    
    if "node_red_flows" in results:
        flows = results["node_red_flows"]
        if isinstance(flows, dict):
            flow_count = sum(1 for v in flows.values() if v and not isinstance(v, str))
            print(f"🔧 Node-RED flows generated: {flow_count}")
    
    print("\\n✨ Network assessment complete! The Network Experts have done their job.")


if __name__ == "__main__":
    asyncio.run(main())
