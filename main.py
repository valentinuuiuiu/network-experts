"""
Network Experts Team - Main Application
The Brotherhood of Network Security Specialists

Team Members:
- MQTT Brother: IoT network communication expert
- Node-RED Brother: Visual workflow automation expert  
- Scanner Brother: Network discovery and reconnaissance expert
- Security Brother: Vulnerability assessment and penetration testing expert
- Traffic Brother: Network traffic analysis and monitoring expert
"""

import asyncio
import logging
from typing import List, Dict, Any

from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.agentxpipe import AgentXPipe
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx.memory.storage import SQLiteManager
# from superagentx.handler.mcp import MCPHandler  # Not available in this version

from network_experts.handlers.mqtt_handler import MQTTHandler
from network_experts.handlers.node_red_handler import NodeRedHandler
from network_experts.handlers.network_scan import NetworkScanHandler

#configure llm
def configure_llm():
    """Configure LLM client"""
    return {
        "model": "gpt-4o-mini",
        "llm_type": "openai"
    }


async def demo_main():
    print("Welcome to the Network Experts Brotherhood!")
    llmconfig = {
        "model": "gpt-4o-mini",
        "llm_type": "openai"
        # Ensure you have set your OpenAI API key in the environment
        # export OPENAI_API_KEY=your_key
    }
    
    # Create the Network Experts Team with LLM config
    team = NetworkExpertsTeam(llm_config=llmconfig)
    await team.initialize_team()
    
    # Run a demo assessment
    results = await team.execute_mission("Perform a comprehensive network assessment of 192.168.1.0/24")
    print("Assessment Results:", results)
    

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkExpertsTeam:
    """
    The Network Experts Brotherhood - A team of specialized network security agents
    """
    
    def __init__(self, llm_config: Dict[str, Any]):
        self.llm_client = LLMClient(llm_config=llm_config)
        self.prompt_template = PromptTemplate()
        self.memory = SQLiteManager(db_path="network_experts.db")
        
        # Initialize handlers
        self.mqtt_handler = MQTTHandler()
        self.node_red_handler = NodeRedHandler()
        self.network_scanner = NetworkScanHandler()
        
        # Initialize MCP handler for external tool integration (commented out - not available in this version)
        # self.mcp_handler = MCPHandler(
        #     command="python",
        #     mcp_args=["-m", "network_experts.mcp_server"]
        # )
        
        self.agents = {}
        self.engines = {}
        self.team_pipe = None
        
    async def initialize_team(self):
        """Initialize all network expert agents"""
        
        # MQTT Brother - The IoT Communication Expert
        mqtt_engine = Engine(
            handler=self.mqtt_handler,
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        self.agents["mqtt_brother"] = Agent(
            name="MQTT Brother",
            goal="Manage MQTT broker operations and IoT device communications",
            role="""You are the MQTT Brother, an expert in IoT network communications.
            Your specialties include:
            - Discovering MQTT brokers in networks
            - Publishing and subscribing to MQTT topics
            - Analyzing MQTT traffic patterns
            - Managing IoT device communications
            - Troubleshooting MQTT connectivity issues
            
            You work closely with your brothers to provide comprehensive network analysis.""",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[mqtt_engine],
            max_retry=3
        )
        
        # Node-RED Brother - The Workflow Automation Expert
        node_red_engine = Engine(
            handler=self.node_red_handler,
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        self.agents["node_red_brother"] = Agent(
            name="Node-RED Brother",
            goal="Create and manage visual automation workflows",
            role="""You are the Node-RED Brother, an expert in visual programming and automation.
            Your specialties include:
            - Creating network monitoring flows
            - Managing Node-RED deployments
            - Building automation workflows
            - Integrating different network tools
            - Visual programming and flow design
            
            You help orchestrate complex network operations through visual workflows.""",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[node_red_engine],
            max_retry=3
        )
        
        # Scanner Brother - The Network Discovery Expert
        scanner_engine = Engine(
            handler=self.network_scanner,
            llm=self.llm_client,
            prompt_template=self.prompt_template
        )
        
        self.agents["scanner_brother"] = Agent(
            name="Scanner Brother",
            goal="Discover and analyze network infrastructure",
            role="""You are the Scanner Brother, an expert in network discovery and reconnaissance.
            Your specialties include:
            - Network host discovery
            - Port scanning and service detection
            - Network topology mapping
            - Asset inventory management
            - Infrastructure reconnaissance
            
            You provide the foundation for all network security operations.""",
            llm=self.llm_client,
            prompt_template=self.prompt_template,
            engines=[scanner_engine],
            max_retry=3
        )
        
        # MCP Integration Brother - The External Tools Expert (commented out - MCP not available)
        # mcp_engine = Engine(
        #     handler=self.mcp_handler,
        #     llm=self.llm_client,
        #     prompt_template=self.prompt_template
        # )
        
        # MCP Integration Brother - commented out (MCP not available in this version)
        # self.agents["mcp_brother"] = Agent(
        #     name="MCP Integration Brother",
        #     goal="Integrate external network tools and services",
        #     role="""You are the MCP Integration Brother, an expert in tool integration.
        #     Your specialties include:
        #     - Coordinating with external MCP servers
        #     - Integrating third-party network tools
        #     - Managing complex tool workflows
        #     - Orchestrating multi-tool operations
        #     - Providing unified access to distributed tools
        #     
        #     You ensure seamless integration of all network analysis capabilities.""",
        #     llm=self.llm_client,
        #     prompt_template=self.prompt_template,
        #     engines=[mcp_engine],
        #     max_retry=3
        # )
        
        # Create the team pipeline
        self.team_pipe = AgentXPipe(
            pipe_id="network-experts-team",
            name="Network Experts Brotherhood",
            description="""The Network Experts Brotherhood is an elite team of specialized 
            network security agents working together to provide comprehensive network analysis,
            security assessment, and automation capabilities. Each brother brings unique 
            expertise while working collaboratively to achieve network security objectives.""",
            agents=list(self.agents.values()),
            memory=self.memory,
            stop_if_goal_not_satisfied=False
        )
        
        logger.info("Network Experts Team initialized successfully!")
        
    async def execute_mission(self, mission_brief: str) -> Dict[str, Any]:
        """
        Execute a network security mission using the brotherhood
        
        Args:
            mission_brief: Description of the network security task
            
        Returns:
            Mission execution results
        """
        logger.info(f"🎯 Network Experts Team executing mission: {mission_brief}")
        
        try:
            result = await self.team_pipe.ask(
                query_instruction=mission_brief
            )
            
            logger.info("✅ Mission completed successfully!")
            return {
                "status": "success",
                "mission": mission_brief,
                "results": result,
                "team_members": list(self.agents.keys())
            }
            
        except Exception as e:
            logger.error(f"❌ Mission failed: {e}")
            return {
                "status": "error",
                "mission": mission_brief,
                "error": str(e),
                "team_members": list(self.agents.keys())
            }
    
    async def get_team_status(self) -> Dict[str, Any]:
        """Get status of all team members"""
        status = {
            "team_name": "Network Experts Brotherhood",
            "total_members": len(self.agents),
            "members": {}
        }
        
        for name, agent in self.agents.items():
            status["members"][name] = {
                "name": agent.name,
                "goal": agent.goal,
                "role_summary": agent.role.split('.')[0] if agent.role else "Network Expert",
                "engines_count": len(agent.engines) if agent.engines else 0,
                "status": "ready"
            }
            
        return status
    
    async def cleanup(self):
        """Clean up resources"""
        try:
            await self.mqtt_handler.cleanup()
            await self.node_red_handler.cleanup()
            logger.info("Network Experts Team cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


async def main():
    """
    Main function to demonstrate Network Experts Team
    """
    print("🚀 Network Experts Team - Initializing...")
    print("=" * 60)
    
    # LLM Configuration
    llm_config = configure_llm()

    # Initialize the Network Experts Team
    network_team = NetworkExpertsTeam(llm_config)
    await network_team.initialize_team()
    
    # Get team status
    team_status = await network_team.get_team_status()
    print("🔐 Network Experts Brotherhood Status:")
    print(f"   Team: {team_status['team_name']}")
    print(f"   Members: {team_status['total_members']}")
    for member_id, member_info in team_status['members'].items():
        print(f"   - {member_info['name']}: {member_info['status']}")
    
    # Example missions
    missions = [
        """Discover all MQTT brokers in the 192.168.1.0/24 network range and 
        create a Node-RED flow to monitor their status every 5 minutes. 
        Publish the monitoring results to the 'network/mqtt/status' topic.""",
        
        """Perform a comprehensive network scan of 192.168.1.1 to identify 
        open ports and services, then analyze any MQTT traffic on discovered 
        brokers and create an automated monitoring workflow.""",
        
        """Set up network monitoring infrastructure: scan for active hosts, 
        discover MQTT brokers, create Node-RED monitoring flows, and establish 
        automated alerting for any network changes."""
    ]
    
    # Execute missions
    for i, mission in enumerate(missions, 1):
        print(f"\n🎯 Mission {i}:")
        print(f"   {mission[:100]}...")
        
        result = await network_team.execute_mission(mission)
        
        if result["status"] == "success":
            print(f"   ✅ Mission {i} completed successfully!")
        else:
            print(f"   ❌ Mission {i} failed: {result.get('error', 'Unknown error')}")
    
    # Cleanup
    await network_team.cleanup()
    print("\n🔐 Network Experts Brotherhood mission complete!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
