"""
Network Experts Team - Main Application
The Brotherhood of Network Security Specialists
"""

import asyncio
import logging
from typing import Dict, Any

import gradio as gr
from superagentx.agentxpipe import AgentXPipe
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx.memory.storage import SQLiteManager
from superagentx.handler.mcp import MCPHandler

from network_experts.handlers.mqtt_handler import MQTTHandler
from network_experts.handlers.node_red_handler import NodeRedHandler
from network_experts.handlers.network_scan import NetworkScanHandler
from network_experts.handlers.traffic_analyzer import TrafficAnalyzerHandler

from network_experts.agents.mqtt_brother import MQTTBrother
from network_experts.agents.node_red_brother import NodeRedBrother
from network_experts.agents.scanner_brother import ScannerBrother
from network_experts.agents.traffic_brother import TrafficBrother
from network_experts.agents.cisco_brother import CiscoBrother
from core.config import config
from a2a.protocol import A2AClient, A2AMessage

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
        self.traffic_analyzer = TrafficAnalyzerHandler()

        # Initialize MCP handler for external tool integration
        self.mcp_handler = MCPHandler(
            command="python",
            mcp_args=["-m", "network_experts.mcp_server"]
        )

        self.agents = {}
        self.team_pipe = None

    async def initialize_team(self):
        """Initialize all network expert agents"""

        # MQTT Brother - The IoT Communication Expert
        self.agents["mqtt_brother"] = MQTTBrother(
            llm_client=self.llm_client,
            prompt_template=self.prompt_template,
            mqtt_handler=self.mqtt_handler
        )

        # Node-RED Brother - The Workflow Automation Expert
        self.agents["node_red_brother"] = NodeRedBrother(
            llm_client=self.llm_client,
            prompt_template=self.prompt_template,
            node_red_handler=self.node_red_handler
        )

        # Scanner Brother - The Network Discovery Expert
        self.agents["scanner_brother"] = ScannerBrother(
            llm_client=self.llm_client,
            prompt_template=self.prompt_template,
            network_scanner=self.network_scanner
        )

        # Traffic Brother - The Network Traffic Analysis Expert
        self.agents["traffic_brother"] = TrafficBrother(
            llm_client=self.llm_client,
            traffic_analyzer=self.traffic_analyzer
        )

        # Cisco Brother - The Cisco Network Expert
        self.agents["cisco_brother"] = CiscoBrother(
            llm_client=self.llm_client,
            mcp_handler=self.mcp_handler
        )

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


class GradioInterface:
    """Real-time A2A communication interface for Hugging Face Spaces"""

    def __init__(self, network_team: NetworkExpertsTeam):
        self.network_team = network_team
        self.agents = {
            "Network Analyst": "agent_analyst",
            "Security Expert": "agent_security",
            "Protocol Specialist": "agent_protocol"
        }
        self.a2a = A2AClient(config.a2a_server_url)

    async def send_message(self, agent, message, history):
        """Handle message sending and response processing"""
        try:
            # The A2A protocol is not fully implemented yet,
            # so we'll just call the execute_mission method directly
            response = await self.network_team.execute_mission(message)
            history.append((message, response["results"]))
            return history, ""
        except Exception as e:
            return history, f"Error: {str(e)}"

    def create_interface(self):
        """Build Gradio interface components"""
        with gr.Blocks(theme=gr.themes.Soft(), title="Network Experts A2A") as demo:
            gr.Markdown("## 🤖 Network Experts Communication Hub")
            gr.Markdown(f"Connected to A2A server: `{config.a2a_server_url}`")

            with gr.Row():
                with gr.Column(scale=1):
                    agent = gr.Dropdown(
                        label="Select Expert Agent",
                        choices=list(self.agents.keys()),
                        value="Network Analyst"
                    )
                    status = gr.Textbox("🟢 System Online", label="Connection Status")

                with gr.Column(scale=3):
                    chatbot = gr.Chatbot(height=400, label="Conversation")
                    msg = gr.Textbox(label="Your Message", placeholder="Type your query...")
                    send = gr.Button("Send")
                    clear = gr.Button("Clear History")

            msg.submit(
                self.send_message,
                [agent, msg, chatbot],
                [chatbot, msg],
                queue=False
            )
            send.click(
                self.send_message,
                [agent, msg, chatbot],
                [chatbot, msg],
                queue=False
            )
            clear.click(lambda: [], None, chatbot, queue=False)

        return demo


async def main():
    """
    Main function to initialize the Network Experts Team and launch the Gradio interface
    """
    # LLM Configuration
    llm_config = {
        "model": "gpt-4o-mini",
        "llm_type": "openai"
    }

    # Initialize the Network Experts Team
    network_team = NetworkExpertsTeam(llm_config)
    await network_team.initialize_team()

    # Create and launch the Gradio interface
    gradio_interface = GradioInterface(network_team)
    demo = gradio_interface.create_interface()
    demo.queue().launch(server_name="0.0.0.0", server_port=7860)


if __name__ == "__main__":
    asyncio.run(main())
