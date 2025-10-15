from superagentx.agent import Agent
from typing import Optional
from network_experts.handlers.traffic_analyzer import TrafficAnalyzerHandler

class TrafficBrother(Agent):
    """Network Traffic Analysis Specialist"""

    def __init__(self, traffic_analyzer: TrafficAnalyzerHandler, llm_client: Optional = None):
        super().__init__(
            name="Traffic Brother",
            goal="Analyze network traffic and identify patterns",
            role="""Expert in network traffic analysis with capabilities including:
            - Deep packet inspection
            - Protocol analysis
            - Flow analysis
            - Anomaly detection""",
            llm=llm_client,
            engines=[traffic_analyzer],
            access_level="read"
        )
        self.knowledge_base = {}

    async def analyze_traffic(self, pcap_file: str):
        """Analyze network traffic from a PCAP file"""
        return await self.engines[0].analyze_traffic(pcap_file=pcap_file)
