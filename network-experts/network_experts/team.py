from typing import List
from .agents import ScannerBrother, SecurityBrother, MonitorBrother
from .handlers.mcp_handler import MCPHandler

class NetworkExpertsTeam:
    """Orchestrates collaboration between expert agents"""
    
    def __init__(self, mcp_endpoint: str, api_key: str):
        self.mcp = MCPHandler(mcp_endpoint, api_key)
        self.agents = [
            ScannerBrother(self.mcp),
            SecurityBrother(self.mcp),
            MonitorBrother(self.mcp)
        ]
        
    def deploy(self):
        """Activate all agents"""
        return [agent.activate() for agent in self.agents]