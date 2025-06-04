from typing import Any, Dict, List, Optional
import aiohttp
import numpy as np
from ..intelligent_agents import IntelligentAgent

class MCPHandler:
    """Enhanced MCP Handler with cognitive capabilities"""
    
    def __init__(self, 
                 mcp_endpoint: str, 
                 api_key: str,
                 cognitive_config: Optional[Dict] = None):
        self.endpoint = mcp_endpoint
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Cognitive-Enabled": "true"
        }
        self.cognitive_layer = self._init_cognitive_layer(cognitive_config)
        
    def _init_cognitive_layer(self, config):
        """Initialize cognitive processing capabilities"""
        return {
            'reasoning_engine': True,
            'memory_buffer': [],
            'learning_rate': config.get('learning_rate', 0.01) if config else 0.01
        }
    
    async def execute(self, 
                     payload: Dict[str, Any], 
                     agents: Optional[List[IntelligentAgent]] = None) -> Dict[str, Any]:
        """Enhanced execution with cognitive processing"""
        if agents:
            payload['cognitive_context'] = [agent.cognition.state for agent in agents]
            
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.endpoint}/v2/execute",
                json=payload,
                headers=self.headers
            ) as response:
                result = await response.json()
                if agents and 'learning_data' in result:
                    for agent in agents:
                        await agent.learn(result['learning_data'])
                return result