import os
import asyncio
from openai import AsyncOpenAI
from network_experts.intelligent_agents import IntelligentAgent
from network_experts.handlers.mcp_handler import MCPHandler

async def test_agents():
    # Initialize with environment variable
    client = AsyncOpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    
    # Test scenario - Network vulnerability assessment
    scenario = {
        "network": "192.168.1.0/24",
        "services": ["HTTP", "SSH"],
        "threat_level": "medium"
    }
    
    # Using mock endpoint for testing
    mcp = MCPHandler("http://localhost:54945/mock-mcp", "test-key")
    print("⚠️ Using mock MCP endpoint - real integrations will need valid credentials")
    scanner = IntelligentAgent(
        name="QuantumScanner",
        mcp_handler=mcp,
        llm_client=client,
        cognitive_config={
            "model": "gpt-4.1-mini",
            "temperature": 0.7,
            "max_tokens": 500
        }
    )
    
    print("🚀 Testing network scan cognition...")
    response = await scanner.think(
        f"Analyze this network scenario: {scenario}\n"
        "Provide:\n1. Potential vulnerabilities\n"
        "2. Recommended scans\n3. Security priorities"
    )
    return response

if __name__ == "__main__":
    result = asyncio.run(test_agents())
    print("\n🔍 Test Results:")
    print(result)