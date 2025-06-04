import asyncio
import pytest
from network_experts.intelligent_agents import IntelligentAgent
from a2a.protocol import A2AMessage
from core.config import config

class TestAgentCommunication:
    """End-to-end agent communication tests"""
    
    @pytest.fixture
    def agents(self):
        return [
            IntelligentAgent(name="AGENT_ALPHA", mcp_handler=None),
            IntelligentAgent(name="AGENT_BETA", mcp_handler=None)
        ]

    @pytest.mark.asyncio
    async def test_a2a_message_flow(self, agents):
        sender, receiver = agents
        
        test_msg = A2AMessage(
            sender=sender.name,
            recipients=[receiver.name],
            content={
                "protocol": "A2A",
                "test": "integration",
                "security": {
                    "hf_token_check": sender.hf_token[:4] + "****",
                    "llm_model": sender.llm["model"]
                }
            }
        )

        # Verify credential loading
        assert sender.hf_token == config.hf_token
        assert sender.llm["api_key"] == config.openai_key
        
        # Test communication
        success = await sender.a2a.send(test_msg)
        assert success is True
        
        print(f"\nTest passed - Message ID: {test_msg.message_id}")
        print(f"Agents successfully using:")
        print(f"- HF Token: {sender.hf_token[:4]}****")
        print(f"- LLM Model: {sender.llm['model']}")
        print(f"- A2A Server: {config.a2a_server_url}")

if __name__ == "__main__":
    import pytest
    pytest.main(["-v", __file__])