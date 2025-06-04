import pytest
import asyncio
from gradio_interface import GradioInterface
from a2a.protocol import A2AMessage

class TestGradioInterface:
    @pytest.fixture
    def interface(self):
        return GradioInterface()

    @pytest.mark.asyncio
    async def test_agent_selection(self, interface):
        assert "Network Analyst" in interface.agents
        assert interface.agents["Network Analyst"] == "agent_analyst"

    @pytest.mark.asyncio
    async def test_message_exchange(self, interface, mocker):
        # Mock A2A client response
        mock_response = A2AMessage(
            sender="agent_analyst",
            recipients=["human_operator"],
            content={"text": "Analysis started for 192.168.1.0/24"}
        )
        mocker.patch.object(interface.a2a, 'send', return_value=mock_response)

        history = []
        test_msg = "Analyze 192.168.1.0/24 network"
        
        history, _ = await interface.send_message(
            "Network Analyst",
            test_msg,
            history
        )
        
        assert len(history) == 1
        assert history[0][0] == test_msg
        assert "started" in history[0][1].lower()
        interface.a2a.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_error_handling(self, interface):
        history = []
        history, error = await interface.send_message(
            "Invalid Agent",
            "Test message",
            history
        )
        assert "Error" in error