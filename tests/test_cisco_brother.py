import asyncio
import pytest
from network_experts.agents.cisco_brother import CiscoBrother
from network_experts.handlers.simulation_handler import SimulationHandler
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate

@pytest.mark.asyncio
async def test_cisco_brother_simulation():
    # Create a new simulation handler
    simulation_handler = SimulationHandler()

    # Add a Cisco device to the simulation
    simulation_handler.add_node("cisco_router", "cisco_ios")

    # Create mock LLMClient and PromptTemplate objects
    llm_client = LLMClient(llm_config={"model": "gpt-4o-mini", "llm_type": "openai", "api_key": "test"})
    prompt_template = PromptTemplate()

    # Create a new CiscoBrother instance
    cisco_brother = CiscoBrother(mcp_handler=None, llm_client=llm_client, prompt_template=prompt_template)

    # Execute a command in the simulated environment
    output = await cisco_brother.execute_simulation_command("cisco_router", "show running-config", simulation_handler)

    # Check that the output is correct
    assert "Running configuration for cisco_router" in output
