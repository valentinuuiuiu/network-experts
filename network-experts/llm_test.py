#!/usr/bin/env python3
"""
Simple LLM Test - Prove that SuperAgentX calls OpenAI
"""
import asyncio
import os
from superagentx.agent import Agent
from superagentx.engine import Engine
from superagentx.llm import LLMClient
from superagentx.prompt import PromptTemplate
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool


class SimpleTestHandler(BaseHandler):
    """Simple test handler"""
    
    @tool
    async def get_current_time(self) -> str:
        """
        Get the current time.
        
        Returns:
            Current time as string
        """
        from datetime import datetime
        return f"Current time: {datetime.now().strftime('%H:%M:%S')}"


async def test_llm():
    """Test if LLM is actually being called"""
    print("🧪 Testing LLM Integration...")
    
    # Configure LLM
    llm_config = {
        "model": "gpt-4o-mini", 
        "llm_type": "openai"
    }
    llm_client = LLMClient(llm_config=llm_config)
    prompt_template = PromptTemplate()
    
    # Create simple engine
    engine = Engine(
        handler=SimpleTestHandler(),
        llm=llm_client,
        prompt_template=prompt_template
    )
    
    # Create agent
    agent = Agent(
        name="TestAgent",
        goal="Answer user questions using available tools",
        role="You are a helpful assistant that can tell time",
        llm=llm_client,
        prompt_template=prompt_template,
        engines=[engine]
    )
    
    # Test with a simple question that requires LLM reasoning
    print("🤖 Asking agent: 'What time is it and what should I do next?'")
    
    result = await agent.execute(
        query_instruction="What time is it and what should I do next? Give me some advice."
    )
    
    print(f"🎯 Agent Response: {result}")
    return result


async def main():
    if not os.getenv('OPENAI_API_KEY'):
        print("❌ Please set OPENAI_API_KEY environment variable")
        return
    
    result = await test_llm()
    
    if result and hasattr(result, 'result'):
        print("✅ LLM Test Successful!")
        print(f"📊 Result: {result.result}")
    else:
        print("❌ LLM Test Failed")


if __name__ == "__main__":
    asyncio.run(main())
