from fastapi import FastAPI
from intelligent_agents import AgentSystem

app = FastAPI()
agents = AgentSystem()

@app.post("/agent/{agent_name}/trigger")
async def trigger_agent(agent_name: str, payload: dict):
    return agents.process_request(agent_name, payload)
