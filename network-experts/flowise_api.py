from fastapi import FastAPI, HTTPException
try:
    from intelligent_agents import AgentSystem
    agents = AgentSystem()
except ImportError as e:
    raise RuntimeError(f"Import error: {str(e)}")
except Exception as e:
    raise RuntimeError(f"Initialization error: {str(e)}")

app = FastAPI()

@app.post("/agent/{agent_name}/trigger")
async def trigger_agent(agent_name: str, payload: dict):
    try:
        return agents.process_request(agent_name, payload)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
