from typing import Dict, List, Optional
from dataclasses import dataclass
import hashlib
import json
from fastapi import FastAPI, Request
import httpx

app = FastAPI()

@dataclass
class A2AMessage:
    """Standardized agent communication format"""
    sender: str
    recipients: List[str]
    content: Dict
    message_id: Optional[str] = None
    protocol_version: str = "1.0"
    
    def __post_init__(self):
        self.message_id = self._generate_message_id()
        
    def _generate_message_id(self) -> str:
        """Create unique hash for message tracking"""
        content_str = json.dumps(self.content).encode()
        return hashlib.sha256(content_str).hexdigest()[:16]

class A2AServer:
    """Lightweight communication hub"""
    def __init__(self):
        self.message_queue = []
        self.agent_registry = {}
        
    def register_agent(self, agent_id: str, callback_url: str):
        self.agent_registry[agent_id] = callback_url
        
    async def receive(self, message: A2AMessage) -> bool:
        """Process incoming message"""
        self.message_queue.append(message)
        # Forward to recipients
        async with httpx.AsyncClient() as client:
            for recipient in message.recipients:
                if recipient in self.agent_registry:
                    await client.post(
                        self.agent_registry[recipient],
                        json=message.__dict__
                    )
        return True

class A2AClient:
    """Agent-side communication handler"""
    def __init__(self, server_url: str):
        self.server_url = server_url
        
    async def send(self, message: A2AMessage) -> bool:
        """Deliver message to server"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.server_url}/a2a/receive",
                json=message.__dict__
            )
        return response.status_code == 200

# FastAPI endpoints
@app.post("/a2a/receive")
async def receive_message(request: Request):
    data = await request.json()
    message = A2AMessage(**data)
    server = A2AServer()
    await server.receive(message)
    return {"status": "received"}

@app.get("/a2a/register/{agent_id}")
async def register_agent(agent_id: str, callback_url: str):
    server = A2AServer()
    server.register_agent(agent_id, callback_url)
    return {"status": "registered"}