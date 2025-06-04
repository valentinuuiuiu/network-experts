import os
from dotenv import load_dotenv
from typing import Optional
from pathlib import Path

# Load from .env in project root
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

class Config:
    """Secure configuration handler with validation"""
    
    @staticmethod
    def get(key: str, default: Optional[str] = None) -> str:
        """Get env var with existence check"""
        value = os.getenv(key)
        if value is None:
            if default is None:
                raise ValueError(f"Missing required env var: {key}")
            return default
        return value

    # Predefined configs
    @property
    def hf_token(self) -> str:
        return self.get("HUGGING_FACE_TOKEN")
    
    @property
    def openai_key(self) -> str:
        return self.get("OPENAI_API_KEY")
    
    @property
    def openai_model(self) -> str:
        return self.get("OPENAI_BASE_MODEL", "gpt-4")

    @property
    def a2a_server_url(self) -> str:
        return self.get("A2A_SERVER_URL", "http://localhost:8000")

# Singleton instance
config = Config()