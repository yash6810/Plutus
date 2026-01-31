"""
Configuration management for Honeypot Scam Detection Agent.

Loads settings from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
env_path = Path(__file__).parent / ".env"
load_dotenv(env_path)


class Config:
    """Central configuration class for the application."""
    
    # ===========================================
    # AI PROVIDER CONFIGURATION
    # ===========================================
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    AI_MODEL_NAME: str = os.getenv("AI_MODEL_NAME", "gemini-1.5-flash")
    
    # ===========================================
    # API SECURITY
    # ===========================================
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "default-dev-key-change-in-production")
    
    # ===========================================
    # GUVI INTEGRATION
    # ===========================================
    GUVI_CALLBACK_ENABLED: bool = os.getenv("GUVI_CALLBACK_ENABLED", "false").lower() == "true"
    GUVI_CALLBACK_URL: str = os.getenv(
        "GUVI_CALLBACK_URL", 
        "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    )
    
    # ===========================================
    # AGENT BEHAVIOR
    # ===========================================
    MAX_CONVERSATION_TURNS: int = int(os.getenv("MAX_CONVERSATION_TURNS", "20"))
    MIN_INTELLIGENCE_THRESHOLD: int = int(os.getenv("MIN_INTELLIGENCE_THRESHOLD", "2"))
    STALE_CONVERSATION_THRESHOLD: int = int(os.getenv("STALE_CONVERSATION_THRESHOLD", "5"))
    SCAM_CONFIDENCE_THRESHOLD: float = float(os.getenv("SCAM_CONFIDENCE_THRESHOLD", "0.7"))
    
    # ===========================================
    # PERFORMANCE
    # ===========================================
    API_TIMEOUT: int = int(os.getenv("API_TIMEOUT", "30"))
    GEMINI_TIMEOUT: int = int(os.getenv("GEMINI_TIMEOUT", "10"))
    CALLBACK_TIMEOUT: int = int(os.getenv("CALLBACK_TIMEOUT", "10"))
    
    @classmethod
    def validate(cls) -> bool:
        """
        Validate that required configuration is present.
        
        Returns:
            bool: True if configuration is valid
            
        Raises:
            ValueError: If required configuration is missing
        """
        if not cls.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is required. "
                "Please set it in your .env file or environment variables."
            )
        return True
    
    @classmethod
    def get_summary(cls) -> dict:
        """Get a summary of current configuration (without sensitive values)."""
        return {
            "ai_model": cls.AI_MODEL_NAME,
            "gemini_api_key_set": bool(cls.GEMINI_API_KEY),
            "api_secret_key_set": cls.API_SECRET_KEY != "default-dev-key-change-in-production",
            "guvi_callback_enabled": cls.GUVI_CALLBACK_ENABLED,
            "max_conversation_turns": cls.MAX_CONVERSATION_TURNS,
            "min_intelligence_threshold": cls.MIN_INTELLIGENCE_THRESHOLD,
            "stale_conversation_threshold": cls.STALE_CONVERSATION_THRESHOLD,
            "scam_confidence_threshold": cls.SCAM_CONFIDENCE_THRESHOLD,
        }


# Create singleton instance
config = Config()
