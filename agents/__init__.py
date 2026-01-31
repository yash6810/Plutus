"""
Agents package for Honeypot Scam Detection Agent.

Contains:
- DetectorAgent: Scam classification using Gemini AI
- ActorAgent: Persona-based response generation
- InvestigatorAgent: Intelligence extraction
- SessionManager: Conversation state tracking
- Orchestrator: Multi-agent coordinator
"""

from .detector_agent import DetectorAgent
from .actor_agent import ActorAgent
from .investigator_agent import InvestigatorAgent
from .session_manager import SessionManager
from .orchestrator import Orchestrator

__all__ = [
    "DetectorAgent",
    "ActorAgent", 
    "InvestigatorAgent",
    "SessionManager",
    "Orchestrator",
]
