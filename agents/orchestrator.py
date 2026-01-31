"""
Orchestrator for coordinating multiple agents in the Honeypot system.

This is the central coordinator that manages the flow between:
- DetectorAgent: Scam classification
- ActorAgent: Response generation
- InvestigatorAgent: Intelligence extraction
- SessionManager: State tracking
"""

import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from .detector_agent import DetectorAgent
from .actor_agent import ActorAgent
from .investigator_agent import InvestigatorAgent
from .session_manager import SessionManager

logger = logging.getLogger(__name__)


class Orchestrator:
    """
    Multi-agent orchestrator for the Honeypot system.
    
    Coordinates the flow of information between specialized agents
    and manages the overall conversation lifecycle.
    
    Attributes:
        detector: DetectorAgent instance
        actor: ActorAgent instance
        investigator: InvestigatorAgent instance
        session_manager: SessionManager instance
        scam_confidence_threshold: Minimum confidence to treat as scam
    """
    
    def __init__(
        self,
        detector: DetectorAgent,
        actor: ActorAgent,
        investigator: InvestigatorAgent,
        session_manager: SessionManager,
        scam_confidence_threshold: float = 0.7
    ):
        """
        Initialize the orchestrator with all agents.
        
        Args:
            detector: DetectorAgent instance
            actor: ActorAgent instance
            investigator: InvestigatorAgent instance
            session_manager: SessionManager instance
            scam_confidence_threshold: Minimum confidence to engage as victim
        """
        self.detector = detector
        self.actor = actor
        self.investigator = investigator
        self.session_manager = session_manager
        self.scam_confidence_threshold = scam_confidence_threshold
        
        logger.info("Orchestrator initialized with all agents")
    
    def process_message(
        self,
        session_id: str,
        message: Dict[str, Any],
        history: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process an incoming message through the agent pipeline.
        
        This is the main entry point for analyzing scam messages.
        
        Args:
            session_id: Unique session identifier
            message: Message dict with sender, text, timestamp
            history: Previous conversation messages
            metadata: Channel, language, locale info
            
        Returns:
            Response dict matching GUVI API specification
        """
        start_time = time.time()
        
        # Extract message text
        message_text = message.get("text", "")
        sender = message.get("sender", "unknown")
        
        logger.info(f"Processing message for session {session_id}: {message_text[:50]}...")
        
        # Get or create session
        session = self.session_manager.get_or_create_session(session_id)
        is_first_turn = session["turn_count"] == 0
        
        # Increment turn count
        turn_count = self.session_manager.increment_turn(session_id)
        
        # Step 1: Detect scam (on first message or if not yet confirmed)
        detection_result = None
        if is_first_turn or not session["scam_detected"]:
            detection_result = self.detector.detect_scam(message_text, history)
            
            self.session_manager.update_session(
                session_id,
                scam_detected=detection_result["is_scam"],
                scam_confidence=detection_result["confidence"]
            )
        
        # Refresh session state
        session = self.session_manager.get_or_create_session(session_id)
        
        # Step 2: Extract intelligence from scammer's message
        intel = self.investigator.extract_all(message_text)
        new_intel_added = self.session_manager.update_intelligence(session_id, intel)
        
        # Step 3: Generate response if scam detected
        agent_response = ""
        if session["scam_detected"] and session["scam_confidence"] >= self.scam_confidence_threshold:
            # Select or maintain persona
            persona = session["persona_used"]
            if not persona:
                persona = self.actor.select_persona(
                    scam_indicators=detection_result.get("indicators", []) if detection_result else [],
                    channel=metadata.get("channel", "sms"),
                    metadata=metadata
                )
                self.session_manager.update_session(session_id, persona_used=persona)
            
            # Generate response
            agent_response = self.actor.generate_response(
                message=message_text,
                persona=persona,
                history=history
            )
        
        # Step 4: Check if conversation should end
        should_end, end_reason = self.session_manager.should_end_conversation(session_id)
        
        if should_end:
            self.session_manager.end_session(session_id, end_reason)
        
        # Get final session state
        session = self.session_manager.get_or_create_session(session_id)
        
        # Calculate response time
        response_time_ms = int((time.time() - start_time) * 1000)
        
        # Build response
        response = self._build_response(
            session=session,
            intel=session["intelligence"],
            agent_response=agent_response,
            turn_count=turn_count,
            response_time_ms=response_time_ms,
            continue_conversation=not should_end,
            detection_result=detection_result,
            end_reason=end_reason if should_end else None
        )
        
        logger.info(
            f"Session {session_id}: Turn {turn_count}, "
            f"scam={session['scam_detected']}, "
            f"continue={not should_end}, "
            f"response_time={response_time_ms}ms"
        )
        
        return response
    
    def _build_response(
        self,
        session: Dict[str, Any],
        intel: Dict[str, List[str]],
        agent_response: str,
        turn_count: int,
        response_time_ms: int,
        continue_conversation: bool,
        detection_result: Optional[Dict] = None,
        end_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build the API response in GUVI-compliant format.
        
        Args:
            session: Current session state
            intel: Accumulated intelligence
            agent_response: Generated response text
            turn_count: Current turn number
            response_time_ms: Processing time in milliseconds
            continue_conversation: Whether to continue
            detection_result: Detection result if available
            end_reason: Reason for ending if applicable
            
        Returns:
            GUVI-compliant response dict
        """
        # Calculate total intelligence items
        total_intel = sum(len(v) for v in intel.values())
        
        # Build agent notes
        notes_parts = []
        if detection_result:
            notes_parts.append(f"Detection: {detection_result.get('reason', 'N/A')}")
        if session["persona_used"]:
            notes_parts.append(f"Persona: {session['persona_used']}")
        if end_reason:
            notes_parts.append(f"Ended: {end_reason}")
        
        agent_notes = ". ".join(notes_parts) if notes_parts else ""
        
        return {
            "status": "success",
            "scamDetected": session["scam_detected"],
            "agentResponse": agent_response,
            "extractedIntelligence": {
                "bankAccounts": intel.get("bankAccounts", []),
                "upiIds": intel.get("upiIds", []),
                "phishingLinks": intel.get("phishingLinks", []),
                "phoneNumbers": intel.get("phoneNumbers", []),
                "suspiciousKeywords": intel.get("suspiciousKeywords", []),
            },
            "engagementMetrics": {
                "conversationTurn": turn_count,
                "responseTimeMs": response_time_ms,
                "totalIntelligenceItems": total_intel,
            },
            "continueConversation": continue_conversation,
            "agentNotes": agent_notes,
        }
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        Get a summary of a session for callbacks/reporting.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session summary dict
        """
        return self.session_manager.get_session_summary(session_id)
    
    def end_session_manually(self, session_id: str, reason: str = "manual") -> bool:
        """
        Manually end a session.
        
        Args:
            session_id: Session identifier
            reason: Reason for ending
            
        Returns:
            True if session was ended
        """
        session = self.session_manager.get_or_create_session(session_id)
        if session and session.get("conversation_active"):
            self.session_manager.end_session(session_id, reason)
            return True
        return False


def create_orchestrator(
    api_key: str,
    model_name: str = "gemini-1.5-flash",
    max_turns: int = 20,
    min_intelligence_types: int = 2,
    stale_threshold: int = 5,
    scam_confidence_threshold: float = 0.7
) -> Orchestrator:
    """
    Factory function to create a fully configured Orchestrator.
    
    Args:
        api_key: Gemini API key
        model_name: Gemini model name
        max_turns: Maximum conversation turns
        min_intelligence_types: Minimum intelligence types for ending
        stale_threshold: Turns without intel before ending
        scam_confidence_threshold: Minimum confidence to engage
        
    Returns:
        Configured Orchestrator instance
    """
    detector = DetectorAgent(api_key=api_key, model_name=model_name)
    actor = ActorAgent(api_key=api_key, model_name=model_name)
    investigator = InvestigatorAgent()
    session_manager = SessionManager(
        max_turns=max_turns,
        min_intelligence_types=min_intelligence_types,
        stale_threshold=stale_threshold
    )
    
    return Orchestrator(
        detector=detector,
        actor=actor,
        investigator=investigator,
        session_manager=session_manager,
        scam_confidence_threshold=scam_confidence_threshold
    )
