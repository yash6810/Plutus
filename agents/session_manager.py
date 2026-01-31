"""
Session Manager for tracking conversation state across multiple turns.

Handles session creation, intelligence accumulation, and conversation
end-condition logic.
"""

import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages conversation sessions and state.
    
    Tracks conversation state, accumulates intelligence across turns,
    and determines when to end conversations.
    
    Attributes:
        sessions: Dict mapping session_id to session state
        lock: Thread lock for concurrent access
    """
    
    def __init__(
        self,
        max_turns: int = 20,
        min_intelligence_types: int = 2,
        stale_threshold: int = 5
    ):
        """
        Initialize the session manager.
        
        Args:
            max_turns: Maximum conversation turns before forcing end
            min_intelligence_types: Minimum types of intelligence to collect
            stale_threshold: Turns without new intel before ending
        """
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        
        # Configuration
        self.max_turns = max_turns
        self.min_intelligence_types = min_intelligence_types
        self.stale_threshold = stale_threshold
        
        logger.info(
            f"SessionManager initialized: max_turns={max_turns}, "
            f"min_intel_types={min_intelligence_types}, "
            f"stale_threshold={stale_threshold}"
        )
    
    def get_or_create_session(self, session_id: str) -> Dict[str, Any]:
        """
        Get an existing session or create a new one.
        
        Args:
            session_id: Unique session identifier
            
        Returns:
            Session state dict
        """
        with self.lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = self._create_new_session(session_id)
                logger.info(f"Created new session: {session_id}")
            
            return self.sessions[session_id].copy()
    
    def _create_new_session(self, session_id: str) -> Dict[str, Any]:
        """Create a new session state structure."""
        return {
            "session_id": session_id,
            "turn_count": 0,
            "scam_detected": False,
            "scam_confidence": 0.0,
            "persona_used": None,
            "intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phoneNumbers": [],
                "phishingLinks": [],
                "suspiciousKeywords": [],
            },
            "conversation_active": True,
            "last_intelligence_turn": 0,
            "end_reason": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
    
    def update_session(
        self,
        session_id: str,
        scam_detected: Optional[bool] = None,
        scam_confidence: Optional[float] = None,
        persona_used: Optional[str] = None
    ) -> None:
        """
        Update session metadata.
        
        Args:
            session_id: Session identifier
            scam_detected: Whether scam was detected
            scam_confidence: Detection confidence
            persona_used: Persona being used
        """
        with self.lock:
            if session_id not in self.sessions:
                return
            
            session = self.sessions[session_id]
            
            if scam_detected is not None:
                session["scam_detected"] = scam_detected
            if scam_confidence is not None:
                session["scam_confidence"] = scam_confidence
            if persona_used is not None:
                session["persona_used"] = persona_used
            
            session["updated_at"] = datetime.now().isoformat()
    
    def update_intelligence(
        self,
        session_id: str,
        new_intel: Dict[str, List[str]]
    ) -> bool:
        """
        Add new intelligence to a session.
        
        Args:
            session_id: Session identifier
            new_intel: New intelligence to add
            
        Returns:
            True if new unique intelligence was added
        """
        with self.lock:
            if session_id not in self.sessions:
                return False
            
            session = self.sessions[session_id]
            existing = session["intelligence"]
            
            # Track if we added anything new
            added_new = False
            
            for key in existing.keys():
                new_items = set(new_intel.get(key, []))
                existing_items = set(existing[key])
                
                unique_new = new_items - existing_items
                if unique_new:
                    existing[key] = list(existing_items.union(new_items))
                    added_new = True
                    logger.debug(f"Added new {key}: {unique_new}")
            
            if added_new:
                session["last_intelligence_turn"] = session["turn_count"]
                logger.info(f"Session {session_id}: New intelligence added at turn {session['turn_count']}")
            
            session["updated_at"] = datetime.now().isoformat()
            return added_new
    
    def increment_turn(self, session_id: str) -> int:
        """
        Increment the turn counter for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            New turn count
        """
        with self.lock:
            if session_id not in self.sessions:
                return 0
            
            self.sessions[session_id]["turn_count"] += 1
            turn = self.sessions[session_id]["turn_count"]
            self.sessions[session_id]["updated_at"] = datetime.now().isoformat()
            
            logger.debug(f"Session {session_id}: Turn count now {turn}")
            return turn
    
    def should_end_conversation(self, session_id: str) -> tuple[bool, str]:
        """
        Determine if the conversation should end.
        
        End conditions:
        1. Found at least min_intelligence_types different types
        2. Turn count >= max_turns
        3. No new intelligence in last stale_threshold turns
        
        Args:
            session_id: Session identifier
            
        Returns:
            Tuple of (should_end: bool, reason: str)
        """
        with self.lock:
            if session_id not in self.sessions:
                return True, "session_not_found"
            
            session = self.sessions[session_id]
            
            # Check if already ended
            if not session["conversation_active"]:
                return True, session.get("end_reason", "already_ended")
            
            turn = session["turn_count"]
            intel = session["intelligence"]
            last_intel_turn = session["last_intelligence_turn"]
            
            # Count intelligence types with items
            intel_types = sum(1 for v in intel.values() if len(v) > 0)
            
            # Condition 1: Enough intelligence types
            if intel_types >= self.min_intelligence_types:
                # Require at least one high-value item
                high_value = sum(len(intel.get(k, [])) for k in 
                               ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks"])
                if high_value >= 1:
                    return True, "sufficient_intelligence"
            
            # Condition 2: Max turns reached
            if turn >= self.max_turns:
                return True, "max_turns_reached"
            
            # Condition 3: Stale conversation
            turns_since_intel = turn - last_intel_turn
            if turn > 3 and turns_since_intel >= self.stale_threshold:
                return True, "stale_conversation"
            
            return False, ""
    
    def end_session(self, session_id: str, reason: str) -> None:
        """
        Mark a session as ended.
        
        Args:
            session_id: Session identifier
            reason: Reason for ending
        """
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]["conversation_active"] = False
                self.sessions[session_id]["end_reason"] = reason
                self.sessions[session_id]["updated_at"] = datetime.now().isoformat()
                logger.info(f"Session {session_id} ended: {reason}")
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        Get a summary of the session for callbacks/reporting.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session summary dict
        """
        with self.lock:
            if session_id not in self.sessions:
                return {"error": "session_not_found"}
            
            session = self.sessions[session_id]
            intel = session["intelligence"]
            
            return {
                "sessionId": session_id,
                "scamDetected": session["scam_detected"],
                "totalMessagesExchanged": session["turn_count"],
                "extractedIntelligence": intel.copy(),
                "personaUsed": session["persona_used"],
                "endReason": session.get("end_reason"),
                "highValueIntelCount": sum(
                    len(intel.get(k, [])) for k in 
                    ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks"]
                ),
                "createdAt": session["created_at"],
                "updatedAt": session["updated_at"],
            }
    
    def get_all_sessions(self) -> Dict[str, Dict]:
        """Get all sessions (for debugging/admin)."""
        with self.lock:
            return {k: v.copy() for k, v in self.sessions.items()}
    
    def cleanup_old_sessions(self, max_age_hours: int = 24) -> int:
        """
        Remove sessions older than max_age_hours.
        
        Args:
            max_age_hours: Maximum age in hours
            
        Returns:
            Number of sessions removed
        """
        from datetime import timedelta
        
        with self.lock:
            cutoff = datetime.now() - timedelta(hours=max_age_hours)
            to_remove = []
            
            for session_id, session in self.sessions.items():
                created = datetime.fromisoformat(session["created_at"])
                if created < cutoff:
                    to_remove.append(session_id)
            
            for session_id in to_remove:
                del self.sessions[session_id]
            
            if to_remove:
                logger.info(f"Cleaned up {len(to_remove)} old sessions")
            
            return len(to_remove)
