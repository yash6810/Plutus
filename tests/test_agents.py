"""
Tests for agent functionality.

Tests SessionManager and InvestigatorAgent.
DetectorAgent and ActorAgent require API keys and are tested separately.
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.session_manager import SessionManager
from agents.investigator_agent import InvestigatorAgent


class TestSessionManager:
    """Test SessionManager functionality."""
    
    @pytest.fixture
    def session_manager(self):
        """Create session manager with test configuration."""
        return SessionManager(
            max_turns=10,
            min_intelligence_types=2,
            stale_threshold=3
        )
    
    def test_create_session(self, session_manager):
        """Test session creation."""
        session = session_manager.get_or_create_session("test-123")
        
        assert session["session_id"] == "test-123"
        assert session["turn_count"] == 0
        assert session["scam_detected"] is False
        assert session["conversation_active"] is True
    
    def test_get_existing_session(self, session_manager):
        """Test retrieving existing session."""
        session_manager.get_or_create_session("test-123")
        session_manager.increment_turn("test-123")
        
        session = session_manager.get_or_create_session("test-123")
        assert session["turn_count"] == 1
    
    def test_update_session(self, session_manager):
        """Test updating session metadata."""
        session_manager.get_or_create_session("test-123")
        session_manager.update_session(
            "test-123",
            scam_detected=True,
            scam_confidence=0.85,
            persona_used="elderly"
        )
        
        session = session_manager.get_or_create_session("test-123")
        assert session["scam_detected"] is True
        assert session["scam_confidence"] == 0.85
        assert session["persona_used"] == "elderly"
    
    def test_increment_turn(self, session_manager):
        """Test turn counter."""
        session_manager.get_or_create_session("test-123")
        
        turn = session_manager.increment_turn("test-123")
        assert turn == 1
        
        turn = session_manager.increment_turn("test-123")
        assert turn == 2
    
    def test_update_intelligence(self, session_manager):
        """Test intelligence accumulation."""
        session_manager.get_or_create_session("test-123")
        
        intel1 = {
            "bankAccounts": ["1234567890"],
            "upiIds": ["scammer@paytm"],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        
        added = session_manager.update_intelligence("test-123", intel1)
        assert added is True
        
        # Add more intelligence (with some duplicates)
        intel2 = {
            "bankAccounts": ["1234567890"],  # Duplicate
            "upiIds": ["fraud@ybl"],  # New
            "phoneNumbers": ["+919876543210"],  # New
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent", "verify"]  # One duplicate
        }
        
        added = session_manager.update_intelligence("test-123", intel2)
        assert added is True
        
        session = session_manager.get_or_create_session("test-123")
        intel = session["intelligence"]
        
        # Check deduplication
        assert len(intel["bankAccounts"]) == 1
        assert len(intel["upiIds"]) == 2
        assert len(intel["phoneNumbers"]) == 1
    
    def test_should_end_max_turns(self, session_manager):
        """Test conversation ends at max turns."""
        session_manager.get_or_create_session("test-123")
        
        # Increment to max turns
        for _ in range(10):
            session_manager.increment_turn("test-123")
        
        should_end, reason = session_manager.should_end_conversation("test-123")
        assert should_end is True
        assert reason == "max_turns_reached"
    
    def test_should_end_sufficient_intelligence(self, session_manager):
        """Test conversation ends with enough intelligence."""
        session_manager.get_or_create_session("test-123")
        session_manager.increment_turn("test-123")
        
        # Add multiple intelligence types
        intel = {
            "bankAccounts": ["1234567890"],  # Type 1
            "upiIds": ["scammer@paytm"],  # Type 2
            "phoneNumbers": ["+919876543210"],  # Type 3 (high value)
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]  # Type 4
        }
        
        session_manager.update_intelligence("test-123", intel)
        
        should_end, reason = session_manager.should_end_conversation("test-123")
        assert should_end is True
        assert reason == "sufficient_intelligence"
    
    def test_should_end_stale_conversation(self, session_manager):
        """Test conversation ends when stale."""
        session_manager.get_or_create_session("test-123")
        
        # Add some intelligence at turn 1
        session_manager.increment_turn("test-123")
        intel = {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        session_manager.update_intelligence("test-123", intel)
        
        # Increment 4 more times without new intelligence
        for _ in range(4):
            session_manager.increment_turn("test-123")
        
        should_end, reason = session_manager.should_end_conversation("test-123")
        assert should_end is True
        assert reason == "stale_conversation"
    
    def test_continue_conversation(self, session_manager):
        """Test conversation continues normally."""
        session_manager.get_or_create_session("test-123")
        session_manager.increment_turn("test-123")
        
        # Add minimal intelligence
        intel = {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        session_manager.update_intelligence("test-123", intel)
        
        should_end, reason = session_manager.should_end_conversation("test-123")
        assert should_end is False
        assert reason == ""
    
    def test_end_session(self, session_manager):
        """Test manual session ending."""
        session_manager.get_or_create_session("test-123")
        session_manager.end_session("test-123", "test_reason")
        
        session = session_manager.get_or_create_session("test-123")
        assert session["conversation_active"] is False
        assert session["end_reason"] == "test_reason"
    
    def test_get_session_summary(self, session_manager):
        """Test session summary generation."""
        session_manager.get_or_create_session("test-123")
        session_manager.update_session("test-123", scam_detected=True, persona_used="elderly")
        session_manager.increment_turn("test-123")
        
        intel = {
            "bankAccounts": ["123"],
            "upiIds": ["a@paytm"],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": []
        }
        session_manager.update_intelligence("test-123", intel)
        
        summary = session_manager.get_session_summary("test-123")
        
        assert summary["sessionId"] == "test-123"
        assert summary["scamDetected"] is True
        assert summary["totalMessagesExchanged"] == 1
        assert summary["personaUsed"] == "elderly"
        assert summary["highValueIntelCount"] == 2


class TestInvestigatorAgent:
    """Test InvestigatorAgent functionality."""
    
    @pytest.fixture
    def investigator(self):
        """Create investigator agent."""
        return InvestigatorAgent()
    
    def test_extract_all(self, investigator):
        """Test extracting all intelligence."""
        text = "Pay to scammer@paytm, call +919876543210. Urgent!"
        result = investigator.extract_all(text)
        
        assert "scammer@paytm" in result["upiIds"]
        assert "+919876543210" in result["phoneNumbers"]
        assert "urgent" in result["suspiciousKeywords"]
    
    def test_extract_from_conversation(self, investigator):
        """Test extracting from conversation history."""
        history = [
            {"sender": "scammer", "text": "Pay to fraud@ybl"},
            {"sender": "agent", "text": "What is your UPI?"},  # Agent message ignored
            {"sender": "scammer", "text": "Also try scammer@paytm or call 9876543210"},
        ]
        
        result = investigator.extract_from_conversation(history)
        
        assert "fraud@ybl" in result["upiIds"]
        assert "scammer@paytm" in result["upiIds"]
        assert "+919876543210" in result["phoneNumbers"]
    
    def test_merge_intelligence(self, investigator):
        """Test merging intelligence without duplicates."""
        existing = {
            "bankAccounts": ["123"],
            "upiIds": ["a@paytm"],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        
        new = {
            "bankAccounts": ["123", "456"],  # One duplicate
            "upiIds": ["b@ybl"],
            "phoneNumbers": ["+919876543210"],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent", "verify"]  # One duplicate
        }
        
        result = investigator.merge_intelligence(existing, new)
        
        assert len(result["bankAccounts"]) == 2
        assert len(result["upiIds"]) == 2
        assert len(result["phoneNumbers"]) == 1
        assert len(result["suspiciousKeywords"]) == 2
    
    def test_get_total_count(self, investigator):
        """Test total item counting."""
        intel = {
            "bankAccounts": ["a"],
            "upiIds": ["b", "c"],
            "phoneNumbers": ["d"],
            "phishingLinks": [],
            "suspiciousKeywords": ["e", "f", "g"]
        }
        
        assert investigator.get_total_count(intel) == 7
    
    def test_get_types_count(self, investigator):
        """Test intelligence type counting."""
        intel = {
            "bankAccounts": ["a"],
            "upiIds": [],
            "phoneNumbers": ["b"],
            "phishingLinks": [],
            "suspiciousKeywords": ["c"]
        }
        
        assert investigator.get_types_count(intel) == 3
    
    def test_get_high_value_count(self, investigator):
        """Test high-value item counting."""
        intel = {
            "bankAccounts": ["a"],
            "upiIds": ["b", "c"],
            "phoneNumbers": ["d"],
            "phishingLinks": ["e"],
            "suspiciousKeywords": ["f", "g", "h"]  # Not counted
        }
        
        assert investigator.get_high_value_count(intel) == 5
    
    def test_analyze_threat_level(self, investigator):
        """Test threat level analysis."""
        # Critical: 3+ high value items
        intel_critical = {
            "bankAccounts": ["a"],
            "upiIds": ["b"],
            "phoneNumbers": ["c"],
            "phishingLinks": [],
            "suspiciousKeywords": []
        }
        assert investigator.analyze_threat_level(intel_critical) == "critical"
        
        # High: 2 high value items
        intel_high = {
            "bankAccounts": [],
            "upiIds": ["a"],
            "phoneNumbers": ["b"],
            "phishingLinks": [],
            "suspiciousKeywords": []
        }
        assert investigator.analyze_threat_level(intel_high) == "high"
        
        # Medium: 1 high value item
        intel_medium = {
            "bankAccounts": [],
            "upiIds": ["a"],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        assert investigator.analyze_threat_level(intel_medium) == "medium"
        
        # Low: no high value items
        intel_low = {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        assert investigator.analyze_threat_level(intel_low) == "low"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
