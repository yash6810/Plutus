"""
Investigator Agent for intelligence extraction from scam messages.

This agent uses pattern matching and validation to extract intelligence
such as bank accounts, UPI IDs, phone numbers, and phishing links.
"""

import logging
from typing import Dict, List

from intelligence.extractors import IntelligenceExtractor

logger = logging.getLogger(__name__)


class InvestigatorAgent:
    """
    Intelligence extraction agent.
    
    This agent scans messages for intelligence using regex patterns
    and validates extracted data.
    
    Attributes:
        extractor: IntelligenceExtractor instance
    """
    
    def __init__(self):
        """Initialize the investigator agent with an extractor."""
        self.extractor = IntelligenceExtractor()
        logger.info("InvestigatorAgent initialized")
    
    def extract_all(self, text: str) -> Dict[str, List[str]]:
        """
        Extract all types of intelligence from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            Dict containing lists of extracted intelligence:
                - bankAccounts: List of bank account numbers
                - upiIds: List of UPI IDs
                - phoneNumbers: List of phone numbers
                - phishingLinks: List of URLs
                - suspiciousKeywords: List of detected keywords
        """
        if not text:
            logger.warning("Empty text provided for extraction")
            return self._empty_result()
        
        logger.debug(f"Extracting intelligence from text: {text[:100]}...")
        
        result = self.extractor.extract_all(text)
        
        # Log findings
        total = self.get_total_count(result)
        if total > 0:
            logger.info(f"Extracted {total} intelligence items: {self._summarize(result)}")
        
        return result
    
    def extract_from_conversation(self, history: List[Dict]) -> Dict[str, List[str]]:
        """
        Extract intelligence from an entire conversation history.
        
        Args:
            history: List of conversation messages
            
        Returns:
            Aggregated intelligence from all messages
        """
        aggregated = self._empty_result()
        
        for message in history:
            text = message.get("text", "")
            sender = message.get("sender", "")
            
            # Only analyze scammer messages (not agent responses)
            if sender != "agent" and text:
                extracted = self.extract_all(text)
                aggregated = self.merge_intelligence(aggregated, extracted)
        
        return aggregated
    
    def merge_intelligence(
        self, 
        existing: Dict[str, List[str]], 
        new: Dict[str, List[str]]
    ) -> Dict[str, List[str]]:
        """
        Merge new intelligence into existing collection without duplicates.
        
        Args:
            existing: Existing intelligence dict
            new: New intelligence to merge
            
        Returns:
            Merged intelligence dict
        """
        result = {}
        
        for key in ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks", "suspiciousKeywords"]:
            existing_items = set(existing.get(key, []))
            new_items = set(new.get(key, []))
            merged = existing_items.union(new_items)
            result[key] = list(merged)
        
        return result
    
    def get_total_count(self, intelligence: Dict[str, List[str]]) -> int:
        """
        Count total intelligence items.
        
        Args:
            intelligence: Intelligence dict
            
        Returns:
            Total count of all items
        """
        return sum(len(v) for v in intelligence.values())
    
    def get_types_count(self, intelligence: Dict[str, List[str]]) -> int:
        """
        Count how many types of intelligence are present.
        
        Args:
            intelligence: Intelligence dict
            
        Returns:
            Number of types with at least one item
        """
        return sum(1 for v in intelligence.values() if len(v) > 0)
    
    def get_high_value_count(self, intelligence: Dict[str, List[str]]) -> int:
        """
        Count high-value intelligence items (excluding keywords).
        
        High-value items are: bank accounts, UPI IDs, phone numbers, phishing links.
        
        Args:
            intelligence: Intelligence dict
            
        Returns:
            Count of high-value items
        """
        high_value_keys = ["bankAccounts", "upiIds", "phoneNumbers", "phishingLinks"]
        return sum(len(intelligence.get(k, [])) for k in high_value_keys)
    
    def _empty_result(self) -> Dict[str, List[str]]:
        """Return an empty result structure."""
        return {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": [],
        }
    
    def _summarize(self, intelligence: Dict[str, List[str]]) -> str:
        """Create a summary string of intelligence found."""
        parts = []
        
        if intelligence.get("bankAccounts"):
            parts.append(f"{len(intelligence['bankAccounts'])} bank accounts")
        if intelligence.get("upiIds"):
            parts.append(f"{len(intelligence['upiIds'])} UPI IDs")
        if intelligence.get("phoneNumbers"):
            parts.append(f"{len(intelligence['phoneNumbers'])} phone numbers")
        if intelligence.get("phishingLinks"):
            parts.append(f"{len(intelligence['phishingLinks'])} links")
        if intelligence.get("suspiciousKeywords"):
            parts.append(f"{len(intelligence['suspiciousKeywords'])} keywords")
        
        return ", ".join(parts) if parts else "none"
    
    def analyze_threat_level(self, intelligence: Dict[str, List[str]]) -> str:
        """
        Analyze the threat level based on extracted intelligence.
        
        Args:
            intelligence: Intelligence dict
            
        Returns:
            Threat level: "low", "medium", "high", or "critical"
        """
        high_value = self.get_high_value_count(intelligence)
        types = self.get_types_count(intelligence)
        
        if high_value >= 3 or types >= 4:
            return "critical"
        elif high_value >= 2 or types >= 3:
            return "high"
        elif high_value >= 1 or types >= 2:
            return "medium"
        else:
            return "low"
