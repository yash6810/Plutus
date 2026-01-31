"""
Intelligence extraction using regex pattern matching.

Extracts:
- Bank account numbers
- UPI IDs
- Phone numbers
- Phishing links/URLs
- Suspicious keywords
"""

import re
import logging
from typing import Dict, List

from .validators import (
    is_valid_bank_account,
    is_valid_upi_id,
    is_valid_phone_number,
    is_valid_url,
    extract_clean_phone,
)

logger = logging.getLogger(__name__)


class IntelligenceExtractor:
    """
    Extract intelligence from scam messages using regex patterns.
    
    This class provides methods to extract various types of scam-related
    intelligence including bank accounts, UPI IDs, phone numbers, URLs,
    and suspicious keywords.
    
    Attributes:
        patterns: Dict of compiled regex patterns
        scam_keywords: List of suspicious keywords to detect
    """
    
    def __init__(self):
        """Initialize the extractor with regex patterns and keywords."""
        # Compile regex patterns for efficiency
        self.patterns = {
            # Bank account: 9-18 digits, may have spaces or hyphens
            'bank_account': re.compile(
                r'\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{1,10})\b'
            ),
            
            # UPI ID: username@provider
            'upi_id': re.compile(
                r'\b([\w.\-]+@(?:paytm|ybl|axisbank|oksbi|okicici|okhdfcbank|'
                r'icici|sbi|hdfc|airtel|freecharge|jiomoney|mobikwik|apl|'
                r'amazonpay|ibl|axl|upi|gpay|pingpay|kotak|pnb|federal|'
                r'indus|rbl|yesbankltd|dbs|idfcbank))\b',
                re.IGNORECASE
            ),
            
            # Indian phone number: +91 or starts with 6-9
            'phone': re.compile(
                r'(?:\+91[\s\-]?)?(?:0)?([6-9]\d{9})\b'
            ),
            
            # URLs including shortened links
            'url': re.compile(
                r'((?:https?://|www\.)[^\s<>"\']+|'
                r'(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|'
                r'buff\.ly|j\.mp|tr\.im)/[^\s<>"\']+)',
                re.IGNORECASE
            ),
        }
        
        # Suspicious keywords commonly used in scams
        self.scam_keywords = [
            "urgent", "immediately", "blocked", "suspended", "verify",
            "otp", "password", "cvv", "expire", "limited time", "act now",
            "account closed", "confirm identity", "click here", "update kyc",
            "kyc update", "link expire", "bank notice", "rbi", "security alert",
            "unusual activity", "unauthorized", "refund", "lottery", "prize",
            "winner", "claim now", "last chance", "final notice", "warning",
            "action required", "pan card", "aadhaar", "debit card", "credit card",
            "pin", "atm", "transfer", "send money", "pay now", "payment failed",
            "transaction failed", "account frozen", "legal action", "police",
            "arrest", "case filed", "court", "fine", "penalty"
        ]
    
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
            return self._empty_result()
        
        logger.debug(f"Extracting intelligence from: {text[:100]}...")
        
        result = {
            "bankAccounts": self.extract_bank_accounts(text),
            "upiIds": self.extract_upi_ids(text),
            "phoneNumbers": self.extract_phone_numbers(text),
            "phishingLinks": self.extract_urls(text),
            "suspiciousKeywords": self.extract_keywords(text),
        }
        
        # Log what we found
        total_items = sum(len(v) for v in result.values())
        if total_items > 0:
            logger.info(f"Extracted {total_items} intelligence items")
        
        return result
    
    def extract_bank_accounts(self, text: str) -> List[str]:
        """
        Extract valid bank account numbers from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            List of valid bank account numbers (duplicates removed)
        """
        matches = self.patterns['bank_account'].findall(text)
        validated = []
        
        for match in matches:
            # Clean the match (remove spaces and hyphens)
            clean = match.replace(' ', '').replace('-', '')
            if is_valid_bank_account(clean):
                validated.append(clean)
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(validated))
    
    def extract_upi_ids(self, text: str) -> List[str]:
        """
        Extract valid UPI IDs from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            List of valid UPI IDs (duplicates removed, lowercase)
        """
        matches = self.patterns['upi_id'].findall(text)
        validated = []
        
        for match in matches:
            upi_lower = match.lower()
            if is_valid_upi_id(upi_lower):
                validated.append(upi_lower)
        
        return list(dict.fromkeys(validated))
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """
        Extract valid Indian phone numbers from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            List of phone numbers in +91XXXXXXXXXX format (duplicates removed)
        """
        # First try to find numbers with +91 prefix
        full_pattern = re.compile(r'(\+91[\s\-]?[6-9]\d{9}|\b0?[6-9]\d{9})\b')
        matches = full_pattern.findall(text)
        validated = []
        
        for match in matches:
            clean = extract_clean_phone(match)
            if clean:
                validated.append(clean)
        
        return list(dict.fromkeys(validated))
    
    def extract_urls(self, text: str) -> List[str]:
        """
        Extract valid URLs/phishing links from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            List of valid URLs (duplicates removed)
        """
        matches = self.patterns['url'].findall(text)
        validated = []
        
        for match in matches:
            # Clean trailing punctuation
            clean = match.rstrip('.,;:!?)')
            if is_valid_url(clean):
                validated.append(clean)
        
        return list(dict.fromkeys(validated))
    
    def extract_keywords(self, text: str) -> List[str]:
        """
        Extract suspicious keywords from text.
        
        Args:
            text: Message text to analyze
            
        Returns:
            List of suspicious keywords found (duplicates removed)
        """
        text_lower = text.lower()
        found = []
        
        for keyword in self.scam_keywords:
            if keyword.lower() in text_lower:
                found.append(keyword)
        
        return list(dict.fromkeys(found))
    
    def _empty_result(self) -> Dict[str, List[str]]:
        """Return an empty result structure."""
        return {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": [],
        }
    
    def get_intelligence_count(self, intelligence: Dict[str, List[str]]) -> int:
        """
        Count total intelligence items extracted.
        
        Args:
            intelligence: Intelligence dict from extract_all()
            
        Returns:
            Total count of all intelligence items
        """
        return sum(len(v) for v in intelligence.values())
    
    def get_intelligence_types_count(self, intelligence: Dict[str, List[str]]) -> int:
        """
        Count how many types of intelligence were extracted.
        
        Args:
            intelligence: Intelligence dict from extract_all()
            
        Returns:
            Number of intelligence types with at least one item
        """
        return sum(1 for v in intelligence.values() if len(v) > 0)


# Singleton instance for convenience
extractor = IntelligenceExtractor()
