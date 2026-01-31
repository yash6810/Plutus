"""
Tests for intelligence extraction functionality.

Tests the IntelligenceExtractor class for:
- Bank account extraction and validation
- UPI ID extraction and validation
- Phone number extraction
- URL/phishing link detection
- Keyword detection
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.extractors import IntelligenceExtractor
from intelligence.validators import (
    is_valid_bank_account,
    is_valid_upi_id,
    is_valid_phone_number,
    is_valid_url,
    extract_clean_phone,
)


class TestValidators:
    """Test validation functions."""
    
    def test_valid_bank_account(self):
        """Test valid bank account numbers."""
        # Non-sequential, realistic bank account numbers
        assert is_valid_bank_account("112233445566") is True
        assert is_valid_bank_account("503041234567") is True  # Realistic SBI format
        assert is_valid_bank_account("918020043210123") is True  # Realistic HDFC format
    
    def test_invalid_bank_account_too_short(self):
        """Test bank accounts that are too short."""
        assert is_valid_bank_account("12345678") is False
        assert is_valid_bank_account("1234") is False
    
    def test_invalid_bank_account_all_same(self):
        """Test bank accounts with all same digits."""
        assert is_valid_bank_account("111111111") is False
        assert is_valid_bank_account("999999999999") is False
    
    def test_invalid_bank_account_sequential(self):
        """Test sequential bank account patterns."""
        assert is_valid_bank_account("123456789") is False
    
    def test_valid_upi_id(self):
        """Test valid UPI IDs."""
        assert is_valid_upi_id("user@paytm") is True
        assert is_valid_upi_id("example123@ybl") is True
        assert is_valid_upi_id("test.user@axisbank") is True
        assert is_valid_upi_id("user-name@sbi") is True
    
    def test_invalid_upi_id_unknown_provider(self):
        """Test UPI IDs with unknown providers."""
        assert is_valid_upi_id("user@unknownbank") is False
        assert is_valid_upi_id("user@random") is False
    
    def test_invalid_upi_id_format(self):
        """Test UPI IDs with invalid format."""
        assert is_valid_upi_id("noatsymbol") is False
        assert is_valid_upi_id("@paytm") is False
        assert is_valid_upi_id("ab@paytm") is False  # Too short username
    
    def test_valid_phone_number(self):
        """Test valid Indian phone numbers."""
        assert is_valid_phone_number("9876543210") is True
        assert is_valid_phone_number("+919876543210") is True
        assert is_valid_phone_number("91 9876543210") is True
        assert is_valid_phone_number("7654321098") is True
    
    def test_invalid_phone_number(self):
        """Test invalid phone numbers."""
        assert is_valid_phone_number("1234567890") is False  # Starts with 1
        assert is_valid_phone_number("12345") is False  # Too short
        assert is_valid_phone_number("9999999999") is False  # All same
    
    def test_valid_url(self):
        """Test valid URLs."""
        assert is_valid_url("http://example.com") is True
        assert is_valid_url("https://bank.com/login") is True
        assert is_valid_url("www.fake-bank.com") is True
    
    def test_extract_clean_phone(self):
        """Test phone number cleaning and formatting."""
        assert extract_clean_phone("+91 9876543210") == "+919876543210"
        assert extract_clean_phone("91-9876-543210") == "+919876543210"
        assert extract_clean_phone("09876543210") == "+919876543210"


class TestIntelligenceExtractor:
    """Test IntelligenceExtractor class."""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor instance."""
        return IntelligenceExtractor()
    
    def test_extract_bank_accounts(self, extractor):
        """Test bank account extraction."""
        text = "Please transfer to account 503041234567890 immediately."
        result = extractor.extract_bank_accounts(text)
        assert "503041234567890" in result
    
    def test_extract_bank_accounts_with_spaces(self, extractor):
        """Test bank account extraction with spaces/hyphens."""
        text = "Account number is 5030-4123-4567"
        result = extractor.extract_bank_accounts(text)
        assert "503041234567" in result
    
    def test_extract_upi_ids(self, extractor):
        """Test UPI ID extraction."""
        text = "Pay to scammer@paytm or fraud@ybl for quick processing."
        result = extractor.extract_upi_ids(text)
        assert "scammer@paytm" in result
        assert "fraud@ybl" in result
    
    def test_extract_phone_numbers(self, extractor):
        """Test phone number extraction."""
        text = "Call us at +91 9876543210 or 8765432109 for help."
        result = extractor.extract_phone_numbers(text)
        assert "+919876543210" in result
        assert "+918765432109" in result
    
    def test_extract_urls(self, extractor):
        """Test URL extraction."""
        text = "Click http://fake-bank.com to verify. Also try bit.ly/scam123"
        result = extractor.extract_urls(text)
        assert "http://fake-bank.com" in result
    
    def test_extract_keywords(self, extractor):
        """Test keyword extraction."""
        text = "URGENT: Account suspended! Verify immediately or face legal action."
        result = extractor.extract_keywords(text)
        assert "urgent" in result
        assert "suspended" in result
        assert "verify" in result
        assert "immediately" in result
        assert "legal action" in result
    
    def test_extract_all(self, extractor):
        """Test extracting all intelligence from a scam message."""
        text = """
        URGENT: Your account 9876543210123456 is blocked!
        Pay Rs.1000 to verify@paytm to unblock.
        Click http://fake-bank.com or call +91 9988776655.
        """
        result = extractor.extract_all(text)
        
        assert len(result["bankAccounts"]) > 0
        assert "verify@paytm" in result["upiIds"]
        assert len(result["phishingLinks"]) > 0
        assert "+919988776655" in result["phoneNumbers"]
        assert "urgent" in result["suspiciousKeywords"]
        assert "blocked" in result["suspiciousKeywords"]
    
    def test_extract_empty_text(self, extractor):
        """Test extraction from empty text."""
        result = extractor.extract_all("")
        assert result["bankAccounts"] == []
        assert result["upiIds"] == []
        assert result["phoneNumbers"] == []
        assert result["phishingLinks"] == []
        assert result["suspiciousKeywords"] == []
    
    def test_no_duplicates(self, extractor):
        """Test that duplicates are removed."""
        text = "Call 9876543210 or +919876543210 or 9876543210"
        result = extractor.extract_phone_numbers(text)
        assert len(result) == 1
    
    def test_get_intelligence_count(self, extractor):
        """Test intelligence counting."""
        intel = {
            "bankAccounts": ["123"],
            "upiIds": ["a@paytm", "b@ybl"],
            "phoneNumbers": [],
            "phishingLinks": ["http://x.com"],
            "suspiciousKeywords": ["urgent"]
        }
        assert extractor.get_intelligence_count(intel) == 5
    
    def test_get_intelligence_types_count(self, extractor):
        """Test counting intelligence types."""
        intel = {
            "bankAccounts": ["123"],
            "upiIds": ["a@paytm"],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": ["urgent"]
        }
        assert extractor.get_intelligence_types_count(intel) == 3


class TestRealScamMessages:
    """Test with realistic scam messages."""
    
    @pytest.fixture
    def extractor(self):
        return IntelligenceExtractor()
    
    def test_banking_scam(self, extractor):
        """Test banking scam message."""
        text = """
        Dear Customer, Your SBI account has been suspended.
        Update KYC immediately at http://sbi-kyc-update.com
        Contact: 9876543210
        """
        result = extractor.extract_all(text)
        
        assert "suspended" in result["suspiciousKeywords"]
        assert "update kyc" in result["suspiciousKeywords"] or "immediately" in result["suspiciousKeywords"]
        assert len(result["phishingLinks"]) > 0
        assert len(result["phoneNumbers"]) > 0
    
    def test_lottery_scam(self, extractor):
        """Test lottery scam message."""
        text = """
        Congratulations! You won Rs.25 Lakhs in lucky draw!
        Send processing fee to winner@paytm.
        Claim now before it expires!
        """
        result = extractor.extract_all(text)
        
        assert "winner@paytm" in result["upiIds"]
        assert "winner" in result["suspiciousKeywords"] or "prize" in result["suspiciousKeywords"]
    
    def test_otp_scam(self, extractor):
        """Test OTP phishing scam."""
        text = """
        We detected unauthorized transaction of Rs.49,999.
        Share OTP to block this transaction.
        Call 8899776655 immediately.
        """
        result = extractor.extract_all(text)
        
        assert "otp" in result["suspiciousKeywords"]
        assert "unauthorized" in result["suspiciousKeywords"]
        assert "immediately" in result["suspiciousKeywords"]
        assert "+918899776655" in result["phoneNumbers"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
