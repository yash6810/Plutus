"""
Validation functions for extracted intelligence data.

Provides validation for:
- Bank account numbers (Indian format)
- UPI IDs
- Phone numbers (Indian format)
- URLs/phishing links
"""

import re
from typing import Optional
import validators as url_validators


# Known UPI providers in India
UPI_PROVIDERS = {
    "paytm",
    "ybl",          # PhonePe
    "axisbank",
    "oksbi",        # SBI
    "okicici",      # ICICI
    "okhdfcbank",   # HDFC
    "icici",
    "sbi",
    "hdfc",
    "airtel",
    "freecharge",
    "jiomoney",
    "mobikwik",
    "apl",          # Amazon Pay
    "amazonpay",
    "ibl",          # ICICI Bank
    "axl",          # Axis Bank
    "upi",
    "gpay",
    "pingpay",
    "abfspay",
    "barodampay",
    "centralbank",
    "cnrb",
    "csbpay",
    "dbs",
    "federal",
    "finobank",
    "idfcbank",
    "indus",
    "kotak",
    "pnb",
    "rbl",
    "sib",
    "ubi",
    "united",
    "utbi",
    "vijb",
    "yesbankltd",
}


def is_valid_bank_account(number: str) -> bool:
    """
    Validate an Indian bank account number.
    
    Rules:
    - Length: 9-18 digits
    - Not all same digits
    - Not simple sequential patterns
    - At least 3 unique digits
    
    Args:
        number: Bank account number (digits only, no spaces/hyphens)
        
    Returns:
        bool: True if valid bank account format
    """
    # Must be digits only
    if not number.isdigit():
        return False
    
    # Check length (Indian bank accounts are 9-18 digits)
    if len(number) < 9 or len(number) > 18:
        return False
    
    # Reject all same digits (e.g., 111111111)
    if len(set(number)) < 3:
        return False
    
    # Reject purely sequential numbers (exact match only)
    # A number is sequential if it's a substring of a purely sequential pattern
    ascending = "12345678901234567890"
    descending = "09876543210987654321"
    
    # Only reject if the ENTIRE number is sequential
    if number in ascending or number in descending:
        return False
    
    # Reject date-like patterns (DDMMYYYY)
    if len(number) == 8:
        try:
            day = int(number[:2])
            month = int(number[2:4])
            if 1 <= day <= 31 and 1 <= month <= 12:
                return False
        except ValueError:
            pass
    
    return True


def is_valid_upi_id(upi_id: str) -> bool:
    """
    Validate a UPI ID format.
    
    Rules:
    - Format: username@provider
    - Provider must be in known UPI providers list
    - Username must be alphanumeric with allowed special chars (., -, _)
    
    Args:
        upi_id: UPI ID string (e.g., "user@paytm")
        
    Returns:
        bool: True if valid UPI ID format
    """
    if not upi_id or "@" not in upi_id:
        return False
    
    parts = upi_id.lower().split("@")
    if len(parts) != 2:
        return False
    
    username, provider = parts
    
    # Username validation: alphanumeric with ., -, _
    if not username or len(username) < 3:
        return False
    
    username_pattern = r'^[\w.\-]+$'
    if not re.match(username_pattern, username):
        return False
    
    # Provider must be known
    if provider not in UPI_PROVIDERS:
        return False
    
    return True


def is_valid_phone_number(phone: str) -> bool:
    """
    Validate an Indian phone number.
    
    Rules:
    - 10 digits (without country code) or 12 digits (with +91)
    - First digit must be 6, 7, 8, or 9
    - Not all same digits
    
    Args:
        phone: Phone number string
        
    Returns:
        bool: True if valid Indian phone number
    """
    # Clean the number
    clean = re.sub(r'[\s\-\(\)\+]', '', phone)
    
    # Remove country code if present
    if clean.startswith('91') and len(clean) == 12:
        clean = clean[2:]
    
    # Must be exactly 10 digits now
    if len(clean) != 10:
        return False
    
    # Must be all digits
    if not clean.isdigit():
        return False
    
    # First digit must be 6-9 (Indian mobile)
    if clean[0] not in '6789':
        return False
    
    # Reject all same digits
    if len(set(clean)) < 3:
        return False
    
    return True


def is_valid_url(url: str) -> bool:
    """
    Validate a URL/phishing link.
    
    Uses the validators library for robust URL validation.
    Also catches common shortened URLs.
    
    Args:
        url: URL string to validate
        
    Returns:
        bool: True if valid URL format
    """
    if not url:
        return False
    
    # Clean up the URL
    url = url.strip()
    
    # Add protocol if missing for validation
    test_url = url
    if not test_url.startswith(('http://', 'https://')):
        if test_url.startswith('www.'):
            test_url = 'http://' + test_url
        else:
            # Could be shortened URL like bit.ly/xyz
            test_url = 'http://' + test_url
    
    # Use validators library
    try:
        result = url_validators.url(test_url)
        return result is True
    except Exception:
        return False


def extract_clean_bank_account(raw: str) -> Optional[str]:
    """
    Clean a raw bank account string and validate it.
    
    Args:
        raw: Raw bank account string (may contain spaces/hyphens)
        
    Returns:
        Cleaned bank account number if valid, None otherwise
    """
    clean = re.sub(r'[\s\-]', '', raw)
    if is_valid_bank_account(clean):
        return clean
    return None


def extract_clean_phone(raw: str) -> Optional[str]:
    """
    Clean a raw phone number and return in standard format.
    
    Args:
        raw: Raw phone number string
        
    Returns:
        Phone number in +91XXXXXXXXXX format if valid, None otherwise
    """
    # Remove all non-digit characters except +
    clean = re.sub(r'[^\d+]', '', raw)
    
    # Normalize to 10-digit format first
    if clean.startswith('+91'):
        digits = clean[3:]
    elif clean.startswith('91') and len(clean) == 12:
        digits = clean[2:]
    elif clean.startswith('0') and len(clean) == 11:
        digits = clean[1:]
    else:
        digits = clean
    
    # Validate
    if len(digits) == 10 and digits[0] in '6789' and digits.isdigit():
        return f"+91{digits}"
    
    return None
