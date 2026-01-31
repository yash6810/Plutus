"""
API authentication middleware and utilities.

Provides API key validation for the Honeypot agent endpoints.
"""

import logging
from typing import Optional

from fastapi import Header, HTTPException, Depends
from fastapi.security import APIKeyHeader

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

logger = logging.getLogger(__name__)

# API Key header configuration
API_KEY_HEADER = APIKeyHeader(name="x-api-key", auto_error=False)


async def verify_api_key(
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
) -> str:
    """
    Verify the API key from request header.
    
    Args:
        x_api_key: API key from x-api-key header
        
    Returns:
        Validated API key
        
    Raises:
        HTTPException: 401 if key is missing or invalid
    """
    if not x_api_key:
        logger.warning("API request without API key")
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Include 'x-api-key' header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Validate against configured secret
    if x_api_key != config.API_SECRET_KEY:
        logger.warning(f"Invalid API key attempt: {x_api_key[:8]}...")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    logger.debug("API key validated successfully")
    return x_api_key


async def optional_api_key(
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
) -> Optional[str]:
    """
    Optional API key validation (for endpoints that may not require auth).
    
    Args:
        x_api_key: API key from header (optional)
        
    Returns:
        API key if provided and valid, None otherwise
    """
    if not x_api_key:
        return None
    
    if x_api_key == config.API_SECRET_KEY:
        return x_api_key
    
    return None


class APIKeyValidator:
    """
    Class-based API key validator for more complex validation scenarios.
    """
    
    def __init__(self, require_auth: bool = True):
        """
        Initialize the validator.
        
        Args:
            require_auth: Whether authentication is required
        """
        self.require_auth = require_auth
    
    async def __call__(
        self,
        x_api_key: Optional[str] = Header(None, alias="x-api-key")
    ) -> Optional[str]:
        """
        Validate the API key.
        
        Args:
            x_api_key: API key from header
            
        Returns:
            Validated API key
            
        Raises:
            HTTPException: If auth required and key invalid
        """
        if self.require_auth:
            return await verify_api_key(x_api_key)
        else:
            return await optional_api_key(x_api_key)


# Pre-configured validators
require_api_key = Depends(verify_api_key)
optional_auth = Depends(optional_api_key)
