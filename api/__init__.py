"""
API package for Honeypot Scam Detection Agent.

Contains:
- FastAPI application and endpoints
- Pydantic models for request/response validation
- Authentication middleware
- GUVI callback handler
"""

from .main import app

__all__ = ["app"]
