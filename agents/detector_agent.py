"""
Detector Agent for scam classification using Google Gemini AI.

This agent analyzes incoming messages and classifies them as scam or legitimate
with a confidence score and reasoning.
"""

import json
import logging
import re
import time
from typing import Dict, List, Any, Optional

import google.generativeai as genai

from .prompts import DETECTOR_SYSTEM_PROMPT, build_detector_prompt

logger = logging.getLogger(__name__)


class DetectorAgent:
    """
    Scam detection agent using Gemini API.
    
    This agent analyzes incoming messages and classifies them as scam
    or legitimate with a confidence score.
    
    Attributes:
        api_key (str): Gemini API key
        model_name (str): Gemini model identifier
        model: Gemini GenerativeModel instance
    """
    
    def __init__(self, api_key: str, model_name: str = "gemini-1.5-flash"):
        """
        Initialize the detector agent.
        
        Args:
            api_key: Gemini API key
            model_name: Model to use (default: gemini-1.5-flash)
            
        Raises:
            ValueError: If api_key is empty
        """
        if not api_key:
            raise ValueError("API key cannot be empty")
        
        self.api_key = api_key
        self.model_name = model_name
        self.model = self._initialize_client()
        self.max_retries = 2
        self.retry_delay = 1.0
        
        logger.info(f"DetectorAgent initialized with model: {model_name}")
    
    def _initialize_client(self) -> genai.GenerativeModel:
        """Initialize Gemini API client."""
        genai.configure(api_key=self.api_key)
        
        # Configure generation settings
        generation_config = genai.types.GenerationConfig(
            temperature=0.3,  # Lower temperature for more consistent classification
            max_output_tokens=500,
        )
        
        try:
            # Try with system_instruction (modern way)
            model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=generation_config,
                system_instruction=DETECTOR_SYSTEM_PROMPT,
            )
            self.uses_system_instruction = True
            return model
        except TypeError:
            # Fallback for older google-generativeai versions
            logger.warning("system_instruction not supported by this version of google-generativeai. Using prompt prefix fallback.")
            model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=generation_config,
            )
            self.uses_system_instruction = False
            return model

    
    def detect_scam(
        self, 
        message: str, 
        history: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Detect if a message is a scam.
        
        Args:
            message: Message text to analyze
            history: Optional conversation history for context
            
        Returns:
            Dict containing:
                - is_scam (bool): Whether message is a scam
                - confidence (float): Confidence score 0.0-1.0
                - reason (str): Explanation
                - indicators (List[str]): Detected scam patterns
        """
        if not message or len(message.strip()) == 0:
            logger.warning("Empty message received")
            return self._default_response()
        
        logger.info(f"Analyzing message: {message[:50]}...")
        
        for attempt in range(self.max_retries + 1):
            try:
                # Build prompt with history context
                prompt = build_detector_prompt(message, history)
                
                # If system_instruction was not supported, prepend it to the prompt
                if not getattr(self, "uses_system_instruction", True):
                    prompt = f"{DETECTOR_SYSTEM_PROMPT}\n\n{prompt}"
                
                # Call Gemini API
                response = self.model.generate_content(prompt)

                
                # Parse JSON response
                result = self._parse_response(response.text)
                
                logger.info(
                    f"Scam detection complete: is_scam={result['is_scam']} "
                    f"(confidence: {result['confidence']:.2f})"
                )
                return result
                
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error on attempt {attempt + 1}: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                    continue
                    
            except Exception as e:
                logger.error(f"Error detecting scam on attempt {attempt + 1}: {str(e)}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                    continue
        
        logger.error("All retry attempts failed, returning default response")
        return self._default_response()
    
    def _parse_response(self, response_text: str) -> Dict[str, Any]:
        """
        Safely parse JSON from Gemini response.
        
        Handles cases where response is wrapped in markdown code blocks.
        
        Args:
            response_text: Raw response text from Gemini
            
        Returns:
            Parsed response dict
            
        Raises:
            json.JSONDecodeError: If parsing fails
        """
        text = response_text.strip()
        
        # Remove markdown code blocks if present
        if text.startswith("```"):
            # Find the JSON content between code blocks
            match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
            if match:
                text = match.group(1)
        
        # Parse JSON
        data = json.loads(text)
        
        # Validate and normalize response
        return {
            "is_scam": bool(data.get("is_scam", False)),
            "confidence": float(data.get("confidence", 0.5)),
            "reason": str(data.get("reason", "No reason provided")),
            "indicators": list(data.get("indicators", [])),
        }
    
    def _default_response(self) -> Dict[str, Any]:
        """Return default response when detection fails."""
        return {
            "is_scam": False,
            "confidence": 0.5,
            "reason": "Unable to analyze message",
            "indicators": [],
        }
    
    def get_quick_classification(self, message: str) -> bool:
        """
        Quick classification without full analysis.
        
        Uses basic keyword matching for fast initial screening.
        
        Args:
            message: Message to classify
            
        Returns:
            True if message appears to be a scam
        """
        if not message:
            return False
        
        message_lower = message.lower()
        
        # High-confidence scam indicators
        strong_indicators = [
            "send otp",
            "share otp",
            "your account will be",
            "account suspended",
            "account blocked",
            "kyc update",
            "click here to verify",
            "won lottery",
            "lucky winner",
            "processing fee",
            "claim your prize",
            "legal action",
            "police complaint",
            "arrest warrant",
        ]
        
        for indicator in strong_indicators:
            if indicator in message_lower:
                return True
        
        return False
