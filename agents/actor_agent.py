"""
Actor Agent for persona-based response generation using Google Gemini AI.

This agent generates human-like responses pretending to be a victim,
maintaining a consistent persona throughout the conversation.
"""

import logging
import random
import time
from typing import Dict, List, Optional

import google.generativeai as genai

from .prompts import (
    PERSONA_PROMPTS,
    build_actor_prompt,
    get_persona_for_scam_type,
    humanize_response,
)

logger = logging.getLogger(__name__)


class ActorAgent:
    """
    Actor agent for generating persona-based responses.
    
    This agent pretends to be a potential scam victim, generating
    believable human-like responses to keep scammers engaged.
    
    Attributes:
        api_key (str): Gemini API key
        model_name (str): Gemini model identifier
        model: Gemini GenerativeModel instance
        current_persona (str): Currently active persona
    """
    
    def __init__(self, api_key: str, model_name: str = "gemini-1.5-flash"):
        """
        Initialize the actor agent.
        
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
        self.current_persona = None
        self.max_retries = 2
        self.retry_delay = 1.0
        
        logger.info(f"ActorAgent initialized with model: {model_name}")
    
    def _initialize_client(self) -> genai.GenerativeModel:
        """Initialize Gemini API client."""
        genai.configure(api_key=self.api_key)
        
        # Configure generation settings for creative responses
        generation_config = genai.types.GenerationConfig(
            temperature=0.8,  # Higher temperature for more varied responses
            max_output_tokens=200,
            top_p=0.9,
        )
        
        return genai.GenerativeModel(
            model_name=self.model_name,
            generation_config=generation_config,
        )
    
    def generate_response(
        self,
        message: str,
        persona: str,
        history: Optional[List[Dict]] = None
    ) -> str:
        """
        Generate a persona-based response to a scammer message.
        
        Args:
            message: Latest scammer message
            persona: One of "elderly", "professional", "novice"
            history: Conversation history
            
        Returns:
            Human-like response string
        """
        if not message:
            return self._get_fallback_response(persona)
        
        # Validate persona
        if persona not in PERSONA_PROMPTS:
            logger.warning(f"Unknown persona '{persona}', defaulting to 'elderly'")
            persona = "elderly"
        
        self.current_persona = persona
        logger.info(f"Generating response as '{persona}' persona")
        
        for attempt in range(self.max_retries + 1):
            try:
                # Build prompt with persona and context
                prompt = build_actor_prompt(message, persona, history)
                
                # Call Gemini API
                response = self.model.generate_content(prompt)
                
                # Clean and validate response
                text = self._clean_response(response.text)
                
                # Add human-like typos occasionally
                text = humanize_response(text, typo_probability=0.05)
                
                logger.info(f"Generated response: {text[:50]}...")
                return text
                
            except Exception as e:
                logger.error(f"Error generating response on attempt {attempt + 1}: {str(e)}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                    continue
        
        logger.warning("All attempts failed, using fallback response")
        return self._get_fallback_response(persona)
    
    def _clean_response(self, response_text: str) -> str:
        """
        Clean up the generated response.
        
        Removes quotes, extra whitespace, and ensures reasonable length.
        
        Args:
            response_text: Raw response from Gemini
            
        Returns:
            Cleaned response string
        """
        text = response_text.strip()
        
        # Remove surrounding quotes if present
        if (text.startswith('"') and text.endswith('"')) or \
           (text.startswith("'") and text.endswith("'")):
            text = text[1:-1]
        
        # Remove any prefix like "Reply:" or "Response:"
        prefixes = ["reply:", "response:", "message:", "answer:"]
        text_lower = text.lower()
        for prefix in prefixes:
            if text_lower.startswith(prefix):
                text = text[len(prefix):].strip()
                break
        
        # Ensure reasonable length (max 200 characters)
        if len(text) > 200:
            # Try to cut at a sentence boundary
            sentences = text.split('.')
            result = ""
            for sentence in sentences:
                if len(result) + len(sentence) + 1 <= 180:
                    result += sentence + "."
                else:
                    break
            text = result.strip() if result else text[:180] + "..."
        
        return text
    
    def _get_fallback_response(self, persona: str) -> str:
        """
        Get a fallback response when generation fails.
        
        Args:
            persona: The persona type
            
        Returns:
            Fallback response appropriate for the persona
        """
        fallbacks = {
            "elderly": [
                "Oh my, I'm so confused. Can you explain again?",
                "I don't understand. What should I do?",
                "This is worrying me. Is this real?",
                "I'm not sure what you mean. Can you help?",
                "My son usually helps me with these things.",
            ],
            "professional": [
                "I'll need verification for this.",
                "Can you send official documentation?",
                "I'm in a meeting. Send details via email.",
                "Let me check with my bank first.",
                "What's the official reference number?",
            ],
            "novice": [
                "omg wait what is happening",
                "im so confused rn",
                "this is scary idk what to do",
                "can u explain step by step?",
                "pls help me understand this",
            ],
        }
        
        responses = fallbacks.get(persona, fallbacks["elderly"])
        return random.choice(responses)
    
    def select_persona(
        self,
        scam_indicators: List[str] = None,
        channel: str = "sms",
        metadata: Dict = None
    ) -> str:
        """
        Select the best persona based on scam type and context.
        
        Args:
            scam_indicators: List of detected scam indicators
            channel: Communication channel (sms, whatsapp, email)
            metadata: Additional context metadata
            
        Returns:
            Selected persona name
        """
        # Determine scam type from indicators
        scam_type = "general"
        
        if scam_indicators:
            indicators_text = " ".join(scam_indicators).lower()
            
            if any(k in indicators_text for k in ["lottery", "winner", "prize"]):
                scam_type = "lottery"
            elif any(k in indicators_text for k in ["bank", "account", "kyc"]):
                scam_type = "banking"
            elif any(k in indicators_text for k in ["job", "work", "salary"]):
                scam_type = "job"
            elif any(k in indicators_text for k in ["delivery", "package", "order"]):
                scam_type = "delivery"
            elif any(k in indicators_text for k in ["otp", "password", "pin"]):
                scam_type = "otp"
        
        persona = get_persona_for_scam_type(scam_type, channel)
        
        logger.info(f"Selected persona '{persona}' for scam type '{scam_type}'")
        return persona
    
    def get_initial_response(self, persona: str) -> str:
        """
        Get an initial response when starting a conversation.
        
        Args:
            persona: The persona type
            
        Returns:
            Initial engagement response
        """
        initials = {
            "elderly": [
                "Hello? Who is this?",
                "Yes, I received a message. Is something wrong?",
                "Oh dear, what's happening with my account?",
            ],
            "professional": [
                "Yes, I saw your message. What's this about?",
                "I'm busy. Can you be quick?",
                "What seems to be the issue?",
            ],
            "novice": [
                "hey i got ur msg, whats going on?",
                "hi, is this about my account??",
                "omg did something happen?",
            ],
        }
        
        responses = initials.get(persona, initials["elderly"])
        return random.choice(responses)
