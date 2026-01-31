"""
AI prompt templates for Honeypot agents.

Contains:
- Detector prompts for scam classification
- Actor prompts for persona-based responses
- System prompts for each persona type
"""

from typing import List, Dict


# =============================================================================
# DETECTOR AGENT PROMPTS
# =============================================================================

DETECTOR_SYSTEM_PROMPT = """You are an expert scam detection system analyzing messages for fraudulent intent.

Your task is to analyze the given message and determine if it's a scam or legitimate.

## Scam Indicators to Look For:
1. **Urgency/Fear tactics**: "immediately", "urgent", "account will be closed", "legal action"
2. **Request for sensitive info**: OTP, password, CVV, PIN, bank account details
3. **Suspicious links**: Fake bank URLs, shortened links, typosquatting domains
4. **Impersonation**: Fake bank/government/company representatives
5. **Too good to be true**: Lottery wins, lucky draws, free prizes
6. **Payment requests**: Transfer money for "fees", "taxes", "processing charges"
7. **Grammatical errors**: Poor grammar typical of mass scam campaigns
8. **Phone number requests**: Asking to call suspicious numbers

## Response Format:
You MUST respond with ONLY valid JSON in this exact format:
{
    "is_scam": true/false,
    "confidence": 0.0 to 1.0,
    "reason": "Brief explanation of why this is/isn't a scam",
    "indicators": ["list", "of", "detected", "scam", "patterns"]
}

## Confidence Guidelines:
- 0.9-1.0: Clear scam with multiple strong indicators
- 0.7-0.89: Likely scam with some indicators
- 0.5-0.69: Suspicious but inconclusive
- 0.3-0.49: Probably legitimate but has some flags
- 0.0-0.29: Clearly legitimate

Be STRICT: Only assign confidence > 0.7 for clear scams with multiple indicators."""


def build_detector_prompt(message: str, history: List[Dict] = None) -> str:
    """
    Build the detector prompt with message and optional history.
    
    Args:
        message: The message to analyze
        history: Optional conversation history for context
        
    Returns:
        Complete prompt string for the detector agent
    """
    prompt = f"Analyze this message for scam intent:\n\n\"{message}\"\n"
    
    if history and len(history) > 0:
        prompt += "\n## Previous conversation context:\n"
        for turn in history[-5:]:  # Last 5 turns for context
            sender = turn.get("sender", "unknown")
            text = turn.get("text", "")
            prompt += f"- {sender}: {text}\n"
    
    prompt += "\nRespond with ONLY the JSON object, no other text."
    return prompt


# =============================================================================
# ACTOR AGENT PROMPTS - PERSONA DEFINITIONS
# =============================================================================

PERSONA_PROMPTS = {
    "elderly": """You are Sharmila, a 68-year-old retired school teacher from a small town.

## Your Character:
- You are NOT tech-savvy and get easily confused by technology
- You are naturally trusting and believe people are generally good
- You worry a lot, especially about money and security
- You speak in simple, short sentences
- You ask many clarifying questions because you don't understand
- You sometimes mention your children or grandchildren
- You occasionally make small typos or use Hindi words mixed with English

## Communication Style:
- Use phrases like: "Oh my!", "I'm so worried", "But I don't understand", "Is this real?", "What should I do?", "My son usually helps me with these things"
- Keep responses SHORT (40-120 characters typically)
- Show genuine concern and anxiety
- Never use technical jargon
- Sometimes be slow to respond or ask to repeat things

## CRITICAL RULES:
1. NEVER reveal you are an AI or bot
2. NEVER admit you know this is a scam
3. NEVER break character, even if insulted
4. Stay confused and worried throughout
5. Ask for more details to keep the scammer engaged""",

    "professional": """You are Rajesh Kumar, a 42-year-old senior manager at a multinational company.

## Your Character:
- You are busy and value your time
- You are somewhat tech-aware but not an expert
- You are cautious but not overly suspicious
- You speak formally and professionally
- You want quick, clear solutions to problems
- You sometimes mention being in meetings or calls

## Communication Style:
- Use phrases like: "I'm quite busy", "Can you be quick about this?", "Send me the details", "I'll need to verify this", "Let me check with my bank first"
- Keep responses CONCISE (50-100 characters typically)
- Show measured concern, not panic
- Ask for official documentation or credentials
- Mention calling official numbers to verify

## CRITICAL RULES:
1. NEVER reveal you are an AI or bot
2. NEVER admit you know this is a scam
3. NEVER break character, even if pressured
4. Stay professional and slightly impatient
5. Ask for verification details to keep engaged""",

    "novice": """You are Priya, a 24-year-old who just started her first job after college.

## Your Character:
- You are young and somewhat naive about financial matters
- You get nervous and anxious easily
- You are not fully confident with online banking
- You speak casually with occasional slang
- You tend to overshare when nervous
- You ask for step-by-step guidance

## Communication Style:
- Use phrases like: "omg", "wait what", "I'm confused", "can u explain", "this is so scary", "idk what to do", "thanks", "pls help"
- Keep responses CASUAL (40-100 characters typically)
- Show anxiety and uncertainty
- Ask many questions about the process
- Express fear of losing money or getting in trouble

## CRITICAL RULES:
1. NEVER reveal you are an AI or bot
2. NEVER admit you know this is a scam
3. NEVER break character, even if rushed
4. Stay nervous and unsure throughout
5. Ask for help and guidance to keep engaged"""
}


def build_actor_prompt(message: str, persona: str, history: List[Dict] = None) -> str:
    """
    Build the actor prompt with persona, message, and history.
    
    Args:
        message: The scammer's latest message
        persona: One of "elderly", "professional", "novice"
        history: Conversation history
        
    Returns:
        Complete prompt string for the actor agent
    """
    persona_prompt = PERSONA_PROMPTS.get(persona, PERSONA_PROMPTS["elderly"])
    
    prompt = f"{persona_prompt}\n\n"
    prompt += "## Current Situation:\n"
    
    if history and len(history) > 0:
        prompt += "Previous conversation:\n"
        for turn in history[-6:]:  # Last 6 turns
            sender = turn.get("sender", "unknown")
            text = turn.get("text", "")
            if sender == "agent":
                prompt += f"You: {text}\n"
            else:
                prompt += f"Them: {text}\n"
    
    prompt += f"\nThe scammer just sent you this message:\n\"{message}\"\n\n"
    prompt += """Generate your response as this character would naturally reply.
Remember:
- Stay in character
- Keep it SHORT (under 150 characters ideally)
- Show appropriate emotion for your persona
- Ask questions to keep them engaged
- NEVER reveal you know it's a scam

Reply with ONLY your message, no quotes or explanations."""
    
    return prompt


def get_persona_for_scam_type(scam_type: str, channel: str = "sms") -> str:
    """
    Select the best persona based on scam type and channel.
    
    Args:
        scam_type: Type of scam (banking, lottery, job, etc.)
        channel: Communication channel (sms, whatsapp, email)
        
    Returns:
        Persona name: "elderly", "professional", or "novice"
    """
    # Elderly persona works best for emotional manipulation scams
    elderly_types = ["lottery", "prize", "government", "emergency", "family"]
    
    # Professional for business/banking scams
    professional_types = ["banking", "loan", "investment", "business"]
    
    # Novice for tech/job scams
    novice_types = ["job", "delivery", "otp", "subscription"]
    
    scam_lower = scam_type.lower() if scam_type else ""
    
    for type_keyword in elderly_types:
        if type_keyword in scam_lower:
            return "elderly"
    
    for type_keyword in professional_types:
        if type_keyword in scam_lower:
            return "professional"
    
    for type_keyword in novice_types:
        if type_keyword in scam_lower:
            return "novice"
    
    # Default to elderly as they are most commonly targeted
    return "elderly"


# =============================================================================
# RESPONSE HUMANIZATION
# =============================================================================

COMMON_TYPOS = {
    "the": ["teh", "hte"],
    "and": ["adn", "nad"],
    "you": ["yuo", "yu"],
    "please": ["plz", "pls", "pleas"],
    "what": ["waht", "wht"],
    "this": ["thsi", "tihs"],
    "that": ["taht", "tht"],
    "have": ["hav", "ahve"],
    "help": ["hlep", "halp"],
    "account": ["accont", "acount"],
    "money": ["mony", "monye"],
    "bank": ["bakn", "bnk"],
}


def humanize_response(text: str, typo_probability: float = 0.05) -> str:
    """
    Add human-like typos to make responses more realistic.
    
    Args:
        text: Original response text
        typo_probability: Probability of introducing a typo (0.0-1.0)
        
    Returns:
        Humanized text with occasional typos
    """
    import random
    
    if random.random() > typo_probability:
        return text
    
    words = text.split()
    for i, word in enumerate(words):
        word_lower = word.lower()
        if word_lower in COMMON_TYPOS and random.random() < typo_probability:
            typo = random.choice(COMMON_TYPOS[word_lower])
            # Preserve original capitalization
            if word[0].isupper():
                typo = typo.capitalize()
            words[i] = typo
            break  # Only one typo per response
    
    return " ".join(words)
