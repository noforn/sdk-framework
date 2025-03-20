#!/usr/bin/env python3

import sys
import json

try:
    from google import genai
    from google.genai.types import GenerateContentConfig, GoogleSearch
    
    GEMINI_API_KEY = ""
    
    def generate_command_suggestions(context):
        """
        Generate better security testing commands using Gemini
        
        Args:
            context: A dictionary containing scan results, discovered vulnerabilities,
                    and any prior commands that have been executed
                    
        Returns:
            Formatted command suggestions with explanations
        """
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        scan_results = context.get("scan_results", "")
        vulnerabilities = context.get("vulnerabilities", "")
        prior_commands = context.get("prior_commands", "")
        target_ip = context.get("target_ip", "unknown")
        
        prompt = f"""
        You are an advanced offensive security testing assistant. Based on the following information, 
        suggest 3-5 specific, targeted commands to test for the discovered vulnerabilities.  

        TARGET IP: {target_ip}

        SCAN RESULTS:
        {scan_results}

        DISCOVERED VULNERABILITIES:
        {vulnerabilities}

        PREVIOUS COMMANDS RUN:
        {prior_commands}

        Provide bash commands that:
        1. Are specific to the discovered services and vulnerabilities
        2. Use proper syntax and flags for Kali Linux tools
        3. Include safe timeouts to prevent hanging operations
        4. Would genuinely test for the presence of these vulnerabilities
        5. Are non-destructive and focused on vulnerability confirmation
        6. Focus on gaining initial access to the target system
        
        Format your response as:
        ```
        # Command 1: <brief purpose>
        <command>

        # Command 2: <brief purpose>
        <command>
        
        ...
        ```
        
        DO NOT include lengthy explanations - just the commands with brief comments.
        """
        
        response = client.models.generate_content(
            model="gemini-2.0-flash-thinking-exp-01-21",
            contents=prompt,
            config=GenerateContentConfig(
                tools=[{"google_search": GoogleSearch()}],
                response_modalities=["TEXT"],
            )
        )
        
        return response.text.strip()
    
    if __name__ == "__main__":
        if len(sys.argv) < 2:
            print("Usage: python suggest.py '<context json>'")
            sys.exit(1)
        
        try:
            context = json.loads(sys.argv[1])
            suggestions = generate_command_suggestions(context)
            print(suggestions)
        except json.JSONDecodeError:
            print("Error: Invalid JSON context", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
            
except ImportError:
    print("Error: Could not import Google Gemini libraries. Please ensure google-generativeai is installed correctly.")
    sys.exit(1)