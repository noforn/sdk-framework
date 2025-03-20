import sys
import json

try:
    from google import genai
    from google.genai.types import GenerateContentConfig, GoogleSearch
    
    GEMINI_API_KEY = ""
    
    def perform_search(query):
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        search_prompt = f"""
        Find Common Vulnerabilities and Exposures (CVEs) specifically affecting {query}.
        Rank results by severity (highest first).
        Format output as a numbered list with:
        1. CVE ID
        2. Severity rating (Critical/High/Medium/Low)
        3. Brief description of the vulnerability
        
        Only include verified CVEs with clear severity ratings.
        """
        
        response = client.models.generate_content(
            model="gemini-2.0-flash-exp",
            contents=search_prompt,
            config=GenerateContentConfig(
                tools=[{"google_search": GoogleSearch()}],
                response_modalities=["TEXT"],
            )
        )
        
        return response.text.strip()
    
    if __name__ == "__main__":
        if len(sys.argv) < 2:
            print("Usage: python gemsearch.py 'query'")
            sys.exit(1)
        
        query = sys.argv[1]
        try:
            result = perform_search(query)
            print(result)
        except Exception as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)
            
except ImportError:
    print("Error: Could not import Google Gemini libraries.")
    sys.exit(1)