from groq import Groq
import os
import json

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

async def analyze_request(request_data):
    prompt = f"""Analyze this HTTP request for security threats:
    {request_data}
    
    Consider OWASP Top 10 patterns and known attack vectors. 
    Respond with JSON: {{"block": boolean, "reason": string}}"""
    
    response = client.chat.completions.create(
        model="llama3-70b-8192",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )
    
    return json.loads(response.choices[0].message.content)