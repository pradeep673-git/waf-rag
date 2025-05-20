# from fastapi import Request, HTTPException
# from fastapi.responses import JSONResponse
# from starlette.middleware.base import BaseHTTPMiddleware
# import re

# class WAFMiddleware(BaseHTTPMiddleware):
#     def __init__(self, app):
#         super().__init__(app)
#         self.regex_patterns = [
#             re.compile(r"<script.*?>", re.IGNORECASE),
#             re.compile(r"\.\./", re.IGNORECASE),      
#             re.compile(r"\.\.\\", re.IGNORECASE),
#             # ... add more targeted patterns
#         ]

#     async def dispatch(self, request: Request, call_next):
#         # Example: Directly block if not authenticated
#         if not request.headers.get("Authorization"):
#             # Immediately stop and ask for authentication
#             return JSONResponse(
#                 status_code=401,
#                 content={"error": "Authentication required"}
#             )
        
#         # Example: Directly block if malicious input
#         body = await request.body()
#         decoded_body = body.decode(errors="ignore")
#         if any(pattern.search(decoded_body) for pattern in self.regex_patterns):
#             return JSONResponse(
#                 status_code=403,
#                 content={"error": "Malicious input detected"}
#             )
        
#         # If all checks pass, continue to the next handler
#         response = await call_next(request)
#         return response

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import re
from .rag_engine import analyze_request  # Make sure this function exists and returns a dict

class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.regex_patterns = [
            re.compile(r"<script.*?>", re.IGNORECASE),
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\.\\", re.IGNORECASE),
            # ... add more targeted patterns if needed
        ]

    async def dispatch(self, request: Request, call_next):
        # 1. Block if not authenticated
        if not request.headers.get("Authorization"):
            return JSONResponse(
                status_code=401,
                content={"error": "Authentication required"}
            )

        # 2. Block if static regex patterns match
        body = await request.body()
        decoded_body = body.decode(errors="ignore")
        if any(pattern.search(decoded_body) for pattern in self.regex_patterns):
            return JSONResponse(
                status_code=403,
                content={"error": "Malicious input detected (regex)"}
            )

        # 3. Use RAG/AI for advanced detection
        try:
            ai_decision = await analyze_request({
                "method": request.method,
                "path": request.url.path,
                "headers": dict(request.headers),
                "body": decoded_body
            })
            if ai_decision.get("block"):
                return JSONResponse(
                    status_code=403,
                    content={"error": "Malicious input detected (AI)", "reason": ai_decision.get("reason", "")}
                )
        except Exception as e:
            # If AI service fails, you can log or choose to allow/block by default
            return JSONResponse(
                status_code=500,
                content={"error": f"WAF AI processing error: {str(e)}"}
            )

        # 4. If all checks pass, continue to the next handler
        response = await call_next(request)
        return response
