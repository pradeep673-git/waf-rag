# from fastapi import Request
# from fastapi.responses import JSONResponse
# from starlette.middleware.base import BaseHTTPMiddleware
# from .rag_engine import analyze_request
# import re

# class WAFMiddleware(BaseHTTPMiddleware):
#     def __init__(self, app):
#         super().__init__(app)
#         self.regex_patterns = [
#             re.compile(pattern, re.IGNORECASE) 
#             for pattern in [
#                 r"(\'|\")(;|--)|(/\*.*\*/)",
#                 r"\b(union|select|insert|delete|update)\b",
#                 r"<script.*?>",
#                 r"javascript:",
#                 r"<img src=",
#                 r"<iframe src=",
#                 r"<body onload=",
#                 r"<a href=",
#                 r"<link href=",
#                 r"<style>",
#                 r"<meta http-equiv=",
#                 r"<object data=",
#                 r"<embed src=",
#                 r"<video src=",
#                 r"<audio src=",
#                 r"<marquee behavior="
#             ]
#         ]
#         self.literal_checks = [
#             "1=1", "--", ";", "drop", "where", 
#             "or", "and", "exec", "chr(", "waitfor",
#             "delay", "sysdate", "pg_sleep"
#         ]

#     async def dispatch(self, request: Request, call_next):
#         try:
#             body = await request.body()
#             decoded_body = body.decode(errors="ignore").lower()
            
#             if self._is_malicious(decoded_body):
#                 return JSONResponse(
#                     content={"error": "Malicious input detected"},
#                     status_code=403
#                 )
            
#             ai_decision = await analyze_request({
#                 "method": request.method,
#                 "path": request.url.path,
#                 "headers": dict(request.headers),
#                 "body": decoded_body
#             })
            
#             if ai_decision.get("block"):
#                 return JSONResponse(
#                     status_code=403,
#                     content={"block_reason": ai_decision.get("reason", "AI detected threat")}
#                 )
            
#             response = await call_next(request)
#             return response
            
#         except Exception as e:
#             return JSONResponse(
#                 status_code=500,
#                 content={"error": f"WAF processing error: {str(e)}"}
#             )

#     def _is_malicious(self, body: str) -> bool:
#         """Check against both regex patterns and literal strings"""
#         if any(pattern.search(body) for pattern in self.regex_patterns):
#             return True
            

#         if any(keyword in body for keyword in self.literal_checks):
#             return True
            
#         return False
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from .rag_engine import analyze_request
import re

class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        # Static regex patterns for known attacks
        self.regex_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in [
                r"(\'|\")(;|--)|(/\*.*\*/)",
                r"\b(union|select|insert|delete|update)\b",
                r"<script.*?>",
                r"javascript:",
                r"<img src=",
                r"<iframe src=",
                r"<body onload=",
                r"<a href=",
                r"<link href=",
                r"<style>",
                r"<meta http-equiv=",
                r"<object data=",
                r"<embed src=",
                r"<video src=",
                r"<audio src=",
                r"<marquee behavior="
            ]
        ]
        # Literal keywords as regex with word boundaries where needed
        self.literal_regex_patterns = [
            re.compile(r"\b1=1\b", re.IGNORECASE),
            re.compile(r"--", re.IGNORECASE),
            re.compile(r";", re.IGNORECASE),
            re.compile(r"\bdrop\b", re.IGNORECASE),
            re.compile(r"\bwhere\b", re.IGNORECASE),
            re.compile(r"\bor\b", re.IGNORECASE),
            re.compile(r"\band\b", re.IGNORECASE),
            re.compile(r"\bexec\b", re.IGNORECASE),
            re.compile(r"chr\(", re.IGNORECASE),
            re.compile(r"\bwaitfor\b", re.IGNORECASE),
            re.compile(r"\bdelay\b", re.IGNORECASE),
            re.compile(r"\bsysdate\b", re.IGNORECASE),
            re.compile(r"\bpg_sleep\b", re.IGNORECASE)
        ]

    async def dispatch(self, request: Request, call_next):
        try:
            body = await request.body()
            decoded_body = body.decode(errors="ignore").lower()
            
            if self._is_malicious(decoded_body):
                return JSONResponse(
                    content={"error": "Malicious input detected"},
                    status_code=403
                )
            
            ai_decision = await analyze_request({
                "method": request.method,
                "path": request.url.path,
                "headers": dict(request.headers),
                "body": decoded_body
            })
            
            if ai_decision.get("block"):
                return JSONResponse(
                    status_code=403,
                    content={"block_reason": ai_decision.get("reason", "AI detected threat")}
                )
            
            response = await call_next(request)
            return response
            
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": f"WAF processing error: {str(e)}"}
            )

    def _is_malicious(self, body: str) -> bool:
        """Check against both regex patterns and literal regex patterns"""
        # Check static regex patterns
        if any(pattern.search(body) for pattern in self.regex_patterns):
            return True
        # Check literal regex patterns with word boundaries
        if any(pattern.search(body) for pattern in self.literal_regex_patterns):
            return True
        return False