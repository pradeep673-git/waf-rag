from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import re
from .rag_engine import analyze_request 

class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.regex_patterns = [
            re.compile(r"<script.*?>", re.IGNORECASE),
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\.\\", re.IGNORECASE),
        ]

    async def dispatch(self, request: Request, call_next):
        if not request.headers.get("Authorization"):
            return JSONResponse(
                status_code=401,
                content={"error": "Authentication required"}
            )

        body = await request.body()
        decoded_body = body.decode(errors="ignore")
        if any(pattern.search(decoded_body) for pattern in self.regex_patterns):
            return JSONResponse(
                status_code=403,
                content={"error": "Malicious input detected (regex)"}
            )

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
            return JSONResponse(
                status_code=500,
                content={"error": f"WAF AI processing error: {str(e)}"}
            )
        
        response = await call_next(request)
        return response
