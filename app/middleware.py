from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse  # ✅ This line fixes the error

class WAFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        body = await request.body()
        if any(bad in body.decode("utf-8").lower() for bad in ["select", "drop", "union", "--", ";"]):
            return JSONResponse(content={"error": "Malicious input detected"}, status_code=403)

        response = await call_next(request)
        return response
