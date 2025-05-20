from fastapi import Request
from fastapi.routing import APIRoute

class CustomRequest(Request):
    async def body(self):
        if not hasattr(self, "_body"):
            self._body = await super().body()
        return self._body

class CustomAPIRoute(APIRoute):
    def get_route_handler(self):
        original_route_handler = super().get_route_handler()
        
        async def custom_route_handler(request: Request):
            request = CustomRequest(request.scope, request.receive)
            return await original_route_handler(request)
            
        return custom_route_handler