from fastapi import FastAPI, Request
from .middleware import WAFMiddleware

app = FastAPI()
app.add_middleware(WAFMiddleware)


@app.get("/")
def home():
    return {"message": "this is a waf and it is working"}

@app.post("/echo")
async def echo_endpoint(request: Request):
    body = await request.body()
    return {"received": body.decode(errors="ignore")}
    return await request.json()