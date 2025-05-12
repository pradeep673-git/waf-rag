from fastapi import FastAPI
from .middleware import WAFMiddleware

app = FastAPI()
app.add_middleware(WAFMiddleware)

@app.get("/")

def home():
    return {"message": "this is a waf and it is working"}
