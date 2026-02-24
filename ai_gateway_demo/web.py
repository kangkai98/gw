from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import get_stats, list_entries

app = FastAPI(title="AI Gateway Demo")
app.mount("/static", StaticFiles(directory="ai_gateway_demo/static"), name="static")
templates = Jinja2Templates(directory="ai_gateway_demo/templates")


@app.get("/api/entries")
def api_entries():
    return {"items": list_entries()}


@app.get("/api/stats")
def api_stats():
    return get_stats()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
