from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import (
    add_self_hosted,
    clear_entries,
    delete_self_hosted,
    get_stats,
    init_db,
    insert_entry,
    list_entries,
    list_self_hosted,
)
from .parser import parse_pcap_to_entries

app = FastAPI(title="AI Gateway Demo")
app.mount("/static", StaticFiles(directory="ai_gateway_demo/static"), name="static")
templates = Jinja2Templates(directory="ai_gateway_demo/templates")

UPLOAD_PATH = Path("uploads")
UPLOAD_PATH.mkdir(exist_ok=True)
init_db()


@app.get("/api/entries")
def api_entries():
    return {"items": list_entries()}


@app.get("/api/stats")
def api_stats():
    return get_stats()


@app.post("/api/upload")
async def api_upload(
    file: UploadFile = File(...),
    gap: float = Form(2.0),
    ai_ip: str | None = Form(None),
):
    filename = file.filename or "upload.pcap"
    local_file = UPLOAD_PATH / filename
    content = await file.read()
    local_file.write_bytes(content)

    configs = list_self_hosted()
    entries = parse_pcap_to_entries(local_file, gap_threshold=gap, self_hosted_configs=configs, ai_ip=ai_ip)
    for e in entries:
        insert_entry(e)

    return {"inserted": len(entries)}


@app.post("/api/clear")
def api_clear():
    clear_entries()
    return {"ok": True}


@app.get("/api/self-hosted")
def api_self_hosted_list():
    return {"items": list_self_hosted()}


@app.post("/api/self-hosted")
def api_self_hosted_add(name: str = Form(...), server_ip: str = Form(...)):
    add_self_hosted(name=name, server_ip=server_ip)
    return {"ok": True}


@app.delete("/api/self-hosted/{service_id}")
def api_self_hosted_delete(service_id: int):
    delete_self_hosted(service_id)
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
