from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import (
    clear_entries,
    delete_self_hosted_config,
    get_stats,
    init_db,
    insert_entries,
    list_entries,
    list_self_hosted_configs,
    upsert_self_hosted_config,
)
from .parser import parse_pcap_to_entries

app = FastAPI(title="AI Gateway Demo")
app.mount("/static", StaticFiles(directory="ai_gateway_demo/static"), name="static")
templates = Jinja2Templates(directory="ai_gateway_demo/templates")


@app.on_event("startup")
def startup_init() -> None:
    init_db()


@app.get("/api/entries")
def api_entries():
    return {"items": list_entries()}


@app.get("/api/stats")
def api_stats():
    return get_stats()


@app.get("/api/self-hosted-configs")
def api_list_configs():
    return {"items": list_self_hosted_configs()}


@app.post("/api/self-hosted-configs")
def api_add_config(ip: str = Form(...), label: str = Form(...)):
    if not ip.strip() or not label.strip():
        raise HTTPException(status_code=400, detail="ip and label are required")
    upsert_self_hosted_config(ip, label)
    return {"ok": True}


@app.delete("/api/self-hosted-configs/{config_id}")
def api_del_config(config_id: int):
    delete_self_hosted_config(config_id)
    return {"ok": True}


@app.post("/api/upload-pcap")
async def api_upload_pcap(
    file: UploadFile = File(...),
    gap: float = Form(2.0),
    ai_ip: str = Form(""),
):
    suffix = Path(file.filename or "upload.pcap").suffix or ".pcap"
    tmp_path = Path(f"/tmp/ai_gateway_upload{suffix}")

    data = await file.read()
    tmp_path.write_bytes(data)
    try:
        entries = parse_pcap_to_entries(
            pcap_path=tmp_path,
            gap_threshold=gap,
            self_hosted_configs=list_self_hosted_configs(),
            ai_ip=(ai_ip.strip() or None),
        )
        insert_entries(entries)
        return {"ok": True, "inserted": len(entries)}
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


@app.post("/api/clear-entries")
def api_clear_entries():
    clear_entries()
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
