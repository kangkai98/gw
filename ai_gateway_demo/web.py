from __future__ import annotations

import socket
import subprocess
import json
import shlex
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import (
    add_self_hosted,
    clear_entries,
    clear_self_hosted,
    delete_self_hosted,
    get_stats,
    init_db,
    insert_entry,
    list_entries,
    list_self_hosted,
)
from .parser import parse_pcap_to_entries

app = FastAPI(title="AI Gateway Demo")

UPLOAD_PATH = Path("uploads")
UPLOAD_PATH.mkdir(exist_ok=True)
init_db()

app.mount("/static", StaticFiles(directory="ai_gateway_demo/static"), name="static")
templates = Jinja2Templates(directory="ai_gateway_demo/templates")


@app.get("/api/entries")
def api_entries(
    category_major: str | None = Query(default=None),
    category_minor: str | None = Query(default=None),
    start_rel_s: float | None = Query(default=None),
    end_rel_s: float | None = Query(default=None),
    start_real: str | None = Query(default=None),
    end_real: str | None = Query(default=None),
):
    return {
        "items": list_entries(
            category_major=category_major,
            category_minor=category_minor,
            start_rel_s=start_rel_s,
            end_rel_s=end_rel_s,
            start_real=start_real,
            end_real=end_real,
        )
    }


@app.get("/api/stats")
def api_stats(
    category_major: str | None = Query(default=None),
    category_minor: str | None = Query(default=None),
    start_rel_s: float | None = Query(default=None),
    end_rel_s: float | None = Query(default=None),
    start_real: str | None = Query(default=None),
    end_real: str | None = Query(default=None),
):
    return get_stats(
        category_major=category_major,
        category_minor=category_minor,
        start_rel_s=start_rel_s,
        end_rel_s=end_rel_s,
        start_real=start_real,
        end_real=end_real,
    )


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    filename = file.filename or "upload.pcap"
    local_file = UPLOAD_PATH / filename
    content = await file.read()
    local_file.write_bytes(content)

    configs = list_self_hosted()
    entries = parse_pcap_to_entries(local_file, self_hosted_configs=configs)
    inserted = sum(1 for e in entries if insert_entry(e))

    return {"inserted": inserted, "detected": len(entries)}


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


@app.post("/api/self-hosted/clear")
def api_self_hosted_clear():
    clear_self_hosted()
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "home"})


@app.get("/config", response_class=HTMLResponse)
def config_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "config"})


@app.get("/records", response_class=HTMLResponse)
def records_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "records"})


@app.get("/probe", response_class=HTMLResponse)
def probe_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "probe"})


@app.post("/api/connectivity-check")
def api_connectivity_check(target: str = Form(...), timeout_sec: float = Form(default=2.0)):
    raw = (target or "").strip()
    if not raw:
        return {"ok": False, "message": "目标为空"}

    parsed = urlparse(raw if "://" in raw else f"tcp://{raw}")
    host = parsed.hostname
    port = parsed.port
    if not host:
        return {"ok": False, "message": "无法解析主机地址"}

    if port is None:
        if parsed.scheme in ("http", "ws"):
            port = 80
        elif parsed.scheme in ("https", "wss"):
            port = 443
        else:
            return {"ok": False, "message": "请提供端口，如 10.0.0.2:443"}

    try:
        with socket.create_connection((host, int(port)), timeout=max(0.2, float(timeout_sec))):
            return {"ok": True, "message": f"连通成功: {host}:{port}"}
    except Exception as exc:  # pragma: no cover - network dependent
        return {"ok": False, "message": f"连通失败: {host}:{port} ({exc})"}


@app.post("/api/probe-curl")
def api_probe_curl(
    target: str = Form(default=""),
    api_key: str = Form(default=""),
    model: str = Form(default=""),
    curl_raw: str = Form(default=""),
    question: str = Form(default="你好"),
    timeout_sec: float = Form(default=20.0),
):
    user_curl = (curl_raw or "").strip()
    if not user_curl:
        return {"ok": False, "message": "curl原文不能为空"}

    raw_target = (target or "").strip().rstrip("/")

    if "/chat/completions" in raw_target:
        chat_url = raw_target
    elif raw_target.endswith("/v1"):
        chat_url = f"{raw_target}/chat/completions"
    else:
        chat_url = f"{raw_target}/v1/chat/completions"

    auth_header = f"Authorization: Bearer {api_key.strip()}"
    model_name = model.strip()

    if user_curl:
        try:
            cmd = shlex.split(user_curl)
        except Exception:
            return {"ok": False, "message": "curl原文解析失败，请检查引号与转义"}
        if not cmd or cmd[0] != "curl":
            return {"ok": False, "message": "curl原文必须以 curl 开头"}
    else:
        body = json.dumps(
            {
                "model": model_name,
                "messages": [{"role": "user", "content": (question or "你好").strip() or "你好"}],
                "stream": False,
            },
            ensure_ascii=False,
        )
        cmd = [
            "curl",
            "-sS",
            "-X",
            "POST",
            "--max-time",
            str(max(1.0, min(float(timeout_sec), 90.0))),
            chat_url,
            "-H",
            auth_header,
            "-H",
            "Content-Type: application/json",
            "--data",
            body,
        ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as exc:  # pragma: no cover - runtime dependent
        return {"ok": False, "message": f"curl 执行失败: {exc}"}

    ok = proc.returncode == 0
    response_text = ""
    error_reason = (proc.stderr or "").strip()
    if (proc.stdout or "").strip():
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, dict):
                choice = (parsed.get("choices") or [{}])[0]
                content = (choice.get("message") or {}).get("content", "")
                if isinstance(content, list):
                    response_text = "".join(str(i.get("text", "")) for i in content if isinstance(i, dict)).strip()
                else:
                    response_text = str(content).strip()
                if not response_text and choice.get("text"):
                    response_text = str(choice.get("text")).strip()
                if not response_text and parsed.get("error"):
                    error_reason = str(parsed.get("error"))
        except Exception:
            if ok:
                response_text = (proc.stdout or "").strip()[:8000]
            else:
                error_reason = (proc.stdout or "").strip()[:4000] or error_reason

    return {
        "ok": ok,
        "code": proc.returncode,
        "stdout": (proc.stdout or "")[:20000],
        "stderr": (proc.stderr or "")[:4000],
        "message": "请求完成" if ok else "请求失败",
        "command": " ".join(shlex.quote(part) for part in cmd),
        "model": model_name,
        "chat_url": chat_url,
        "response_text": response_text,
        "error_reason": error_reason,
    }
