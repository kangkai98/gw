from __future__ import annotations

import socket
import subprocess
import json
import shlex
import ssl
import time
import http.client
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
    refresh_entry_categories_by_self_hosted,
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
def api_self_hosted_add(name: str = Form(...), server_ip: str = Form(...), server_port: int = Form(...)):
    add_self_hosted(name=name, server_ip=server_ip, server_port=server_port)
    updated = refresh_entry_categories_by_self_hosted()
    return {"ok": True, "updated_entries": updated}


@app.delete("/api/self-hosted/{service_id}")
def api_self_hosted_delete(service_id: int):
    delete_self_hosted(service_id)
    updated = refresh_entry_categories_by_self_hosted()
    return {"ok": True, "updated_entries": updated}


@app.post("/api/self-hosted/clear")
def api_self_hosted_clear():
    clear_self_hosted()
    updated = refresh_entry_categories_by_self_hosted()
    return {"ok": True, "updated_entries": updated}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "home"})


@app.get("/config", response_class=HTMLResponse)
def config_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "config"})


@app.get("/records", response_class=HTMLResponse)
def records_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "records"})


@app.get("/query", response_class=HTMLResponse)
def query_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "page": "query"})


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


def _to_chat_completions_url(base_url: str) -> str:
    raw_target = (base_url or "").strip().rstrip("/")
    if "/chat/completions" in raw_target:
        return raw_target
    if raw_target.endswith("/v1"):
        return f"{raw_target}/chat/completions"
    return f"{raw_target}/v1/chat/completions"


def _http_post_json(url: str, payload: dict, headers: dict[str, str], timeout_sec: float) -> tuple[int, bytes, float]:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    if not host:
        raise ValueError("URL 缺少主机地址")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout_sec, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout_sec)
    start = time.perf_counter()
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    latency_ms = (time.perf_counter() - start) * 1000
    status = int(resp.status or 0)
    conn.close()
    return status, raw, latency_ms


def _http_post_stream_probe(url: str, payload: dict, headers: dict[str, str], timeout_sec: float) -> dict:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    if not host:
        raise ValueError("URL 缺少主机地址")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    conn: http.client.HTTPConnection | http.client.HTTPSConnection
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout_sec, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout_sec)

    t0 = time.perf_counter()
    conn.request("POST", path, body=body, headers=headers)
    resp = conn.getresponse()
    status = int(resp.status or 0)
    ttfb_ms: float | None = None
    ttft_ms: float | None = None
    collected: list[str] = []
    try:
        while True:
            line = resp.fp.readline(65536)
            if not line:
                break
            now_ms = (time.perf_counter() - t0) * 1000
            if ttfb_ms is None:
                ttfb_ms = now_ms
            text = line.decode("utf-8", errors="ignore").strip()
            if not text.startswith("data:"):
                continue
            payload_text = text[5:].strip()
            if not payload_text or payload_text == "[DONE]":
                continue
            try:
                data = json.loads(payload_text)
            except Exception:
                continue
            choice = (data.get("choices") or [{}])[0] if isinstance(data, dict) else {}
            delta = choice.get("delta") if isinstance(choice, dict) else {}
            content = ""
            if isinstance(delta, dict):
                content = str(delta.get("content") or "")
            if content:
                if ttft_ms is None:
                    ttft_ms = now_ms
                collected.append(content)
    finally:
        conn.close()

    latency_ms = (time.perf_counter() - t0) * 1000
    return {
        "status_code": status,
        "latency_ms": latency_ms,
        "ttfb_ms": ttfb_ms,
        "ttft_ms": ttft_ms,
        "response_text": "".join(collected)[:2000],
    }


@app.post("/api/probe/llm")
def api_probe_llm(
    target: str = Form(...),
    api_key: str = Form(default=""),
    model: str = Form(default="gpt-4o-mini"),
    question: str = Form(default="你好"),
    mode: str = Form(default="standard"),
    timeout_sec: float = Form(default=20.0),
):
    chat_url = _to_chat_completions_url(target)
    timeout_value = max(2.0, min(float(timeout_sec), 90.0))
    headers = {
        "Content-Type": "application/json",
    }
    if api_key.strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"

    stream_mode = mode == "stream"
    payload = {
        "model": (model or "gpt-4o-mini").strip() or "gpt-4o-mini",
        "messages": [{"role": "user", "content": (question or "你好").strip() or "你好"}],
        "stream": stream_mode,
    }
    try:
        if stream_mode:
            stream_result = _http_post_stream_probe(chat_url, payload, headers, timeout_value)
            ok = int(stream_result["status_code"]) < 400
            return {
                "ok": ok,
                "kind": "llm_stream",
                "availability": "可用" if ok else "不可用",
                "status_code": stream_result["status_code"],
                "latency_ms": round(float(stream_result["latency_ms"]), 1),
                "ttfb_ms": None if stream_result["ttfb_ms"] is None else round(float(stream_result["ttfb_ms"]), 1),
                "ttft_ms": None if stream_result["ttft_ms"] is None else round(float(stream_result["ttft_ms"]), 1),
                "response_text": stream_result["response_text"],
                "chat_url": chat_url,
                "message": "流式拨测完成" if ok else "流式拨测失败",
            }
        status_code, raw, latency_ms = _http_post_json(chat_url, payload, headers, timeout_value)
        ok = status_code < 400
        resp_text = raw.decode("utf-8", errors="ignore")
        short_text = ""
        try:
            parsed = json.loads(resp_text)
            choice = (parsed.get("choices") or [{}])[0] if isinstance(parsed, dict) else {}
            message = choice.get("message") if isinstance(choice, dict) else {}
            short_text = str((message or {}).get("content") or choice.get("text") or "")[:2000]
        except Exception:
            short_text = resp_text[:2000]
        return {
            "ok": ok,
            "kind": "llm_standard",
            "availability": "可用" if ok else "不可用",
            "status_code": status_code,
            "latency_ms": round(latency_ms, 1),
            "response_text": short_text,
            "chat_url": chat_url,
            "message": "标准拨测完成" if ok else "标准拨测失败",
        }
    except Exception as exc:  # pragma: no cover - network dependent
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测异常: {exc}"}


@app.post("/api/probe/mcp")
def api_probe_mcp(
    endpoint: str = Form(...),
    operation: str = Form(default="initialize"),
    timeout_sec: float = Form(default=10.0),
    api_key: str = Form(default=""),
    custom_method: str = Form(default=""),
):
    op_map = {
        "initialize": ("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ai-gateway-demo", "version": "1.0"}}),
        "tools_list": ("tools/list", {}),
        "resources_list": ("resources/list", {}),
        "prompts_list": ("prompts/list", {}),
    }
    if operation == "custom":
        method = (custom_method or "").strip()
        params = {}
    else:
        method, params = op_map.get(operation, op_map["initialize"])
    if not method:
        return {"ok": False, "availability": "不可用", "message": "自定义方法不能为空"}
    payload = {"jsonrpc": "2.0", "id": "probe-1", "method": method, "params": params}
    headers = {"Content-Type": "application/json"}
    if api_key.strip():
        headers["Authorization"] = f"Bearer {api_key.strip()}"
    timeout_value = max(1.0, min(float(timeout_sec), 60.0))
    try:
        status_code, raw, latency_ms = _http_post_json(endpoint, payload, headers, timeout_value)
        text = raw.decode("utf-8", errors="ignore")
        body = json.loads(text) if text.strip().startswith("{") else {"raw": text[:2000]}
        ok = status_code < 400 and "error" not in body
        return {
            "ok": ok,
            "availability": "可用" if ok else "不可用",
            "status_code": status_code,
            "latency_ms": round(latency_ms, 1),
            "operation": operation,
            "method": method,
            "result_preview": json.dumps(body.get("result", body.get("error", body)), ensure_ascii=False)[:2000],
            "message": "MCP拨测完成" if ok else "MCP拨测失败",
        }
    except Exception as exc:  # pragma: no cover - network dependent
        return {"ok": False, "availability": "不可用", "operation": operation, "method": method, "message": f"MCP拨测异常: {exc}"}
