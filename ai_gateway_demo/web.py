from __future__ import annotations

import os
import socket
import subprocess
import shlex
import json
import ssl
import time
import http.client
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .capture import OnlineCaptureManager
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
capture_manager = OnlineCaptureManager()


@dataclass
class ProbeTask:
    id: int
    params: dict[str, Any]
    interval_sec: int
    last_message: str = "-"
    last_ok: bool | None = None
    last_latency_ms: float | None = None
    running: bool = False
    thread: threading.Thread | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)


@dataclass
class FollowProbeTask:
    id: int
    category_minor: str
    params: dict[str, Any]
    last_triggered_entry_id: int = 0
    last_message: str = "-"
    enabled: bool = True


_probe_lock = threading.Lock()
_probe_tasks: dict[int, ProbeTask] = {}
_probe_records: list[dict[str, Any]] = []
_next_probe_task_id = 1
_follow_probe_tasks: dict[int, FollowProbeTask] = {}
_next_follow_probe_task_id = 1
DEFAULT_HEALTH_CFG = {"ttft_alert": 3500.0, "tpot_alert": 180.0}


def _probe_task_view(task: ProbeTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "task_name": f"任务{task.id}",
        "target": task.params.get("target", ""),
        "model": task.params.get("model", ""),
        "mode": task.params.get("mode", "standard"),
        "interval_sec": task.interval_sec,
        "running": task.running,
        "thread_alive": bool(task.thread and task.thread.is_alive() and not task.stop_event.is_set()),
        "last_message": task.last_message,
        "last_ok": task.last_ok,
        "last_latency_ms": task.last_latency_ms,
    }


def _add_probe_record(record: dict[str, Any]) -> None:
    with _probe_lock:
        _probe_records.insert(0, record)
        del _probe_records[200:]


def _probe_now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _is_red_entry(entry: dict[str, Any]) -> bool:
    return float(entry.get("ttft_ms") or 0.0) >= DEFAULT_HEALTH_CFG["ttft_alert"] or float(entry.get("tpot_ms_per_token") or 0.0) >= DEFAULT_HEALTH_CFG["tpot_alert"]


def _maybe_trigger_follow_for_entry(entry: dict[str, Any]) -> None:
    if not _is_red_entry(entry):
        return
    entry_id = int(entry.get("id") or 0)
    minor = str(entry.get("category_minor") or "").strip()
    if entry_id <= 0 or not minor:
        return
    with _probe_lock:
        tasks = [t for t in _follow_probe_tasks.values() if t.enabled and t.category_minor == minor and entry_id > t.last_triggered_entry_id]
    for task in tasks:
        params = dict(task.params)
        result = _run_llm_probe(
            params.get("target", ""),
            params.get("api_key", ""),
            params.get("model", "gpt-4o-mini"),
            params.get("question", "你好"),
            params.get("mode", "standard"),
            float(params.get("timeout_sec") or 20.0),
        )
        _add_probe_record(
            {
                "time": _probe_now_text(),
                "task_id": task.id,
                "task_name": f"随流任务{task.id}",
                "trigger": f"随流({minor})#{entry_id}",
                "target": params.get("target", ""),
                "model": params.get("model", ""),
                "mode": params.get("mode", "standard"),
                "ok": bool(result.get("ok")),
                "status_code": result.get("status_code"),
                "latency_ms": result.get("latency_ms"),
                "ttfb_ms": result.get("ttfb_ms"),
                "ttft_ms": result.get("ttft_ms"),
                "message": result.get("message") or "",
            }
        )
        with _probe_lock:
            live = _follow_probe_tasks.get(task.id)
            if live:
                live.last_triggered_entry_id = max(live.last_triggered_entry_id, entry_id)
                live.last_message = str(result.get("message") or "-")


@app.on_event("startup")
def startup_online_capture() -> None:
    interface = os.getenv("AI_GATEWAY_LISTEN_INTERFACE", "").strip()
    if not interface:
        return
    interval = int(os.getenv("AI_GATEWAY_LISTEN_INTERVAL", "60") or "60")
    bpf_filter = os.getenv("AI_GATEWAY_LISTEN_FILTER", "tcp")
    idle_timeout = int(os.getenv("AI_GATEWAY_LISTEN_IDLE_TIMEOUT", "120") or "120")
    max_flow_duration = int(os.getenv("AI_GATEWAY_LISTEN_MAX_FLOW_DURATION", "300") or "300")
    pcap_retention = int(os.getenv("AI_GATEWAY_LISTEN_PCAP_RETENTION", "0") or "0")
    try:
        capture_manager.start(
            interface=interface,
            interval_sec=interval,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout,
            max_flow_duration_sec=max_flow_duration,
            pcap_retention_sec=pcap_retention,
        )
    except Exception:
        # Keep the web app available even if the host lacks tcpdump/capture permissions.
        pass


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
    inserted = 0
    for e in entries:
        if insert_entry(e):
            inserted += 1
            latest = list_entries(start_real=e.get("start_time_real"), end_real=e.get("start_time_real"))
            if latest:
                _maybe_trigger_follow_for_entry(latest[0])

    return {"inserted": inserted, "detected": len(entries)}


@app.post("/api/clear")
def api_clear():
    clear_entries()
    return {"ok": True}


@app.get("/api/capture/status")
def api_capture_status():
    return capture_manager.status()


@app.post("/api/capture/start")
def api_capture_start(
    interface: str = Form(...),
    interval_sec: int = Form(default=60),
    bpf_filter: str = Form(default="tcp"),
    idle_timeout_sec: int = Form(default=120),
    max_flow_duration_sec: int = Form(default=300),
    pcap_retention_sec: int = Form(default=0),
):
    try:
        status = capture_manager.start(
            interface=interface,
            interval_sec=interval_sec,
            bpf_filter=bpf_filter,
            idle_timeout_sec=idle_timeout_sec,
            max_flow_duration_sec=max_flow_duration_sec,
            pcap_retention_sec=pcap_retention_sec,
        )
        return {"ok": True, **status}
    except Exception as exc:
        return {**capture_manager.status(), "ok": False, "message": str(exc)}


@app.post("/api/capture/stop")
def api_capture_stop():
    return {"ok": True, **capture_manager.stop()}


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


def _build_llm_probe_curl(chat_url: str, api_key: str, payload: dict[str, Any]) -> str:
    headers = ['-H "Content-Type: application/json"']
    if api_key.strip():
        headers.append(f'-H "Authorization: Bearer {api_key.strip()}"')
    payload_text = json.dumps(payload, ensure_ascii=False, indent=2)
    return "\n".join([f"curl {chat_url} \\", *[f"  {h} \\" for h in headers], f"  -d '{payload_text}'"])


def _run_curl_command_with_metrics(curl_command: str, timeout_sec: float, stream_mode: bool) -> dict[str, Any]:
    try:
        cmd = shlex.split(curl_command)
    except Exception:
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": "拨测异常: curl命令解析失败"}
    if not cmd or cmd[0] != "curl":
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": "拨测异常: 命令必须以curl开头"}
    t0 = time.perf_counter()
    timeout_value = max(2.0, min(float(timeout_sec), 90.0))
    if stream_mode:
        if "-N" not in cmd:
            cmd.insert(1, "-N")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        collected: list[str] = []
        ttfb_ms: float | None = None
        ttft_ms: float | None = None
        while True:
            if time.perf_counter() - t0 > timeout_value + 5.0:
                proc.kill()
                return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测超时({timeout_value:.0f}s)", "command": " ".join(shlex.quote(part) for part in cmd)}
            line = proc.stdout.readline() if proc.stdout else ""
            if not line:
                if proc.poll() is not None:
                    break
                continue
            now_ms = (time.perf_counter() - t0) * 1000
            if ttfb_ms is None:
                ttfb_ms = now_ms
            text = line.strip()
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
            if isinstance(delta, dict) and delta.get("content"):
                if ttft_ms is None:
                    ttft_ms = now_ms
                collected.append(str(delta.get("content")))
        stderr = (proc.stderr.read() if proc.stderr else "").strip()
        rc = proc.wait(timeout=1)
        if rc != 0:
            return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测异常: {stderr or 'curl失败'}", "command": " ".join(shlex.quote(part) for part in cmd)}
        latency_ms = (time.perf_counter() - t0) * 1000
        return {"ok": True, "kind": "llm_stream", "availability": "可用", "status_code": 200, "latency_ms": round(latency_ms, 1), "ttfb_ms": None if ttfb_ms is None else round(ttfb_ms, 1), "ttft_ms": None if ttft_ms is None else round(ttft_ms, 1), "response_text": "".join(collected)[:2000], "message": "流式拨测完成", "command": " ".join(shlex.quote(part) for part in cmd)}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_value + 5.0)
    except subprocess.TimeoutExpired:
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测超时({timeout_value:.0f}s)", "command": " ".join(shlex.quote(part) for part in cmd)}
    latency_ms = (time.perf_counter() - t0) * 1000
    if proc.returncode != 0:
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测异常: {proc.stderr.strip() or proc.stdout.strip() or 'curl失败'}", "command": " ".join(shlex.quote(part) for part in cmd)}
    out = proc.stdout or ""
    try:
        parsed = json.loads(out)
    except Exception:
        return {"ok": False, "kind": "llm_standard", "availability": "不可用", "status_code": None, "latency_ms": round(latency_ms, 1), "response_text": out[:2000], "message": "标准拨测失败", "command": " ".join(shlex.quote(part) for part in cmd)}
    choice = (parsed.get("choices") or [{}])[0] if isinstance(parsed, dict) else {}
    message = choice.get("message") if isinstance(choice, dict) else {}
    short_text = str((message or {}).get("content") or choice.get("text") or "")[:2000]
    return {"ok": True, "kind": "llm_standard", "availability": "可用", "status_code": 200, "latency_ms": round(latency_ms, 1), "response_text": short_text, "message": "标准拨测完成", "command": " ".join(shlex.quote(part) for part in cmd)}




def _run_llm_probe_via_curl(chat_url: str, api_key: str, payload: dict[str, Any], timeout_sec: float, stream_mode: bool) -> dict[str, Any]:
    headers = ["-H", "Content-Type: application/json"]
    if api_key.strip():
        headers += ["-H", f"Authorization: Bearer {api_key.strip()}"]
    body = json.dumps(payload, ensure_ascii=False)
    cmd = [
        "curl", "-sS", "--http1.1", "-X", "POST",
        chat_url,
        *headers,
        "--data-raw", body,
    ]
    if stream_mode:
        cmd.insert(1, "-N")
    t0 = time.perf_counter()
    timeout_value = max(2.0, min(float(timeout_sec), 90.0))
    if stream_mode:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as exc:
            return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测异常: {exc}", "command": " ".join(shlex.quote(part) for part in cmd)}
        collected: list[str] = []
        ttfb_ms: float | None = None
        ttft_ms: float | None = None
        try:
            while True:
                if time.perf_counter() - t0 > timeout_value + 5.0:
                    proc.kill()
                    return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测超时({timeout_value:.0f}s)", "command": " ".join(shlex.quote(part) for part in cmd)}
                line = proc.stdout.readline() if proc.stdout else ""
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                now_ms = (time.perf_counter() - t0) * 1000
                if ttfb_ms is None:
                    ttfb_ms = now_ms
                text = line.strip()
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
                if isinstance(delta, dict) and delta.get("content"):
                    if ttft_ms is None:
                        ttft_ms = now_ms
                    collected.append(str(delta.get("content")))
            stderr = (proc.stderr.read() if proc.stderr else "").strip()
            rc = proc.wait(timeout=1)
            if rc != 0:
                return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测异常: {stderr or 'curl失败'}", "command": " ".join(shlex.quote(part) for part in cmd)}
        finally:
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        latency_ms = (time.perf_counter() - t0) * 1000
        return {
            "ok": True,
            "kind": "llm_stream",
            "availability": "可用",
            "status_code": 200,
            "latency_ms": round(latency_ms, 1),
            "ttfb_ms": None if ttfb_ms is None else round(ttfb_ms, 1),
            "ttft_ms": None if ttft_ms is None else round(ttft_ms, 1),
            "response_text": "".join(collected)[:2000],
            "chat_url": chat_url,
            "message": "流式拨测完成",
            "command": " ".join(shlex.quote(part) for part in cmd),
        }

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout_value + 5.0)
    except subprocess.TimeoutExpired:
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测超时({timeout_value:.0f}s)", "command": " ".join(shlex.quote(part) for part in cmd)}
    latency_ms = (time.perf_counter() - t0) * 1000
    if proc.returncode != 0:
        return {"ok": False, "kind": "llm", "availability": "不可用", "message": f"拨测异常: {proc.stderr.strip() or proc.stdout.strip() or 'curl失败'}", "command": " ".join(shlex.quote(part) for part in cmd)}
    out = proc.stdout or ""

    try:
        parsed = json.loads(out)
    except Exception:
        return {"ok": False, "kind": "llm_standard", "availability": "不可用", "status_code": None, "latency_ms": round(latency_ms, 1), "response_text": out[:2000], "chat_url": chat_url, "message": "标准拨测失败", "command": " ".join(shlex.quote(part) for part in cmd)}
    choice = (parsed.get("choices") or [{}])[0] if isinstance(parsed, dict) else {}
    message = choice.get("message") if isinstance(choice, dict) else {}
    short_text = str((message or {}).get("content") or choice.get("text") or "")[:2000]
    if isinstance(parsed, dict) and parsed.get("error"):
        return {"ok": False, "kind": "llm_standard", "availability": "不可用", "status_code": None, "latency_ms": round(latency_ms, 1), "response_text": short_text, "chat_url": chat_url, "message": f"标准拨测失败: {parsed.get('error')}", "command": " ".join(shlex.quote(part) for part in cmd)}
    return {"ok": True, "kind": "llm_standard", "availability": "可用", "status_code": 200, "latency_ms": round(latency_ms, 1), "response_text": short_text, "chat_url": chat_url, "message": "标准拨测完成", "command": " ".join(shlex.quote(part) for part in cmd)}
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
            try:
                line = resp.fp.readline(65536)
            except (TimeoutError, socket.timeout):
                if collected or ttfb_ms is not None:
                    break
                raise
            if not line:
                break
            now_ms = (time.perf_counter() - t0) * 1000
            if ttfb_ms is None:
                ttfb_ms = now_ms
            text = line.decode("utf-8", errors="ignore").strip()
            if not text.startswith("data:"):
                continue
            payload_text = text[5:].strip()
            if not payload_text:
                continue
            if payload_text == "[DONE]":
                break
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


def _run_llm_probe(
    target: str,
    api_key: str = "",
    model: str = "gpt-4o-mini",
    question: str = "你好",
    mode: str = "standard",
    timeout_sec: float = 20.0,
    *_: Any,
) -> dict[str, Any]:
    chat_url = _to_chat_completions_url(target)
    timeout_value = max(2.0, min(float(timeout_sec), 90.0))
    stream_mode = mode == "stream"
    payload: dict[str, Any] = {
        "model": (model or "gpt-4o-mini").strip() or "gpt-4o-mini",
        "messages": [{"role": "user", "content": (question or "你好").strip() or "你好"}],
        "stream": stream_mode,
    }
    return _run_llm_probe_via_curl(chat_url, api_key, payload, timeout_value, stream_mode)


@app.post("/api/probe/llm")
def api_probe_llm(
    target: str = Form(...),
    api_key: str = Form(default=""),
    model: str = Form(default="gpt-4o-mini"),
    question: str = Form(default="你好"),
    mode: str = Form(default="standard"),
    timeout_sec: float = Form(default=20.0),
    final_curl: str = Form(default=""),
    trigger: str = Form(default=""),
    raw_curl: str = Form(default=""),
    passthrough: str = Form(default=""),
):
    payload = {
        "model": (model or "gpt-4o-mini").strip() or "gpt-4o-mini",
        "messages": [{"role": "user", "content": (question or "你好").strip() or "你好"}],
        "stream": (mode or "standard").strip() == "stream",
    }
    rendered_curl = (final_curl or "").strip() or _build_llm_probe_curl(_to_chat_completions_url(target), api_key, payload)
    result = _run_curl_command_with_metrics(rendered_curl, timeout_sec, payload["stream"])
    result["chat_url"] = _to_chat_completions_url(target)
    result["final_curl"] = rendered_curl
    if trigger:
        _add_probe_record(
            {
                "time": _probe_now_text(),
                "task_id": None,
                "task_name": "单次",
                "trigger": trigger,
                "target": (target or "").strip(),
                "model": (model or "").strip(),
                "mode": (mode or "standard").strip() or "standard",
                "ok": bool(result.get("ok")),
                "status_code": result.get("status_code"),
                "latency_ms": result.get("latency_ms"),
                "ttfb_ms": result.get("ttfb_ms"),
                "ttft_ms": result.get("ttft_ms"),
                "message": result.get("message") or "",
            }
        )
    return result


@app.get("/api/probe/follow-tasks")
def api_probe_follow_tasks():
    with _probe_lock:
        items = [dict(id=t.id, category_minor=t.category_minor, **t.params, enabled=t.enabled, thread_alive=t.enabled, last_triggered_entry_id=t.last_triggered_entry_id, last_message=t.last_message) for t in sorted(_follow_probe_tasks.values(), key=lambda x: x.id)]
    return {"items": items}


@app.post("/api/probe/follow-tasks")
def api_probe_follow_task_add(
    category_minor: str = Form(...),
    target: str = Form(...),
    api_key: str = Form(default=""),
    model: str = Form(default="gpt-4o-mini"),
    question: str = Form(default="你好"),
    mode: str = Form(default="standard"),
    timeout_sec: float = Form(default=20.0),
):
    global _next_follow_probe_task_id
    with _probe_lock:
        task = FollowProbeTask(
            id=_next_follow_probe_task_id,
            category_minor=(category_minor or "").strip(),
            params={"target": target.strip(), "api_key": api_key.strip(), "model": model.strip() or "gpt-4o-mini", "question": question.strip() or "你好", "mode": mode.strip() or "standard", "timeout_sec": str(max(2.0, min(float(timeout_sec), 90.0)))},
        )
        _next_follow_probe_task_id += 1
        _follow_probe_tasks[task.id] = task
    return {"ok": True, "task_id": task.id}


@app.post("/api/probe/follow-tasks/clear")
def api_probe_follow_tasks_clear():
    global _next_follow_probe_task_id
    with _probe_lock:
        _follow_probe_tasks.clear()
        _next_follow_probe_task_id = 1
    return {"ok": True}


@app.post("/api/probe/follow-tasks/{task_id}/triggered")
def api_probe_follow_task_triggered(task_id: int, entry_id: int = Form(...), message: str = Form(default="")):
    with _probe_lock:
        task = _follow_probe_tasks.get(task_id)
        if not task:
            return {"ok": False, "message": "任务不存在"}
        task.last_triggered_entry_id = max(task.last_triggered_entry_id, int(entry_id or 0))
        if message:
            task.last_message = message
    return {"ok": True}


@app.post("/api/probe/follow-tasks/{task_id}/stop")
def api_probe_follow_task_stop(task_id: int):
    with _probe_lock:
        task = _follow_probe_tasks.get(task_id)
        if not task:
            return {"ok": False, "message": "任务不存在"}
        task.enabled = False
    return {"ok": True}


@app.post("/api/probe/follow-tasks/{task_id}/start")
def api_probe_follow_task_start(task_id: int):
    with _probe_lock:
        task = _follow_probe_tasks.get(task_id)
        if not task:
            return {"ok": False, "message": "任务不存在"}
        task.enabled = True
    return {"ok": True}


@app.delete("/api/probe/follow-tasks/{task_id}")
def api_probe_follow_task_delete(task_id: int):
    with _probe_lock:
        if task_id not in _follow_probe_tasks:
            return {"ok": False, "message": "任务不存在"}
        del _follow_probe_tasks[task_id]
    return {"ok": True}




def _run_llm_probe_with_deadline(params: dict[str, Any], deadline_sec: float) -> dict[str, Any]:
    result_holder: dict[str, Any] = {}

    def _target() -> None:
        result_holder["result"] = _run_llm_probe(
            params.get("target", ""),
            params.get("api_key", ""),
            params.get("model", "gpt-4o-mini"),
            params.get("question", "你好"),
            params.get("mode", "standard"),
            float(params.get("timeout_sec") or deadline_sec),
            params.get("system_prompt", ""),
            params.get("reasoning_effort", ""),
            params.get("thinking_type", ""),
        )

    t0 = time.perf_counter()
    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout=max(1.0, deadline_sec + 0.5))
    if worker.is_alive():
        return {
            "ok": False,
            "availability": "不可用",
            "message": f"拨测超时({deadline_sec:.0f}s)",
            "status_code": None,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
        }
    return result_holder.get("result") or {"ok": False, "availability": "不可用", "message": "拨测失败"}
def _run_probe_task_once(task_id: int, trigger: str = "周期") -> None:
    started_at = _probe_now_text()
    with _probe_lock:
        task = _probe_tasks.get(task_id)
        if not task:
            return
        if task.running:
            return
        params = dict(task.params)
        task.running = True
        task.last_message = "拨测中..."

    timeout_value = max(2.0, min(float(params.get("timeout_sec") or 20.0), 90.0))
    result = _run_llm_probe_with_deadline(params, timeout_value)
    record = {
        "time": started_at,
        "task_id": task_id,
        "task_name": f"任务{task_id}",
        "trigger": trigger,
        "target": params.get("target", ""),
        "model": params.get("model", ""),
        "mode": params.get("mode", "standard"),
        "ok": bool(result.get("ok")),
        "status_code": result.get("status_code"),
        "latency_ms": result.get("latency_ms"),
        "ttfb_ms": result.get("ttfb_ms"),
        "ttft_ms": result.get("ttft_ms"),
        "message": result.get("message") or "",
    }
    with _probe_lock:
        task = _probe_tasks.get(task_id)
        if not task or task.stop_event.is_set():
            return
    _add_probe_record(record)
    with _probe_lock:
        task = _probe_tasks.get(task_id)
        if not task:
            return
        task.running = False
        task.last_ok = bool(result.get("ok"))
        latency_ms = result.get("latency_ms")
        task.last_latency_ms = latency_ms if isinstance(latency_ms, (int, float)) else None
        if task.last_ok and task.last_latency_ms is not None:
            task.last_message = f"成功 {task.last_latency_ms:.1f}ms"
        else:
            task.last_message = str(result.get("message") or "失败")


def _probe_task_loop(task_id: int) -> None:
    next_fire = time.monotonic()
    while True:
        with _probe_lock:
            task = _probe_tasks.get(task_id)
            if not task or task.stop_event.is_set():
                return
            interval_sec = max(5, int(task.interval_sec or 60))
            stop_event = task.stop_event
        now = time.monotonic()
        if now < next_fire and stop_event.wait(next_fire - now):
            return
        threading.Thread(target=_run_probe_task_once, args=(task_id,), daemon=True).start()
        next_fire += interval_sec
        if next_fire < time.monotonic():
            next_fire = time.monotonic() + interval_sec


def _start_probe_task_locked(task: ProbeTask) -> None:
    if task.thread and task.thread.is_alive():
        return
    task.stop_event.clear()
    task.thread = threading.Thread(target=_probe_task_loop, args=(task.id,), daemon=True)
    task.thread.start()


def _stop_probe_task(task: ProbeTask) -> None:
    task.stop_event.set()
    task.running = False


@app.get("/api/probe/tasks")
def api_probe_tasks():
    with _probe_lock:
        tasks = [_probe_task_view(task) for task in sorted(_probe_tasks.values(), key=lambda item: item.id)]
        follow_tasks = [dict(id=t.id, category_minor=t.category_minor, **t.params, enabled=t.enabled, thread_alive=t.enabled, last_triggered_entry_id=t.last_triggered_entry_id, last_message=t.last_message) for t in sorted(_follow_probe_tasks.values(), key=lambda x: x.id)]
        records = list(_probe_records)
    return {"items": tasks, "follow_items": follow_tasks, "records": records}


@app.post("/api/probe/tasks")
def api_probe_task_add(
    target: str = Form(...),
    api_key: str = Form(default=""),
    model: str = Form(default="gpt-4o-mini"),
    question: str = Form(default="你好"),
    mode: str = Form(default="standard"),
    timeout_sec: float = Form(default=20.0),
    schedule_interval_sec: int = Form(default=60),
):
    global _next_probe_task_id
    params = {
        "target": (target or "").strip(),
        "api_key": (api_key or "").strip(),
        "model": (model or "gpt-4o-mini").strip() or "gpt-4o-mini",
        "question": (question or "你好").strip() or "你好",
        "mode": (mode or "standard").strip() or "standard",
        "timeout_sec": str(max(2.0, min(float(timeout_sec), 90.0))),
    }
    interval_sec = max(5, min(int(schedule_interval_sec or 60), 86400))
    with _probe_lock:
        task = ProbeTask(id=_next_probe_task_id, params=params, interval_sec=interval_sec)
        _next_probe_task_id += 1
        _probe_tasks[task.id] = task
        _start_probe_task_locked(task)
        view = _probe_task_view(task)
    return {"ok": True, "task": view}


@app.post("/api/probe/tasks/{task_id}/start")
def api_probe_task_start(task_id: int):
    with _probe_lock:
        task = _probe_tasks.get(task_id)
        if not task:
            return {"ok": False, "message": "任务不存在"}
        _start_probe_task_locked(task)
        view = _probe_task_view(task)
    return {"ok": True, "task": view}


@app.post("/api/probe/tasks/{task_id}/stop")
def api_probe_task_stop(task_id: int):
    with _probe_lock:
        task = _probe_tasks.get(task_id)
        if not task:
            return {"ok": False, "message": "任务不存在"}
        _stop_probe_task(task)
        view = _probe_task_view(task)
    return {"ok": True, "task": view}


@app.delete("/api/probe/tasks/{task_id}")
def api_probe_task_delete(task_id: int):
    with _probe_lock:
        task = _probe_tasks.pop(task_id, None)
        if not task:
            return {"ok": False, "message": "任务不存在"}
        _stop_probe_task(task)
    return {"ok": True}


@app.post("/api/probe/tasks/clear")
def api_probe_tasks_clear():
    global _next_probe_task_id
    with _probe_lock:
        for task in _probe_tasks.values():
            _stop_probe_task(task)
        _probe_tasks.clear()
        _next_probe_task_id = 1
    return {"ok": True}


@app.get("/api/probe/records")
def api_probe_records():
    with _probe_lock:
        return {"items": list(_probe_records)}


@app.post("/api/probe/records/clear")
def api_probe_records_clear():
    global _next_probe_task_id
    with _probe_lock:
        _probe_records.clear()
        if not _probe_tasks:
            _next_probe_task_id = 1
    return {"ok": True, "next_task_id": _next_probe_task_id}
