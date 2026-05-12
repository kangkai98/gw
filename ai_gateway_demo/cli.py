from __future__ import annotations

import argparse
import os

import uvicorn

from .db import init_db


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI 网关 demo：启动网页服务并在页面上传 pcap")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--listen-interface", default="", help="启动后自动在线监听的网卡名，如 eth0/en0")
    parser.add_argument("--listen-interval", type=int, default=60, help="在线监听分析周期（秒），默认 60 秒")
    parser.add_argument("--listen-filter", default="tcp", help="BPF 过滤表达式，默认 tcp")
    parser.add_argument("--listen-idle-timeout", type=int, default=300, help="流 idle timeout（秒），默认 300 秒")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    init_db()
    if args.listen_interface:
        os.environ["AI_GATEWAY_LISTEN_INTERFACE"] = args.listen_interface
        os.environ["AI_GATEWAY_LISTEN_INTERVAL"] = str(args.listen_interval)
        os.environ["AI_GATEWAY_LISTEN_FILTER"] = args.listen_filter
        os.environ["AI_GATEWAY_LISTEN_IDLE_TIMEOUT"] = str(args.listen_idle_timeout)
    uvicorn.run("ai_gateway_demo.web:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
