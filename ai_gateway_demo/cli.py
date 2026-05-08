from __future__ import annotations

import argparse

import uvicorn

from .db import init_db


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI 网关 demo：启动网页服务并在页面上传 pcap")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    init_db()
    uvicorn.run("ai_gateway_demo.web:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
