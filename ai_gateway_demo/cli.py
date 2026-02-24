from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from .db import init_db, insert_entry
from .parser import parse_pcap_to_entries


def run_all_in_one(args: argparse.Namespace) -> None:
    init_db()
    entries = parse_pcap_to_entries(
        pcap_path=Path(args.pcap),
        source=args.source,
        gap_threshold=args.gap,
        ai_ip=args.ai_ip,
    )
    for entry in entries:
        insert_entry(entry)
    print(f"Inserted {len(entries)} entries into ai_gateway_demo.db")
    uvicorn.run("ai_gateway_demo.web:app", host=args.host, port=args.port, reload=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI 网关 demo：导入 pcap 到数据库并直接启动可视化服务"
    )
    parser.add_argument("--pcap", required=True, help="pcap 文件路径")
    parser.add_argument("--source", default=None, help="AI 来源（可选，不填自动识别）")
    parser.add_argument("--ai-ip", default=None, help="AI 服务器 IP（可选，不填自动识别）")
    parser.add_argument("--gap", type=float, default=2.0, help="问答切分阈值（秒）")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    run_all_in_one(args)


if __name__ == "__main__":
    main()
