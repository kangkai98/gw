from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("ai_gateway_demo.db")


def get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                flow_key TEXT NOT NULL,
                start_time REAL NOT NULL,
                ttfb REAL,
                ttft REAL,
                latency REAL,
                tpot REAL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_entry(entry: dict[str, Any], db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO entries (
                source, flow_key, start_time, ttfb, ttft,
                latency, tpot, input_tokens, output_tokens
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["source"],
                entry["flow_key"],
                entry["start_time"],
                entry["ttfb"],
                entry["ttft"],
                entry["latency"],
                entry["tpot"],
                entry["input_tokens"],
                entry["output_tokens"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_entries(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    conn = get_conn(db_path)
    try:
        rows = conn.execute("SELECT * FROM entries ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_stats(db_path: Path = DB_PATH) -> dict[str, Any]:
    conn = get_conn(db_path)
    try:
        totals = conn.execute(
            """
            SELECT
                COUNT(*) AS total_entries,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                MIN(start_time) AS min_start,
                MAX(start_time + COALESCE(latency, 0)) AS max_end
            FROM entries
            """
        ).fetchone()
        source_stats_rows = conn.execute(
            """
            SELECT
                source,
                COUNT(*) AS total_entries,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                AVG(ttfb) AS avg_ttfb,
                AVG(ttft) AS avg_ttft,
                AVG(latency) AS avg_latency
            FROM entries
            GROUP BY source
            ORDER BY total_entries DESC
            """
        ).fetchall()

        min_start = totals["min_start"]
        max_end = totals["max_end"]
        duration = (max_end - min_start) if (min_start is not None and max_end is not None) else 0
        rps = (totals["total_entries"] / duration) if duration and duration > 0 else 0

        return {
            "total_entries": totals["total_entries"],
            "total_input_tokens": totals["total_input_tokens"],
            "total_output_tokens": totals["total_output_tokens"],
            "rps": round(rps, 4),
            "source_stats": [dict(row) for row in source_stats_rows],
        }
    finally:
        conn.close()
