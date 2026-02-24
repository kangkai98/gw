from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("ai_gateway_demo.db")

ENTRY_COLUMNS = {
    "id",
    "source_major",
    "source_minor",
    "flow_key",
    "start_time_s",
    "start_time_dt",
    "end_time_dt",
    "ttfb_ms",
    "ttft_ms",
    "latency_ms",
    "tpot_ms_per_token",
    "input_tokens",
    "output_tokens",
    "created_at",
}


def get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _create_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_major TEXT NOT NULL,
            source_minor TEXT NOT NULL,
            flow_key TEXT NOT NULL,
            start_time_s REAL NOT NULL,
            start_time_dt TEXT NOT NULL,
            end_time_dt TEXT,
            ttfb_ms REAL,
            ttft_ms REAL,
            latency_ms REAL,
            tpot_ms_per_token REAL,
            input_tokens INTEGER NOT NULL,
            output_tokens INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS self_hosted_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='entries'"
        ).fetchone()
        if exists:
            cols = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(entries)").fetchall()
            }
            if not ENTRY_COLUMNS.issubset(cols):
                conn.execute("DROP TABLE entries")
        _create_tables(conn)
        conn.commit()
    finally:
        conn.close()


def insert_entries(entries: list[dict[str, Any]], db_path: Path = DB_PATH) -> None:
    if not entries:
        return
    conn = get_conn(db_path)
    try:
        conn.executemany(
            """
            INSERT INTO entries (
                source_major, source_minor, flow_key, start_time_s, start_time_dt,
                end_time_dt, ttfb_ms, ttft_ms, latency_ms, tpot_ms_per_token,
                input_tokens, output_tokens
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    e["source_major"],
                    e["source_minor"],
                    e["flow_key"],
                    e["start_time_s"],
                    e["start_time_dt"],
                    e["end_time_dt"],
                    e["ttfb_ms"],
                    e["ttft_ms"],
                    e["latency_ms"],
                    e["tpot_ms_per_token"],
                    e["input_tokens"],
                    e["output_tokens"],
                )
                for e in entries
            ],
        )
        conn.commit()
    finally:
        conn.close()


def clear_entries(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute("DELETE FROM entries")
        conn.commit()
    finally:
        conn.close()


def list_entries(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    conn = get_conn(db_path)
    try:
        rows = conn.execute("SELECT * FROM entries ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_self_hosted_configs(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    conn = get_conn(db_path)
    try:
        rows = conn.execute(
            "SELECT id, ip, label, created_at FROM self_hosted_configs ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def upsert_self_hosted_config(ip: str, label: str, db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO self_hosted_configs (ip, label)
            VALUES (?, ?)
            ON CONFLICT(ip) DO UPDATE SET label=excluded.label
            """,
            (ip.strip(), label.strip()),
        )
        conn.commit()
    finally:
        conn.close()


def delete_self_hosted_config(config_id: int, db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute("DELETE FROM self_hosted_configs WHERE id=?", (config_id,))
        conn.commit()
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
                MIN(start_time_s) AS min_start,
                MAX(start_time_s + COALESCE(latency_ms, 0)/1000.0) AS max_end
            FROM entries
            """
        ).fetchone()
        by_major = conn.execute(
            """
            SELECT
                source_major,
                COUNT(*) AS total_entries,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                AVG(ttfb_ms) AS avg_ttfb_ms,
                AVG(ttft_ms) AS avg_ttft_ms,
                AVG(latency_ms) AS avg_latency_ms
            FROM entries
            GROUP BY source_major
            ORDER BY total_entries DESC
            """
        ).fetchall()

        min_start = totals["min_start"]
        max_end = totals["max_end"]
        duration_s = (max_end - min_start) if (min_start is not None and max_end is not None) else 0
        rps = (totals["total_entries"] / duration_s) if duration_s and duration_s > 0 else 0

        return {
            "total_entries": totals["total_entries"],
            "total_input_tokens": totals["total_input_tokens"],
            "total_output_tokens": totals["total_output_tokens"],
            "rps": round(rps, 2),
            "by_major": [dict(r) for r in by_major],
        }
    finally:
        conn.close()
