from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("ai_gateway_demo.db")

ENTRY_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "category_major": "TEXT NOT NULL",
    "category_minor": "TEXT NOT NULL",
    "flow_key": "TEXT NOT NULL",
    "start_time_real": "TEXT NOT NULL",
    "end_time_real": "TEXT NOT NULL",
    "start_time_rel_s": "REAL NOT NULL",
    "ttfb_ms": "REAL",
    "ttft_ms": "REAL",
    "latency_ms": "REAL",
    "tpot_ms_per_token": "REAL",
    "input_tokens": "INTEGER NOT NULL",
    "output_tokens": "INTEGER NOT NULL",
    "created_at": "DATETIME DEFAULT CURRENT_TIMESTAMP",
}


def get_conn(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _reset_autoincrement(conn: sqlite3.Connection, table: str) -> None:
    if _table_exists(conn, "sqlite_sequence"):
        conn.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))


def _ensure_entry_schema(conn: sqlite3.Connection) -> None:
    cols = conn.execute("PRAGMA table_info(entries)").fetchall()
    if not cols:
        fields = ",\n                ".join(f"{name} {ddl}" for name, ddl in ENTRY_COLUMNS.items())
        conn.execute(f"CREATE TABLE entries ({fields})")
        return

    existing = {row[1] for row in cols}
    for name, ddl in ENTRY_COLUMNS.items():
        if name not in existing and "PRIMARY KEY" not in ddl:
            conn.execute(f"ALTER TABLE entries ADD COLUMN {name} {ddl}")


def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        _ensure_entry_schema(conn)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS self_hosted_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                server_ip TEXT NOT NULL UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _is_valid_entry_for_store(entry: dict[str, Any]) -> bool:
    latency = entry.get("latency_ms")
    ttft = entry.get("ttft_ms")
    input_tokens = entry.get("input_tokens") or 0
    output_tokens = entry.get("output_tokens") or 0
    if latency is None or float(latency) <= 0:
        return False
    if ttft is None or float(ttft) <= 0:
        return False
    if int(input_tokens) <= 0 or int(output_tokens) <= 0:
        return False
    return True


def insert_entry(entry: dict[str, Any], db_path: Path = DB_PATH) -> None:
    if not _is_valid_entry_for_store(entry):
        return
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO entries (
                category_major, category_minor, flow_key,
                start_time_real, end_time_real, start_time_rel_s,
                ttfb_ms, ttft_ms, latency_ms, tpot_ms_per_token,
                input_tokens, output_tokens
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["category_major"],
                entry["category_minor"],
                entry["flow_key"],
                entry["start_time_real"],
                entry["end_time_real"],
                entry["start_time_rel_s"],
                entry["ttfb_ms"],
                entry["ttft_ms"],
                entry["latency_ms"],
                entry["tpot_ms_per_token"],
                entry["input_tokens"],
                entry["output_tokens"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def clear_entries(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute("DELETE FROM entries")
        _reset_autoincrement(conn, "entries")
        conn.commit()
    finally:
        conn.close()


def _build_filters(
    category_major: str | None = None,
    start_rel_s: float | None = None,
    end_rel_s: float | None = None,
    start_real: str | None = None,
    end_real: str | None = None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if category_major:
        clauses.append("category_major = ?")
        params.append(category_major)
    if start_rel_s is not None:
        clauses.append("start_time_rel_s >= ?")
        params.append(start_rel_s)
    if end_rel_s is not None:
        clauses.append("start_time_rel_s <= ?")
        params.append(end_rel_s)
    if start_real:
        clauses.append("start_time_real >= ?")
        params.append(start_real)
    if end_real:
        clauses.append("start_time_real <= ?")
        params.append(end_real)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def list_entries(
    category_major: str | None = None,
    start_rel_s: float | None = None,
    end_rel_s: float | None = None,
    start_real: str | None = None,
    end_real: str | None = None,
    db_path: Path = DB_PATH,
) -> list[dict[str, Any]]:
    conn = get_conn(db_path)
    try:
        where_sql, params = _build_filters(category_major, start_rel_s, end_rel_s, start_real, end_real)
        rows = conn.execute(f"SELECT * FROM entries{where_sql} ORDER BY id DESC", params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_stats(
    category_major: str | None = None,
    start_rel_s: float | None = None,
    end_rel_s: float | None = None,
    start_real: str | None = None,
    end_real: str | None = None,
    db_path: Path = DB_PATH,
) -> dict[str, Any]:
    conn = get_conn(db_path)
    try:
        where_sql, params = _build_filters(category_major, start_rel_s, end_rel_s, start_real, end_real)
        totals = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_entries,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                MIN(start_time_rel_s) AS min_start,
                MAX(start_time_rel_s + COALESCE(latency_ms, 0)/1000.0) AS max_end
            FROM entries
            {where_sql}
            """,
            params,
        ).fetchone()
        major_rows = conn.execute(
            f"""
            SELECT
                category_major,
                COUNT(*) AS total_entries,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                AVG(ttfb_ms) AS avg_ttfb_ms,
                AVG(ttft_ms) AS avg_ttft_ms,
                AVG(latency_ms) AS avg_latency_ms
            FROM entries
            {where_sql}
            GROUP BY category_major
            ORDER BY total_entries DESC
            """,
            params,
        ).fetchall()

        min_start = totals["min_start"]
        max_end = totals["max_end"]
        duration = (max_end - min_start) if (min_start is not None and max_end is not None) else 0
        rps = (totals["total_entries"] / duration) if duration and duration > 0 else 0

        return {
            "total_entries": totals["total_entries"],
            "total_input_tokens": totals["total_input_tokens"],
            "total_output_tokens": totals["total_output_tokens"],
            "rps": round(rps, 1),
            "major_stats": [dict(row) for row in major_rows],
        }
    finally:
        conn.close()


def list_self_hosted(db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    conn = get_conn(db_path)
    try:
        rows = conn.execute("SELECT * FROM self_hosted_services ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def add_self_hosted(name: str, server_ip: str, db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO self_hosted_services(name, server_ip) VALUES (?, ?)",
            (name, server_ip),
        )
        conn.commit()
    finally:
        conn.close()


def delete_self_hosted(service_id: int, db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute("DELETE FROM self_hosted_services WHERE id = ?", (service_id,))
        conn.commit()
    finally:
        conn.close()


def clear_self_hosted(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute("DELETE FROM self_hosted_services")
        _reset_autoincrement(conn, "self_hosted_services")
        conn.commit()
    finally:
        conn.close()
