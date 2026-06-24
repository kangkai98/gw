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

APP_FLOW_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "flow_uid": "TEXT NOT NULL UNIQUE",
    "app_name": "TEXT NOT NULL",
    "sni": "TEXT NOT NULL",
    "flow_key": "TEXT NOT NULL",
    "protocol": "TEXT NOT NULL DEFAULT 'TCP'",
    "client_endpoint": "TEXT NOT NULL",
    "server_endpoint": "TEXT NOT NULL",
    "start_time_real": "TEXT NOT NULL",
    "end_time_real": "TEXT NOT NULL",
    "duration_sec": "REAL NOT NULL DEFAULT 0",
    "uplink_bytes": "INTEGER NOT NULL DEFAULT 0",
    "downlink_bytes": "INTEGER NOT NULL DEFAULT 0",
    "peak_bps": "REAL NOT NULL DEFAULT 0",
    "created_at": "DATETIME DEFAULT CURRENT_TIMESTAMP",
}

def _ensure_app_flow_schema(conn: sqlite3.Connection) -> None:
    cols = conn.execute("PRAGMA table_info(app_flow_stats)").fetchall()
    if not cols:
        fields = ",\n                ".join(f"{name} {ddl}" for name, ddl in APP_FLOW_COLUMNS.items())
        conn.execute(f"CREATE TABLE app_flow_stats ({fields})")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_app_flow_stats_flow_uid ON app_flow_stats(flow_uid)")
        return

    existing = {row[1] for row in cols}
    for name, ddl in APP_FLOW_COLUMNS.items():
        if name not in existing and "PRIMARY KEY" not in ddl and "UNIQUE" not in ddl:
            conn.execute(f"ALTER TABLE app_flow_stats ADD COLUMN {name} {ddl}")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_app_flow_stats_flow_uid ON app_flow_stats(flow_uid)")


        _ensure_app_flow_schema(conn)
TRAFFIC_SUMMARY_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "source": "TEXT NOT NULL",
    "pcap_path": "TEXT NOT NULL",
    "window_start_time": "TEXT",
    "window_end_time": "TEXT",
    "uplink_total_bytes": "INTEGER NOT NULL DEFAULT 0",
    "downlink_total_bytes": "INTEGER NOT NULL DEFAULT 0",
    "uplink_ai_bytes": "INTEGER NOT NULL DEFAULT 0",
    "downlink_ai_bytes": "INTEGER NOT NULL DEFAULT 0",
    "created_at": "DATETIME DEFAULT CURRENT_TIMESTAMP",
}

APP_FLOW_COLUMNS: dict[str, str] = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "app_name": "TEXT NOT NULL",
    "sni": "TEXT NOT NULL",
    "flow_key": "TEXT NOT NULL",
    "protocol": "TEXT NOT NULL DEFAULT 'TCP'",
    "client_endpoint": "TEXT NOT NULL",
    "server_endpoint": "TEXT NOT NULL",
    "start_time_real": "TEXT NOT NULL",
    "end_time_real": "TEXT NOT NULL",
    "duration_sec": "REAL NOT NULL DEFAULT 0",
    "uplink_bytes": "INTEGER NOT NULL DEFAULT 0",
    "downlink_bytes": "INTEGER NOT NULL DEFAULT 0",
    "peak_bps": "REAL NOT NULL DEFAULT 0",
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
        conn.execute("INSERT OR REPLACE INTO sqlite_sequence(name, seq) VALUES(?, 0)", (table,))


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


def _ensure_traffic_summary_schema(conn: sqlite3.Connection) -> None:
    cols = conn.execute("PRAGMA table_info(traffic_summaries)").fetchall()
    if not cols:
        fields = ",\n                ".join(f"{name} {ddl}" for name, ddl in TRAFFIC_SUMMARY_COLUMNS.items())
        conn.execute(f"CREATE TABLE traffic_summaries ({fields})")
        return

    existing = {row[1] for row in cols}
    for name, ddl in TRAFFIC_SUMMARY_COLUMNS.items():
        if name not in existing and "PRIMARY KEY" not in ddl:
            conn.execute(f"ALTER TABLE traffic_summaries ADD COLUMN {name} {ddl}")


def _ensure_app_flow_schema(conn: sqlite3.Connection) -> None:
    cols = conn.execute("PRAGMA table_info(app_flow_stats)").fetchall()
    if not cols:
        fields = ",\n                ".join(f"{name} {ddl}" for name, ddl in APP_FLOW_COLUMNS.items())
        conn.execute(f"CREATE TABLE app_flow_stats ({fields})")
        conn.execute("DELETE FROM app_flow_stats")
        _reset_autoincrement(conn, "app_flow_stats")
        conn.commit()
    finally:
        conn.close()


def upsert_app_flow_stat(flow: dict[str, Any], db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO app_flow_stats (
                flow_uid, app_name, sni, flow_key, protocol, client_endpoint, server_endpoint,
                start_time_real, end_time_real, duration_sec,
                uplink_bytes, downlink_bytes, peak_bps
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_uid) DO UPDATE SET
                app_name = excluded.app_name,
                sni = excluded.sni,
                protocol = excluded.protocol,
                client_endpoint = excluded.client_endpoint,
                server_endpoint = excluded.server_endpoint,
                start_time_real = excluded.start_time_real,
                end_time_real = excluded.end_time_real,
                duration_sec = excluded.duration_sec,
                uplink_bytes = excluded.uplink_bytes,
                downlink_bytes = excluded.downlink_bytes,
                peak_bps = excluded.peak_bps
            """,
            (
                str(flow.get("flow_uid") or flow.get("flow_key") or ""),
                str(flow.get("app_name") or ""),
                str(flow.get("sni") or ""),
                str(flow.get("flow_key") or ""),
                str(flow.get("protocol") or "TCP"),
                str(flow.get("client_endpoint") or ""),
                str(flow.get("server_endpoint") or ""),
                str(flow.get("start_time_real") or ""),
                str(flow.get("end_time_real") or ""),
                float(flow.get("duration_sec") or 0),
                int(flow.get("uplink_bytes") or 0),
                int(flow.get("downlink_bytes") or 0),
                float(flow.get("peak_bps") or 0),
            ),
        )
def get_app_traffic_stats(
    app_name: str | None = None,
    start_real: str | None = None,
    end_real: str | None = None,
    db_path: Path = DB_PATH,
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if app_name:
        clauses.append("app_name = ?")
        params.append(app_name)
    if start_real:
        clauses.append("end_time_real >= ?")
        params.append(start_real)
    if end_real:
        clauses.append("start_time_real <= ?")
        params.append(end_real)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_conn(db_path)
    try:
        totals = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_flows,
                COALESCE(SUM(uplink_bytes), 0) AS total_uplink_bytes,
                COALESCE(SUM(downlink_bytes), 0) AS total_downlink_bytes,
                COALESCE(MAX(peak_bps), 0) AS peak_bps
            FROM app_flow_stats
            {where}
            """,
            params,
        ).fetchone()
        by_app = conn.execute(
            f"""
            SELECT app_name, COUNT(*) AS flow_count,
                   COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes,
                   COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes,
                   COALESCE(MAX(peak_bps), 0) AS peak_bps
            FROM app_flow_stats
            {where}
            GROUP BY app_name
            ORDER BY (COALESCE(SUM(uplink_bytes), 0) + COALESCE(SUM(downlink_bytes), 0)) DESC
            """,
            params,
        ).fetchall()
        trend = conn.execute(
            f"""
            SELECT substr(end_time_real, 1, 16) AS bucket,
                   COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes,
                   COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes
            FROM app_flow_stats
            {where}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            params,
        ).fetchall()
        flows = conn.execute(
            f"""
            SELECT * FROM app_flow_stats
            {where}
            ORDER BY id DESC
            LIMIT 500
            """,
            params,
        ).fetchall()
        return {
            "total_flows": totals["total_flows"],
            "total_uplink_bytes": totals["total_uplink_bytes"],
            "total_downlink_bytes": totals["total_downlink_bytes"],
            "peak_bps": totals["peak_bps"],
            "by_app": [dict(row) for row in by_app],
            "trend": [dict(row) for row in trend],
            "flows": [dict(row) for row in flows],
        }
    finally:
        conn.close()


        return

    existing = {row[1] for row in cols}
    for name, ddl in APP_FLOW_COLUMNS.items():
        if name not in existing and "PRIMARY KEY" not in ddl:
            conn.execute(f"ALTER TABLE app_flow_stats ADD COLUMN {name} {ddl}")


def init_db(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        _ensure_entry_schema(conn)
        _ensure_traffic_summary_schema(conn)
        _ensure_app_flow_schema(conn)
        _ensure_self_hosted_schema(conn)
        conn.commit()
    finally:
        conn.close()


def _ensure_self_hosted_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS self_hosted_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            server_ip TEXT NOT NULL,
            server_port INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cols = conn.execute("PRAGMA table_info(self_hosted_services)").fetchall()
    existing = {row[1] for row in cols}
    if "server_port" not in existing:
        conn.execute("ALTER TABLE self_hosted_services ADD COLUMN server_port INTEGER")
        conn.execute("UPDATE self_hosted_services SET server_port = 443 WHERE server_port IS NULL")


def _is_valid_entry_for_store(entry: dict[str, Any]) -> bool:
    # No DB-side filtering constraints; parser is responsible for filtering.
    return True


def insert_entry(entry: dict[str, Any], db_path: Path = DB_PATH) -> bool:
    if not _is_valid_entry_for_store(entry):
        return False
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
        return True
    finally:
        conn.close()


def clear_entries(db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute("DELETE FROM entries")
        conn.execute("DELETE FROM traffic_summaries")
        conn.execute("DELETE FROM app_flow_stats")
        _reset_autoincrement(conn, "entries")
        _reset_autoincrement(conn, "traffic_summaries")
        _reset_autoincrement(conn, "app_flow_stats")
        conn.commit()
    finally:
        conn.close()


def insert_traffic_summary(summary: dict[str, Any], db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO traffic_summaries (
                source, pcap_path, window_start_time, window_end_time,
                uplink_total_bytes, downlink_total_bytes, uplink_ai_bytes, downlink_ai_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                summary.get("source") or "unknown",
                summary.get("pcap_path") or "",
                summary.get("window_start_time"),
                summary.get("window_end_time"),
                int(summary.get("uplink_total_bytes") or 0),
                int(summary.get("downlink_total_bytes") or 0),
                int(summary.get("uplink_ai_bytes") or 0),
                int(summary.get("downlink_ai_bytes") or 0),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def insert_app_flow_stat(flow: dict[str, Any], db_path: Path = DB_PATH) -> None:
    conn = get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT INTO app_flow_stats (
                app_name, sni, flow_key, protocol, client_endpoint, server_endpoint,
                start_time_real, end_time_real, duration_sec,
                uplink_bytes, downlink_bytes, peak_bps
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(flow.get("app_name") or ""),
                str(flow.get("sni") or ""),
                str(flow.get("flow_key") or ""),
                str(flow.get("protocol") or "TCP"),
                str(flow.get("client_endpoint") or ""),
                str(flow.get("server_endpoint") or ""),
                str(flow.get("start_time_real") or ""),
                str(flow.get("end_time_real") or ""),
                float(flow.get("duration_sec") or 0),
                int(flow.get("uplink_bytes") or 0),
                int(flow.get("downlink_bytes") or 0),
                float(flow.get("peak_bps") or 0),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_app_traffic_stats(app_name: str | None = None, start_real: str | None = None, end_real: str | None = None, db_path: Path = DB_PATH) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    if app_name:
        clauses.append("app_name = ?")
        params.append(app_name)
    if start_real:
        clauses.append("end_time_real >= ?")
        params.append(start_real)
    if end_real:
        clauses.append("start_time_real <= ?")
        params.append(end_real)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    conn = get_conn(db_path)
    try:
        totals = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total_flows,
                COALESCE(SUM(uplink_bytes), 0) AS total_uplink_bytes,
                COALESCE(SUM(downlink_bytes), 0) AS total_downlink_bytes,
                COALESCE(MAX(peak_bps), 0) AS peak_bps
            FROM app_flow_stats
            {where}
            """,
            params,
        ).fetchone()
        by_app = conn.execute(
            f"""
            SELECT app_name, COUNT(*) AS flow_count,
                   COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes,
                   COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes,
                   COALESCE(MAX(peak_bps), 0) AS peak_bps
            FROM app_flow_stats
            {where}
            GROUP BY app_name
            ORDER BY (COALESCE(SUM(uplink_bytes), 0) + COALESCE(SUM(downlink_bytes), 0)) DESC
            """,
            params,
        ).fetchall()
        trend = conn.execute(
            f"""
            SELECT substr(end_time_real, 1, 16) AS bucket,
                   COALESCE(SUM(uplink_bytes), 0) AS uplink_bytes,
                   COALESCE(SUM(downlink_bytes), 0) AS downlink_bytes
            FROM app_flow_stats
            {where}
            GROUP BY bucket
            ORDER BY bucket ASC
            """,
            params,
        ).fetchall()
        flows = conn.execute(
            f"""
            SELECT * FROM app_flow_stats
            {where}
            ORDER BY id DESC
            LIMIT 500
            """,
            params,
        ).fetchall()
        return {
            "total_flows": totals["total_flows"],
            "total_uplink_bytes": totals["total_uplink_bytes"],
            "total_downlink_bytes": totals["total_downlink_bytes"],
            "peak_bps": totals["peak_bps"],
            "by_app": [dict(row) for row in by_app],
            "trend": [dict(row) for row in trend],
            "flows": [dict(row) for row in flows],
        }
    finally:
        conn.close()


def _build_filters(
    category_major: str | None = None,
    category_minor: str | None = None,
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
    if category_minor:
        clauses.append("category_minor LIKE ?")
        params.append(f"%{category_minor}%")
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
    category_minor: str | None = None,
    start_rel_s: float | None = None,
    end_rel_s: float | None = None,
    start_real: str | None = None,
    end_real: str | None = None,
    db_path: Path = DB_PATH,
) -> list[dict[str, Any]]:
    conn = get_conn(db_path)
    try:
        where_sql, params = _build_filters(category_major, category_minor, start_rel_s, end_rel_s, start_real, end_real)
        rows = conn.execute(f"SELECT * FROM entries{where_sql} ORDER BY id DESC", params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()



def _build_traffic_filters(start_real: str | None = None, end_real: str | None = None) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if start_real:
        clauses.append("COALESCE(window_end_time, window_start_time, created_at) >= ?")
        params.append(start_real)
    if end_real:
        clauses.append("COALESCE(window_start_time, window_end_time, created_at) <= ?")
        params.append(end_real)
    return ("WHERE " + " AND ".join(clauses), params) if clauses else ("", params)

def get_stats(
    category_major: str | None = None,
    category_minor: str | None = None,
    start_rel_s: float | None = None,
    end_rel_s: float | None = None,
    start_real: str | None = None,
    end_real: str | None = None,
    db_path: Path = DB_PATH,
) -> dict[str, Any]:
    conn = get_conn(db_path)
    try:
        where_sql, params = _build_filters(category_major, category_minor, start_rel_s, end_rel_s, start_real, end_real)
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

        traffic_where_sql, traffic_params = _build_traffic_filters(start_real, end_real)
        traffic = conn.execute(
            f"""
            SELECT
                COALESCE(SUM(uplink_total_bytes), 0) AS total_uplink_bytes,
                COALESCE(SUM(downlink_total_bytes), 0) AS total_downlink_bytes,
                COALESCE(SUM(uplink_ai_bytes), 0) AS total_uplink_ai_bytes,
                COALESCE(SUM(downlink_ai_bytes), 0) AS total_downlink_ai_bytes
            FROM traffic_summaries
            {traffic_where_sql}
            """,
            traffic_params,
        ).fetchone()

        return {
            "total_entries": totals["total_entries"],
            "total_input_tokens": totals["total_input_tokens"],
            "total_output_tokens": totals["total_output_tokens"],
            "rps": round(rps, 1),
            "major_stats": [dict(row) for row in major_rows],
            "total_uplink_bytes": traffic["total_uplink_bytes"],
            "total_downlink_bytes": traffic["total_downlink_bytes"],
            "total_uplink_ai_bytes": traffic["total_uplink_ai_bytes"],
            "total_downlink_ai_bytes": traffic["total_downlink_ai_bytes"],
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


def add_self_hosted(name: str, server_ip: str, server_port: int, db_path: Path = DB_PATH) -> None:
    normalized = (server_ip or "").strip()
    if ":" in normalized:
        normalized = normalized.split(":", 1)[0].strip()
    normalized_port = int(server_port)
    conn = get_conn(db_path)
    try:
        conn.execute(
            "INSERT INTO self_hosted_services(name, server_ip, server_port) VALUES (?, ?, ?)",
            (name, normalized, normalized_port),
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


def refresh_entry_categories_by_self_hosted(db_path: Path = DB_PATH) -> int:
    conn = get_conn(db_path)
    try:
        cfgs = conn.execute("SELECT name, server_ip, server_port FROM self_hosted_services").fetchall()
        entries = conn.execute("SELECT id, flow_key, category_major, category_minor FROM entries").fetchall()
        updated = 0
        for row in entries:
            entry_id = int(row["id"])
            flow_key = str(row["flow_key"] or "")
            category_major = str(row["category_major"] or "")
            category_minor = str(row["category_minor"] or "")
            _, server_endpoint = _split_flow_key(flow_key)
            server_ip, server_port = _split_endpoint(server_endpoint)
            matched = next(
                (cfg for cfg in cfgs if str(cfg["server_ip"] or "") == server_ip and int(cfg["server_port"] or 0) == server_port),
                None,
            )
            if matched:
                new_major = "自建AI"
                new_minor = str(matched["name"] or f"{server_ip}:{server_port}")
            elif category_major == "自建AI":
                new_major = "实验AI"
                new_minor = f"exp-{server_ip}" if server_ip else category_minor
            else:
                continue

            if new_major != category_major or new_minor != category_minor:
                conn.execute(
                    "UPDATE entries SET category_major = ?, category_minor = ? WHERE id = ?",
                    (new_major, new_minor, entry_id),
                )
                updated += 1
        conn.commit()
        return updated
    finally:
        conn.close()


def _split_flow_key(flow_key: str) -> tuple[str, str]:
    parts = str(flow_key or "").split("-", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "", ""


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    raw = str(endpoint or "")
    if ":" not in raw:
        return raw.strip(), 0
    host, port = raw.rsplit(":", 1)
    try:
        return host.strip(), int(port.strip())
    except ValueError:
        return host.strip(), 0
