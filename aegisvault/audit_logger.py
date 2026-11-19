
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / ".aegis"
DATABASE_PATH = DATABASE_DIR / "aegisvault.db"


def get_connection():
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                input_type TEXT NOT NULL,

                decision TEXT NOT NULL,

                pii_count INTEGER DEFAULT 0,

                message TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_logs(timestamp)
        """)


def log_scan(input_type, decision, pii_count, message):

    allowed_types = {"text", "image"}
    allowed_decisions = {"SAFE", "SANITIZE", "REVIEW", "BLOCK"}

    if input_type not in allowed_types:
        raise ValueError("Invalid input type.")

    if decision not in allowed_decisions:
        raise ValueError("Invalid security decision.")

    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:

        connection.execute("""
            INSERT INTO audit_logs
            (timestamp, input_type, decision, pii_count, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            timestamp,
            input_type,
            decision,
            max(0, int(pii_count)),
            str(message)[:250]
        ))


def get_recent_logs(limit=20):

    limit = max(1, min(int(limit), 100))

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT id, timestamp, input_type, decision,
                   pii_count, message
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_audit_statistics():

    with get_connection() as connection:

        total = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
        """).fetchone()[0]

        blocked = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
            WHERE decision = 'BLOCK'
        """).fetchone()[0]

        sanitized = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
            WHERE decision = 'SANITIZE'
        """).fetchone()[0]

        safe = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
            WHERE decision = 'SAFE'
        """).fetchone()[0]

        review = connection.execute("""
            SELECT COUNT(*) FROM audit_logs
            WHERE decision = 'REVIEW'
        """).fetchone()[0]

    return {
        "total": total,
        "blocked": blocked,
        "sanitized": sanitized,
        "safe": safe,
        "review": review
    }


initialize_database()
