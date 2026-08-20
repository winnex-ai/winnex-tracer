"""
Tracer-GOV — PostgreSQL Store
==============================
Persists audit records to PostgreSQL with dual-write support.
Table schema is configurable via policies JSON.

Licensed under Business Source License 1.1 (BSL 1.1) | contact: licensing@winnex.ai
"""
import os, json, uuid, re
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone


class PgStore:
    """PostgreSQL store — primary database for dual-write.

    Args:
        connection_string: PostgreSQL connection string
        table_name: Audit table name (configurable)

    Security: ``table_name`` is validated against a strict identifier
    pattern (``^[a-z_][a-z0-9_]*$``). Because table names cannot be bound
    as query parameters in PostgreSQL, this validation is what makes the
    generated SQL safe by construction (prevents SQL injection via config).
    """

    # Strict identifier pattern: letters, digits, underscore, no quotes.
    _TABLE_RE = re.compile(r"^[a-z_][a-z0-9_]*$")

    def __init__(self, connection_string: str = "",
                 table_name: str = "tracer_gov_audits"):
        if not self._TABLE_RE.match(table_name):
            raise ValueError(
                f"Invalid table_name {table_name!r}: must match "
                r"^[a-z_][a-z0-9_]*$ (alphanumeric + underscore).")
        self.connection_string = connection_string or os.environ.get(
            "WINNEX_TRACER_PG_CONNECTION", "postgresql://localhost/tracer_gov")
        self.table_name = table_name
        self._conn = None

    def _connect(self):
        if self._conn is None:
            import psycopg2
            self._conn = psycopg2.connect(self.connection_string)

    def insert(self, record: dict) -> Dict[str, Any]:
        """Insert an audit record into PostgreSQL.

        Args:
            record: Complete audit record dict

        Returns:
            Receipt with audit_id and timestamps
        """
        self._connect()
        cur = self._conn.cursor()

        audit_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc)
        metadata = record.get("metadata", {})
        retention_years = metadata.get("retention_years", 5)
        expires_at = created_at.replace(
            year=created_at.year + retention_years
        )

        cur.execute(f"""
            INSERT INTO {self.table_name} (
                id, query_hash, agency, cpf, role,
                source_database, sensitivity, purpose,
                result, audit_trail, signature, algorithm,
                worm_path, worm_hash, blockchain_tx,
                created_at, expires_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s,
                %s, %s
            )
        """, (
            audit_id,
            record.get("query_hash", ""),
            metadata.get("requesting_agency", ""),
            metadata.get("cpf", ""),
            metadata.get("role", ""),
            metadata.get("source_database", ""),
            metadata.get("sensitivity", ""),
            metadata.get("purpose", ""),
            json.dumps({"indices": record.get("indices", []),
                        "scores": record.get("scores", [])}),
            json.dumps(record.get("audit", [])),
            record.get("signature", ""),
            record.get("signature_algorithm", ""),
            record.get("worm_path", ""),
            record.get("worm_hash", ""),
            record.get("blockchain_tx", ""),
            created_at.isoformat(),
            expires_at.isoformat(),
        ))

        self._conn.commit()
        cur.close()

        return {
            "store": "postgresql",
            "audit_id": audit_id,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }

    def get(self, audit_id: str) -> Optional[dict]:
        """Get audit record by ID."""
        self._connect()
        cur = self._conn.cursor()
        cur.execute(f"SELECT * FROM {self.table_name} WHERE id = %s",
                    (audit_id,))
        row = cur.fetchone()
        cur.close()
        if row is None:
            return None
        return {
            "id": row[0],
            "query_hash": row[1],
            "agency": row[2],
            "cpf": row[3],
            "role": row[4],
            "source_database": row[5],
            "sensitivity": row[6],
            "purpose": row[7],
            "result": json.loads(row[8]) if isinstance(row[8], str) else row[8],
            "audit_trail": json.loads(row[9]) if isinstance(row[9], str) else row[9],
            "signature": row[10],
            "algorithm": row[11],
            "worm_path": row[12],
            "worm_hash": row[13],
            "created_at": row[14].isoformat() if row[14] else "",
            "expires_at": row[15].isoformat() if row[15] else "",
        }

    def list_by_agency(self, agency: str, limit: int = 100) -> List[dict]:
        """List audit records by agency."""
        self._connect()
        cur = self._conn.cursor()
        cur.execute(
            f"SELECT id, agency, purpose, sensitivity, created_at "
            f"FROM {self.table_name} WHERE agency = %s "
            f"ORDER BY created_at DESC LIMIT %s",
            (agency, limit))
        rows = cur.fetchall()
        cur.close()
        return [
            {"id": r[0], "agency": r[1], "purpose": r[2],
             "sensitivity": r[3], "created_at": r[4].isoformat()}
            for r in rows
        ]

    def count_by_period(self, start: str, end: str) -> dict:
        """Count audit records grouped by agency for a time period."""
        self._connect()
        cur = self._conn.cursor()
        cur.execute(
            f"SELECT agency, COUNT(*) FROM {self.table_name} "
            f"WHERE created_at >= %s AND created_at < %s "
            f"GROUP BY agency ORDER BY COUNT(*) DESC",
            (start, end))
        rows = cur.fetchall()
        cur.close()
        return {r[0]: r[1] for r in rows}

    def get_schema_ddl(self) -> str:
        """Get the DDL for the audit table."""
        return f"""
CREATE TABLE IF NOT EXISTS {self.table_name} (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query_hash      TEXT NOT NULL,
    agency          TEXT NOT NULL,
    cpf             TEXT NOT NULL,
    role            TEXT NOT NULL,
    source_database TEXT NOT NULL,
    sensitivity     TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    result          JSONB NOT NULL,
    audit_trail     JSONB NOT NULL,
    signature       TEXT NOT NULL,
    algorithm       TEXT NOT NULL,
    worm_path       TEXT,
    worm_hash       TEXT,
    blockchain_tx   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT valid_sensitivity CHECK (
        sensitivity IN ('public', 'restricted', 'secret'))
);

CREATE INDEX IF NOT EXISTS idx_{self.table_name}_agency
    ON {self.table_name}(agency);
CREATE INDEX IF NOT EXISTS idx_{self.table_name}_cpf
    ON {self.table_name}(cpf);
CREATE INDEX IF NOT EXISTS idx_{self.table_name}_created_at
    ON {self.table_name}(created_at DESC);
"""
