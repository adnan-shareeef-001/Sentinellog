"""SQLite persistence for alerts, incidents, and analyst triage statuses."""

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinellog.alerts.incidents import Incident
from sentinellog.models import Alert


class AlertStore:
    """Thread-safe SQLite database manager for alerts and incident records."""

    def __init__(self, db_path: Path | str = "data/sentinellog.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a managed SQLite connection that closes on exit."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    alert_count INTEGER NOT NULL,
                    entities TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    entities TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    mitre TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    recommended_action TEXT,
                    status TEXT NOT NULL DEFAULT 'new',
                    incident_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE SET NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")

    def save_alert(self, alert: Alert, incident_id: str | None = None) -> str:
        """Insert a single alert into the database and return its unique ID."""
        alert_id = f"ALT-{uuid.uuid4().hex[:12].upper()}"
        now_iso = datetime.now(UTC).isoformat()

        evidence_dicts = [e.model_dump() for e in alert.evidence]

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO alerts (
                    id, rule_id, rule_name, severity, score,
                    first_seen, last_seen, count, entities, evidence,
                    mitre, explanation, recommended_action, status,
                    incident_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity.value,
                    alert.score,
                    alert.first_seen.isoformat(),
                    alert.last_seen.isoformat(),
                    alert.count,
                    json.dumps(alert.entities),
                    json.dumps(evidence_dicts),
                    json.dumps(alert.mitre),
                    alert.explanation,
                    alert.recommended_action,
                    "new",
                    incident_id,
                    now_iso,
                ),
            )
        return alert_id

    def save_alerts(
        self,
        alerts: list[Alert],
        incident_id: str | None = None,
    ) -> list[str]:
        """Save multiple alerts in a single transaction."""
        ids: list[str] = []
        now_iso = datetime.now(UTC).isoformat()

        with self._get_connection() as conn:
            for alert in alerts:
                alert_id = f"ALT-{uuid.uuid4().hex[:12].upper()}"
                ids.append(alert_id)
                evidence_dicts = [e.model_dump() for e in alert.evidence]

                conn.execute(
                    """
                    INSERT INTO alerts (
                        id, rule_id, rule_name, severity, score,
                        first_seen, last_seen, count, entities, evidence,
                        mitre, explanation, recommended_action, status,
                        incident_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        alert.rule_id,
                        alert.rule_name,
                        alert.severity.value,
                        alert.score,
                        alert.first_seen.isoformat(),
                        alert.last_seen.isoformat(),
                        alert.count,
                        json.dumps(alert.entities),
                        json.dumps(evidence_dicts),
                        json.dumps(alert.mitre),
                        alert.explanation,
                        alert.recommended_action,
                        "new",
                        incident_id,
                        now_iso,
                    ),
                )
        return ids

    def get_alerts(
        self,
        severity: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve stored alerts with optional filtering."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())
        if status:
            query += " AND status = ?"
            params.append(status.lower())
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id.upper())

        query += " ORDER BY first_seen DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["entities"] = json.loads(item["entities"])
                item["evidence"] = json.loads(item["evidence"])
                item["mitre"] = json.loads(item["mitre"])
                results.append(item)
            return results

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        """Fetch a single alert by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            item["entities"] = json.loads(item["entities"])
            item["evidence"] = json.loads(item["evidence"])
            item["mitre"] = json.loads(item["mitre"])
            return item

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update triage status for an alert (e.g., 'acknowledged', 'resolved')."""
        valid_statuses = {"new", "acknowledged", "resolved", "false_positive"}
        clean_status = status.lower().strip()
        if clean_status not in valid_statuses:
            msg = f"Invalid status '{status}'. Must be one of {valid_statuses}."
            raise ValueError(msg)

        with self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (clean_status, alert_id),
            )
            return cur.rowcount > 0

    def save_incidents(self, incidents: list[Incident]) -> list[str]:
        """Persist incidents and associate their constituent alerts."""
        now_iso = datetime.now(UTC).isoformat()
        saved_ids: list[str] = []

        with self._get_connection() as conn:
            for inc in incidents:
                saved_ids.append(inc.id)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO incidents (
                        id, title, severity, score, first_seen,
                        last_seen, status, alert_count, entities, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inc.id,
                        inc.title,
                        inc.severity.value,
                        inc.score,
                        inc.first_seen.isoformat(),
                        inc.last_seen.isoformat(),
                        inc.status,
                        inc.alert_count,
                        json.dumps(inc.entities),
                        now_iso,
                    ),
                )
                # Save and link alerts
                for a in inc.alerts:
                    alert_id = f"ALT-{uuid.uuid4().hex[:12].upper()}"
                    evidence_dicts = [e.model_dump() for e in a.evidence]
                    conn.execute(
                        """
                        INSERT INTO alerts (
                            id, rule_id, rule_name, severity, score,
                            first_seen, last_seen, count, entities, evidence,
                            mitre, explanation, recommended_action, status,
                            incident_id, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert_id,
                            a.rule_id,
                            a.rule_name,
                            a.severity.value,
                            a.score,
                            a.first_seen.isoformat(),
                            a.last_seen.isoformat(),
                            a.count,
                            json.dumps(a.entities),
                            json.dumps(evidence_dicts),
                            json.dumps(a.mitre),
                            a.explanation,
                            a.recommended_action,
                            "new",
                            inc.id,
                            now_iso,
                        ),
                    )
        return saved_ids

    def get_incidents(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve stored incidents with optional filtering."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.lower())

        query += " ORDER BY first_seen DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                item["entities"] = json.loads(item["entities"])
                results.append(item)
            return results

    def update_incident_status(self, incident_id: str, status: str) -> bool:
        """Update triage status for an incident."""
        valid_statuses = {"open", "investigating", "resolved", "false_positive"}
        clean_status = status.lower().strip()
        if clean_status not in valid_statuses:
            msg = f"Invalid status '{status}'. Must be one of {valid_statuses}."
            raise ValueError(msg)

        with self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (clean_status, incident_id),
            )
            return cur.rowcount > 0
