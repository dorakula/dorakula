"""
DORAKULA Database Module
========================
SQLite-based persistent storage for the DORAKULA offensive security framework.
Provides thread-safe database operations for engagements, findings, scan results,
sessions, reports, and scope rules.

Author: DORAKULA Framework
License: Offensive Security Use Only
"""

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dorakula.core.database")


class DorakulaDatabase:
    """SQLite-based persistent storage for DORAKULA framework.

    Provides thread-safe CRUD operations for all framework entities including
    engagements, findings, scan results, targets, sessions, reports, and
    scope rules. Uses connection-per-operation pattern with threading.Lock
    for thread safety.

    Attributes:
        db_path: Absolute path to the SQLite database file.
        lock: Threading lock for thread-safe write operations.
    """

    def __init__(self, db_path: str = "./data/dorakula.db") -> None:
        """Initialize the database connection manager.

        Args:
            db_path: Absolute path to the SQLite database file.
                     Defaults to ./data/dorakula.db
        """
        self.db_path: str = db_path
        self.lock: threading.Lock = threading.Lock()
        self._ensure_data_directory()
        self.init_db()
        logger.info("DorakulaDatabase initialized at %s", self.db_path)

    def _ensure_data_directory(self) -> None:
        """Ensure the directory for the database file exists."""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.debug("Created database directory: %s", db_dir)

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new database connection with row factory.

        Returns:
            A new sqlite3.Connection with Row factory enabled.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_db(self) -> None:
        """Create all database tables if they do not exist.

        Creates the following tables:
            - engagements: Bug bounty engagement tracking
            - findings: Security vulnerabilities discovered
            - scan_results: Tool scan output storage
            - targets: Target host/asset definitions
            - sessions: Active/past testing sessions
            - reports: Generated report metadata
            - scope_rules: Engagement scope boundary rules
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.executescript("""
                    CREATE TABLE IF NOT EXISTS engagements (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        target TEXT NOT NULL,
                        scope TEXT DEFAULT '{}',
                        status TEXT DEFAULT 'active',
                        start_date TEXT NOT NULL,
                        end_date TEXT,
                        description TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL DEFAULT 'info',
                        cvss_score REAL,
                        cvss_vector TEXT,
                        description TEXT,
                        impact TEXT,
                        remediation TEXT,
                        evidence TEXT,
                        url TEXT,
                        parameter TEXT,
                        request TEXT,
                        response TEXT,
                        tool TEXT,
                        verified INTEGER DEFAULT 0,
                        false_positive INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS scan_results (
                        id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL,
                        session_id TEXT,
                        tool TEXT NOT NULL,
                        target TEXT NOT NULL,
                        result TEXT NOT NULL DEFAULT '{}',
                        raw_output TEXT,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        status TEXT DEFAULT 'completed',
                        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS targets (
                        id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL,
                        host TEXT NOT NULL,
                        ip_address TEXT,
                        port INTEGER,
                        service TEXT,
                        technology TEXT,
                        notes TEXT,
                        in_scope INTEGER DEFAULT 1,
                        discovered_at TEXT NOT NULL,
                        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS sessions (
                        id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL,
                        target TEXT NOT NULL,
                        scope TEXT DEFAULT '[]',
                        phase TEXT DEFAULT 'recon',
                        status TEXT DEFAULT 'active',
                        tools_executed TEXT DEFAULT '[]',
                        findings_count INTEGER DEFAULT 0,
                        started_at TEXT NOT NULL,
                        ended_at TEXT,
                        notes TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS reports (
                        id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL,
                        report_type TEXT NOT NULL,
                        format TEXT NOT NULL,
                        file_path TEXT,
                        generated_at TEXT NOT NULL,
                        summary TEXT,
                        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS scope_rules (
                        id TEXT PRIMARY KEY,
                        engagement_id TEXT NOT NULL,
                        rule_type TEXT NOT NULL,
                        pattern TEXT NOT NULL,
                        description TEXT,
                        enabled INTEGER DEFAULT 1,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
                    );

                    CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
                    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                    CREATE INDEX IF NOT EXISTS idx_scan_results_engagement ON scan_results(engagement_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_engagement ON sessions(engagement_id);
                    CREATE INDEX IF NOT EXISTS idx_targets_engagement ON targets(engagement_id);
                    CREATE INDEX IF NOT EXISTS idx_scope_rules_engagement ON scope_rules(engagement_id);
                    CREATE INDEX IF NOT EXISTS idx_reports_engagement ON reports(engagement_id);
                """)
                conn.commit()
                logger.debug("Database tables initialized successfully")
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to initialize database: %s", exc)
                raise
            finally:
                conn.close()

    @staticmethod
    def _generate_id() -> str:
        """Generate a unique identifier using timestamp and thread info.

        Returns:
            A unique string ID in format 'dk-{timestamp}-{threadid}'.
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        tid = threading.current_thread().ident or 0
        return f"dk-{ts}-{tid}"

    @staticmethod
    def _now_iso() -> str:
        """Return the current UTC timestamp in ISO 8601 format.

        Returns:
            ISO 8601 formatted UTC timestamp string.
        """
        return datetime.now(timezone.utc).isoformat()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a sqlite3.Row to a dictionary.

        Args:
            row: A sqlite3.Row object.

        Returns:
            Dictionary with column names as keys.
        """
        return dict(row) if row else {}

    def save_engagement(self, engagement: Dict) -> str:
        """Save an engagement record to the database.

        Args:
            engagement: Dictionary containing engagement data. Required keys:
                       'name', 'target'. Optional: 'scope', 'description', 'start_date'.

        Returns:
            The generated engagement ID string.

        Raises:
            sqlite3.Error: If the database operation fails.
            KeyError: If required fields are missing.
        """
        engagement_id = engagement.get("id", self._generate_id())
        now = self._now_iso()

        with self.lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    INSERT INTO engagements (id, name, target, scope, status, start_date, end_date, description, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        engagement_id,
                        engagement.get("name", "Unnamed Engagement"),
                        engagement.get("target", ""),
                        json.dumps(engagement.get("scope", {})),
                        engagement.get("status", "active"),
                        engagement.get("start_date", now),
                        engagement.get("end_date"),
                        engagement.get("description", ""),
                        now,
                        now,
                    ),
                )
                conn.commit()
                logger.info("Saved engagement %s: %s", engagement_id, engagement.get("name"))
                return engagement_id
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to save engagement: %s", exc)
                raise
            finally:
                conn.close()

    def get_engagement(self, engagement_id: str) -> Optional[Dict]:
        """Retrieve an engagement by ID.

        Args:
            engagement_id: The unique engagement identifier.

        Returns:
            Dictionary with engagement data, or None if not found.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
            )
            row = cursor.fetchone()
            if row:
                result = self._row_to_dict(row)
                result["scope"] = json.loads(result.get("scope", "{}"))
                return result
            return None
        except sqlite3.Error as exc:
            logger.error("Failed to get engagement %s: %s", engagement_id, exc)
            return None
        finally:
            conn.close()

    def list_engagements(self) -> List[Dict]:
        """List all engagements, ordered by most recent first.

        Returns:
            List of engagement dictionaries.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM engagements ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                result = self._row_to_dict(row)
                result["scope"] = json.loads(result.get("scope", "{}"))
                results.append(result)
            return results
        except sqlite3.Error as exc:
            logger.error("Failed to list engagements: %s", exc)
            return []
        finally:
            conn.close()

    def save_finding(self, engagement_id: str, finding: Dict) -> str:
        """Save a security finding for an engagement.

        Args:
            engagement_id: The parent engagement ID.
            finding: Dictionary with finding data. Required: 'title', 'severity'.
                    Optional: 'cvss_score', 'cvss_vector', 'description', 'impact',
                    'remediation', 'evidence', 'url', 'parameter', 'request',
                    'response', 'tool'.

        Returns:
            The generated finding ID string.

        Raises:
            sqlite3.Error: If the database operation fails.
        """
        finding_id = finding.get("id", self._generate_id())
        now = self._now_iso()

        with self.lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    INSERT INTO findings (
                        id, engagement_id, title, severity, cvss_score, cvss_vector,
                        description, impact, remediation, evidence, url, parameter,
                        request, response, tool, verified, false_positive,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        engagement_id,
                        finding.get("title", "Untitled Finding"),
                        finding.get("severity", "info"),
                        finding.get("cvss_score"),
                        finding.get("cvss_vector"),
                        finding.get("description", ""),
                        finding.get("impact", ""),
                        finding.get("remediation", ""),
                        finding.get("evidence", ""),
                        finding.get("url", ""),
                        finding.get("parameter", ""),
                        finding.get("request", ""),
                        finding.get("response", ""),
                        finding.get("tool", ""),
                        1 if finding.get("verified", False) else 0,
                        1 if finding.get("false_positive", False) else 0,
                        now,
                        now,
                    ),
                )
                conn.commit()
                logger.info(
                    "Saved finding %s [%s] for engagement %s",
                    finding_id, finding.get("severity"), engagement_id,
                )
                return finding_id
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to save finding: %s", exc)
                raise
            finally:
                conn.close()

    def get_findings(self, engagement_id: str, severity: Optional[str] = None) -> List[Dict]:
        """Retrieve findings for an engagement, optionally filtered by severity.

        Args:
            engagement_id: The engagement ID to query findings for.
            severity: Optional severity filter (critical, high, medium, low, info).

        Returns:
            List of finding dictionaries matching the criteria.
        """
        conn = self._get_connection()
        try:
            if severity:
                cursor = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE engagement_id = ? AND severity = ?
                    ORDER BY cvss_score DESC NULLS LAST, created_at DESC
                    """,
                    (engagement_id, severity),
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE engagement_id = ?
                    ORDER BY cvss_score DESC NULLS LAST, created_at DESC
                    """,
                    (engagement_id,),
                )
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.error("Failed to get findings for %s: %s", engagement_id, exc)
            return []
        finally:
            conn.close()

    def save_scan_result(self, engagement_id: str, tool: str, result: Dict) -> str:
        """Save a tool scan result for an engagement.

        Args:
            engagement_id: The parent engagement ID.
            tool: Name of the scanning tool (e.g., 'nmap', 'nuclei').
            result: Dictionary with scan result data. Required: 'target'.
                    Optional: 'raw_output', 'session_id', 'status'.

        Returns:
            The generated scan result ID string.

        Raises:
            sqlite3.Error: If the database operation fails.
        """
        result_id = self._generate_id()
        now = self._now_iso()

        with self.lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    INSERT INTO scan_results (
                        id, engagement_id, session_id, tool, target, result,
                        raw_output, started_at, completed_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result_id,
                        engagement_id,
                        result.get("session_id"),
                        tool,
                        result.get("target", ""),
                        json.dumps(result.get("parsed", {})),
                        result.get("raw_output", ""),
                        result.get("started_at", now),
                        result.get("completed_at", now),
                        result.get("status", "completed"),
                    ),
                )
                conn.commit()
                logger.info(
                    "Saved scan result %s [%s] for engagement %s",
                    result_id, tool, engagement_id,
                )
                return result_id
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to save scan result: %s", exc)
                raise
            finally:
                conn.close()

    def get_scan_history(self, target: str) -> List[Dict]:
        """Retrieve scan history for a specific target across all engagements.

        Args:
            target: The target hostname, IP, or URL to look up.

        Returns:
            List of scan result dictionaries for the target.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT * FROM scan_results
                WHERE target LIKE ?
                ORDER BY started_at DESC
                """,
                (f"%{target}%",),
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                result = self._row_to_dict(row)
                result["result"] = json.loads(result.get("result", "{}"))
                results.append(result)
            return results
        except sqlite3.Error as exc:
            logger.error("Failed to get scan history for %s: %s", target, exc)
            return []
        finally:
            conn.close()

    def save_session(self, session: Dict) -> str:
        """Save a testing session to the database.

        Args:
            session: Dictionary with session data. Required: 'engagement_id', 'target'.
                    Optional: 'scope', 'phase', 'tools_executed', 'notes'.

        Returns:
            The generated session ID string.

        Raises:
            sqlite3.Error: If the database operation fails.
        """
        session_id = session.get("id", self._generate_id())
        now = self._now_iso()

        with self.lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """
                    INSERT INTO sessions (
                        id, engagement_id, target, scope, phase, status,
                        tools_executed, findings_count, started_at, ended_at,
                        notes, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        session.get("engagement_id", ""),
                        session.get("target", ""),
                        json.dumps(session.get("scope", [])),
                        session.get("phase", "recon"),
                        session.get("status", "active"),
                        json.dumps(session.get("tools_executed", [])),
                        session.get("findings_count", 0),
                        session.get("started_at", now),
                        session.get("ended_at"),
                        session.get("notes", ""),
                        now,
                        now,
                    ),
                )
                conn.commit()
                logger.info("Saved session %s for target %s", session_id, session.get("target"))
                return session_id
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to save session: %s", exc)
                raise
            finally:
                conn.close()

    def get_active_sessions(self) -> List[Dict]:
        """Retrieve all currently active sessions.

        Returns:
            List of session dictionaries with status='active'.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE status = 'active' ORDER BY started_at DESC"
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                result = self._row_to_dict(row)
                result["scope"] = json.loads(result.get("scope", "[]"))
                result["tools_executed"] = json.loads(result.get("tools_executed", "[]"))
                results.append(result)
            return results
        except sqlite3.Error as exc:
            logger.error("Failed to get active sessions: %s", exc)
            return []
        finally:
            conn.close()

    def compare_findings(self, engagement_id_1: str, engagement_id_2: str) -> Dict:
        """Compare findings between two engagements to identify differences.

        Useful for tracking new vulnerabilities across scan iterations or
        comparing different testing phases.

        Args:
            engagement_id_1: First engagement ID (baseline).
            engagement_id_2: Second engagement ID (comparison).

        Returns:
            Dictionary with keys:
                - 'only_in_1': Findings only in the first engagement
                - 'only_in_2': Findings only in the second engagement
                - 'common': Findings present in both engagements
                - 'new_critical': New critical/high findings in engagement 2
                - 'resolved': Findings in engagement 1 but not in engagement 2
        """
        findings_1 = self.get_findings(engagement_id_1)
        findings_2 = self.get_findings(engagement_id_2)

        def finding_signature(f: Dict) -> str:
            """Create a normalized signature for finding comparison."""
            return f"{f.get('title', '')}|{f.get('severity', '')}|{f.get('url', '')}|{f.get('parameter', '')}"

        sigs_1 = {finding_signature(f): f for f in findings_1}
        sigs_2 = {finding_signature(f): f for f in findings_2}

        set_1 = set(sigs_1.keys())
        set_2 = set(sigs_2.keys())

        only_in_1 = [sigs_1[s] for s in set_1 - set_2]
        only_in_2 = [sigs_2[s] for s in set_2 - set_1]
        common = [sigs_1[s] for s in set_1 & set_2]
        new_critical = [
            sigs_2[s] for s in (set_2 - set_1)
            if sigs_2[s].get("severity") in ("critical", "high")
        ]

        result = {
            "engagement_1": engagement_id_1,
            "engagement_2": engagement_id_2,
            "only_in_1": only_in_1,
            "only_in_2": only_in_2,
            "common": common,
            "new_critical": new_critical,
            "resolved": only_in_1,
            "summary": {
                "total_in_1": len(findings_1),
                "total_in_2": len(findings_2),
                "new_findings": len(only_in_2),
                "resolved_findings": len(only_in_1),
                "persistent_findings": len(common),
                "new_critical_count": len(new_critical),
            },
        }
        logger.info(
            "Compared findings: %d vs %d (%d new, %d resolved, %d common)",
            len(findings_1), len(findings_2),
            len(only_in_2), len(only_in_1), len(common),
        )
        return result

    def export_findings(self, engagement_id: str, fmt: str = "json") -> str:
        """Export findings for an engagement in the specified format.

        Args:
            engagement_id: The engagement ID to export findings for.
            fmt: Output format - 'json' (default), 'csv', or 'markdown'.

        Returns:
            String containing the formatted findings data.

        Raises:
            ValueError: If an unsupported format is specified.
        """
        findings = self.get_findings(engagement_id)
        engagement = self.get_engagement(engagement_id)

        if fmt == "json":
            export_data = {
                "engagement": engagement,
                "findings": findings,
                "exported_at": self._now_iso(),
                "total_findings": len(findings),
            }
            return json.dumps(export_data, indent=2, default=str)

        elif fmt == "csv":
            lines = [
                "id,title,severity,cvss_score,url,parameter,tool,verified,false_positive,created_at"
            ]
            for f in findings:
                lines.append(
                    f"{f.get('id','')},{f.get('title','')},{f.get('severity','')},"
                    f"{f.get('cvss_score','')},{f.get('url','')},{f.get('parameter','')},"
                    f"{f.get('tool','')},{f.get('verified',0)},{f.get('false_positive',0)},"
                    f"{f.get('created_at','')}"
                )
            return "\n".join(lines)

        elif fmt == "markdown":
            lines = [
                f"# Findings Report - {engagement.get('name', 'Unknown') if engagement else 'Unknown'}",
                f"",
                f"**Target:** {engagement.get('target', 'N/A') if engagement else 'N/A'}",
                f"**Total Findings:** {len(findings)}",
                f"**Exported:** {self._now_iso()}",
                f"",
            ]
            for f in findings:
                lines.append(f"## {f.get('title', 'Untitled')}")
                lines.append(f"- **Severity:** {f.get('severity', 'N/A')}")
                lines.append(f"- **CVSS:** {f.get('cvss_score', 'N/A')}")
                lines.append(f"- **URL:** {f.get('url', 'N/A')}")
                lines.append(f"- **Parameter:** {f.get('parameter', 'N/A')}")
                lines.append(f"- **Description:** {f.get('description', 'N/A')}")
                lines.append(f"- **Remediation:** {f.get('remediation', 'N/A')}")
                lines.append("")
            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported export format: {fmt}. Use 'json', 'csv', or 'markdown'.")

    def get_stats(self) -> Dict:
        """Retrieve database statistics across all engagements.

        Returns:
            Dictionary with counts for all entity types and severity
            breakdown of findings.
        """
        conn = self._get_connection()
        try:
            stats: Dict[str, Any] = {}

            tables = ["engagements", "findings", "scan_results", "targets", "sessions", "reports", "scope_rules"]
            for table in tables:
                cursor = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}")
                row = cursor.fetchone()
                stats[f"{table}_count"] = row["cnt"] if row else 0

            # Severity breakdown
            cursor = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity ORDER BY cnt DESC"
            )
            severity_breakdown = {}
            for row in cursor.fetchall():
                severity_breakdown[row["severity"]] = row["cnt"]
            stats["severity_breakdown"] = severity_breakdown

            # Active sessions
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM sessions WHERE status = 'active'")
            row = cursor.fetchone()
            stats["active_sessions"] = row["cnt"] if row else 0

            # Recent findings (last 24h)
            cursor = conn.execute(
                "SELECT COUNT(*) as cnt FROM findings WHERE created_at >= datetime('now', '-1 day')"
            )
            row = cursor.fetchone()
            stats["recent_findings_24h"] = row["cnt"] if row else 0

            # Database file size
            try:
                stats["db_size_bytes"] = os.path.getsize(self.db_path)
            except OSError:
                stats["db_size_bytes"] = 0

            return stats
        except sqlite3.Error as exc:
            logger.error("Failed to get database stats: %s", exc)
            return {}
        finally:
            conn.close()

    def update_finding(self, finding_id: str, updates: Dict) -> bool:
        """Update specific fields of a finding.

        Args:
            finding_id: The finding ID to update.
            updates: Dictionary of field names and new values.

        Returns:
            True if the update was successful, False otherwise.
        """
        if not updates:
            return False

        updates["updated_at"] = self._now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [finding_id]

        with self.lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    f"UPDATE findings SET {set_clause} WHERE id = ?", values
                )
                conn.commit()
                logger.debug("Updated finding %s", finding_id)
                return True
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to update finding %s: %s", finding_id, exc)
                return False
            finally:
                conn.close()

    def get_session_by_id(self, session_id: str) -> Optional[Dict]:
        """Retrieve a session by its ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            Dictionary with session data, or None if not found.
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            )
            row = cursor.fetchone()
            if row:
                result = self._row_to_dict(row)
                result["scope"] = json.loads(result.get("scope", "[]"))
                result["tools_executed"] = json.loads(result.get("tools_executed", "[]"))
                return result
            return None
        except sqlite3.Error as exc:
            logger.error("Failed to get session %s: %s", session_id, exc)
            return None
        finally:
            conn.close()

    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update specific fields of a session.

        Args:
            session_id: The session ID to update.
            updates: Dictionary of field names and new values.

        Returns:
            True if the update was successful, False otherwise.
        """
        if not updates:
            return False

        updates["updated_at"] = self._now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [session_id]

        with self.lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    f"UPDATE sessions SET {set_clause} WHERE id = ?", values
                )
                conn.commit()
                logger.debug("Updated session %s", session_id)
                return True
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to update session %s: %s", session_id, exc)
                return False
            finally:
                conn.close()

    def delete_engagement(self, engagement_id: str) -> bool:
        """Delete an engagement and all related records.

        Args:
            engagement_id: The engagement ID to delete.

        Returns:
            True if deleted, False if not found or error.
        """
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    "DELETE FROM engagements WHERE id = ?", (engagement_id,)
                )
                conn.commit()
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.info("Deleted engagement %s and all related records", engagement_id)
                else:
                    logger.warning("Engagement %s not found for deletion", engagement_id)
                return deleted
            except sqlite3.Error as exc:
                conn.rollback()
                logger.error("Failed to delete engagement %s: %s", engagement_id, exc)
                return False
            finally:
                conn.close()
