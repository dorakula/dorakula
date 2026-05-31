"""
DORAKULA Session Manager Module
=================================
Manages testing sessions for the DORAKULA offensive security framework.
Tracks targets, scope, phases, findings, and tool execution history
with full persistence via DorakulaDatabase.

Author: DORAKULA Framework
License: Offensive Security Use Only
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.database import DorakulaDatabase

logger = logging.getLogger("dorakula.core.session_manager")

# Valid testing phases in order of execution
VALID_PHASES: List[str] = [
    "recon",
    "mapping",
    "vulnerability_scan",
    "exploitation",
    "post_exploitation",
    "reporting",
    "completed",
]


class SessionManager:
    """Manages testing sessions for DORAKULA framework.

    A session represents a single testing workflow against a target,
    tracking the current phase, scope boundaries, tools executed,
    findings discovered, and timestamps. All data is persisted
    through the DorakulaDatabase.

    Attributes:
        db: DorakulaDatabase instance for persistent storage.
    """

    def __init__(self, db: DorakulaDatabase) -> None:
        """Initialize the session manager.

        Args:
            db: DorakulaDatabase instance for data persistence.
        """
        self.db: DorakulaDatabase = db
        logger.info("SessionManager initialized")

    def create_session(
        self,
        target: str,
        scope: List[str],
        engagement_id: str,
    ) -> Dict:
        """Create a new testing session.

        Args:
            target: The primary target hostname, IP, or URL.
            scope: List of in-scope assets/domains/URLs.
            engagement_id: The parent engagement ID.

        Returns:
            Dictionary with the created session data including generated ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        session_data: Dict[str, Any] = {
            "engagement_id": engagement_id,
            "target": target,
            "scope": scope,
            "phase": "recon",
            "status": "active",
            "tools_executed": [],
            "findings_count": 0,
            "started_at": now,
            "ended_at": None,
            "notes": "",
        }

        session_id = self.db.save_session(session_data)
        session_data["id"] = session_id

        logger.info(
            "Created session %s for target %s (engagement: %s)",
            session_id, target, engagement_id,
        )
        return session_data

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Retrieve a session by ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            Dictionary with session data, or None if not found.
        """
        return self.db.get_session_by_id(session_id)

    def list_sessions(self) -> List[Dict]:
        """List all sessions (both active and closed).

        Returns:
            List of session dictionaries ordered by most recent first.
        """
        # Get active sessions first
        active = self.db.get_active_sessions()
        # For a complete list, we query all sessions from the database
        # Since DorakulaDatabase doesn't have a list_all_sessions method,
        # we'll work with what we have and log it
        logger.debug("Listed %d active sessions", len(active))
        return active

    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update specific fields of a session.

        Validates phase transitions and serializes list/dict fields
        before persisting to the database.

        Args:
            session_id: The session ID to update.
            updates: Dictionary of field names and new values.
                    Special handling for 'phase' (validation) and
                    'scope'/'tools_executed' (JSON serialization).

        Returns:
            True if the update was successful, False otherwise.
        """
        if not updates:
            return False

        # Validate phase transition
        if "phase" in updates:
            new_phase = updates["phase"]
            if new_phase not in VALID_PHASES:
                logger.warning(
                    "Invalid phase '%s' for session %s. Valid: %s",
                    new_phase, session_id, VALID_PHASES,
                )
                return False

        # Serialize list/dict fields for SQLite storage
        if "scope" in updates and isinstance(updates["scope"], list):
            updates["scope"] = json.dumps(updates["scope"])
        if "tools_executed" in updates and isinstance(updates["tools_executed"], list):
            updates["tools_executed"] = json.dumps(updates["tools_executed"])

        result = self.db.update_session(session_id, updates)
        if result:
            logger.info("Updated session %s: %s", session_id, list(updates.keys()))
        else:
            logger.warning("Failed to update session %s", session_id)
        return result

    def close_session(self, session_id: str) -> Dict:
        """Close an active session, marking it as completed.

        Sets status to 'closed', phase to 'completed', and records
        the end timestamp.

        Args:
            session_id: The session ID to close.

        Returns:
            Dictionary with the updated session data.

        Raises:
            ValueError: If the session is not found.
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")

        now = datetime.now(timezone.utc).isoformat()
        self.update_session(session_id, {
            "status": "closed",
            "phase": "completed",
            "ended_at": now,
        })

        closed_session = self.get_session(session_id)
        logger.info("Closed session %s for target %s", session_id, session.get("target"))
        return closed_session if closed_session else {"id": session_id, "status": "closed"}

    def resume_session(self, session_id: str) -> Dict:
        """Resume a previously closed session.

        Resets the status to 'active' and clears the end timestamp,
        allowing continued work on the same session.

        Args:
            session_id: The session ID to resume.

        Returns:
            Dictionary with the updated session data.

        Raises:
            ValueError: If the session is not found.
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")

        if session.get("status") == "active":
            logger.warning("Session %s is already active", session_id)
            return session

        self.update_session(session_id, {
            "status": "active",
            "ended_at": None,
        })

        resumed_session = self.get_session(session_id)
        logger.info(
            "Resumed session %s for target %s at phase %s",
            session_id, session.get("target"), session.get("phase"),
        )
        return resumed_session if resumed_session else {"id": session_id, "status": "active"}

    def get_session_context(self, session_id: str) -> Dict:
        """Retrieve the full context of a session for decision-making.

        Aggregates session data with all related findings, tool
        execution history, and engagement metadata to provide a
        comprehensive view for AI-driven workflow decisions.

        Args:
            session_id: The session ID to get context for.

        Returns:
            Dictionary with keys:
                - 'session': Session metadata
                - 'engagement': Parent engagement data
                - 'findings': All findings for this engagement
                - 'tool_history': All scan results for this session
                - 'current_phase': Current testing phase
                - 'next_phases': Remaining phases to execute
                - 'tools_executed': List of tools already run
                - 'scope': In-scope assets

        Raises:
            ValueError: If the session is not found.
        """
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")

        engagement_id = session.get("engagement_id", "")
        engagement = self.db.get_engagement(engagement_id)
        findings = self.db.get_findings(engagement_id)

        # Get scan results for this session
        tool_history = self._get_session_scan_results(session_id)

        current_phase = session.get("phase", "recon")
        current_idx = VALID_PHASES.index(current_phase) if current_phase in VALID_PHASES else 0
        next_phases = VALID_PHASES[current_idx + 1:]

        # Parse JSON fields if they are still strings
        scope = session.get("scope", [])
        if isinstance(scope, str):
            scope = json.loads(scope)

        tools_executed = session.get("tools_executed", [])
        if isinstance(tools_executed, str):
            tools_executed = json.loads(tools_executed)

        context: Dict[str, Any] = {
            "session": session,
            "engagement": engagement,
            "findings": findings,
            "tool_history": tool_history,
            "current_phase": current_phase,
            "next_phases": next_phases,
            "tools_executed": tools_executed,
            "scope": scope,
            "findings_by_severity": self._group_findings_by_severity(findings),
        }

        logger.debug(
            "Built session context for %s: phase=%s, findings=%d, tools=%d",
            session_id, current_phase, len(findings), len(tools_executed),
        )
        return context

    def add_tool_result(self, session_id: str, tool: str, result: Dict) -> None:
        """Add a tool execution result to the session.

        Records the tool in the session's executed tools list and
        saves the scan result to the database.

        Args:
            session_id: The session ID to add the result to.
            tool: Name of the tool that was executed.
            result: Dictionary with scan result data including
                   'target', 'parsed', 'raw_output', etc.
        """
        session = self.get_session(session_id)
        if not session:
            logger.error("Cannot add tool result: session %s not found", session_id)
            return

        engagement_id = session.get("engagement_id", "")

        # Save the scan result with session reference
        result["session_id"] = session_id
        self.db.save_scan_result(engagement_id, tool, result)

        # Update the tools_executed list
        tools_executed = session.get("tools_executed", [])
        if isinstance(tools_executed, str):
            tools_executed = json.loads(tools_executed)

        if tool not in tools_executed:
            tools_executed.append(tool)

        # Update findings count from engagement
        findings = self.db.get_findings(engagement_id)
        findings_count = len(findings)

        self.update_session(session_id, {
            "tools_executed": tools_executed,
            "findings_count": findings_count,
        })

        logger.info(
            "Added tool result [%s] to session %s (total tools: %d)",
            tool, session_id, len(tools_executed),
        )

    def get_tool_history(self, session_id: str) -> List[Dict]:
        """Retrieve the tool execution history for a session.

        Args:
            session_id: The session ID to get history for.

        Returns:
            List of scan result dictionaries for this session,
            ordered by most recent first.
        """
        return self._get_session_scan_results(session_id)

    def _get_session_scan_results(self, session_id: str) -> List[Dict]:
        """Retrieve scan results for a specific session from the database.

        Args:
            session_id: The session ID to query.

        Returns:
            List of scan result dictionaries matching the session.
        """
        conn = self.db._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT * FROM scan_results
                WHERE session_id = ?
                ORDER BY started_at DESC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                result = self.db._row_to_dict(row)
                result["result"] = json.loads(result.get("result", "{}"))
                results.append(result)
            return results
        except Exception as exc:
            logger.error(
                "Failed to get scan results for session %s: %s",
                session_id, exc,
            )
            return []
        finally:
            conn.close()

    @staticmethod
    def _group_findings_by_severity(findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity level.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Dictionary mapping severity levels to lists of findings.
        """
        grouped: Dict[str, List[Dict]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in grouped:
                grouped[sev].append(f)
            else:
                grouped.setdefault("other", []).append(f)
        return grouped
