"""
itsm_client.py
===============
ITSM (IT Service Management) integration client for AegisOps.

Handles incident ticket lifecycle operations: creation, updates,
and closure. Persists ticket state to PostgreSQL for audit trails
and cross-references with the LangGraph incident ID.

In production, this would integrate with ServiceNow, Jira Service
Management, PagerDuty, or similar. For the hackathon, it persists
locally to PostgreSQL and logs structured payloads.
"""

import json
import time
from typing import Any, Dict, Optional

from aegisops.core.db_config import get_db_connection


def _ensure_itsm_table() -> None:
    """Creates the ITSM tickets table if it doesn't exist.

    Called lazily on first use to avoid startup ordering issues.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS itsm_tickets (
                id SERIAL PRIMARY KEY,
                ticket_id VARCHAR(255) UNIQUE NOT NULL,
                service_name VARCHAR(255),
                status VARCHAR(50) DEFAULT 'OPEN',
                resolution_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP
            );
            """)
    finally:
        conn.close()


def create_itsm_ticket(
    ticket_id: str,
    service_name: str,
    description: str,
) -> Dict[str, Any]:
    """Creates a new incident ticket in the ITSM system.

    Args:
        ticket_id: Unique ticket identifier (matches incident_id).
        service_name: The affected service.
        description: Initial incident description.

    Returns:
        Dictionary with ticket creation confirmation.
    """
    print(
        f"[ITSM] Creating ticket {ticket_id} for {service_name}: "
        f"{description[:100]}"
    )

    try:
        _ensure_itsm_table()
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO itsm_tickets (ticket_id, service_name, status)
                    VALUES (%s, %s, 'OPEN')
                    ON CONFLICT (ticket_id) DO UPDATE SET status = 'OPEN';
                    """,
                    (ticket_id, service_name),
                )
        finally:
            conn.close()
    except Exception as e:
        print(f"[ITSM] WARNING: DB persistence failed: {e}")

    return {
        "ticket_id": ticket_id,
        "status": "OPEN",
        "service": service_name,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def close_itsm_ticket(ticket_id: str, resolution_notes: str) -> Dict[str, Any]:
    """Closes an incident ticket with resolution notes.

    Args:
        ticket_id: The ticket to close.
        resolution_notes: Summary of the resolution including
            actions taken, firewall audit, and RCA.

    Returns:
        Dictionary with ticket closure confirmation.
    """
    print(f"[ITSM] Closing ticket {ticket_id}: {resolution_notes[:200]}")

    try:
        _ensure_itsm_table()
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE itsm_tickets
                    SET status = 'RESOLVED',
                        resolution_notes = %s,
                        resolved_at = CURRENT_TIMESTAMP
                    WHERE ticket_id = %s;
                    """,
                    (resolution_notes, ticket_id),
                )
                # If no rows updated, insert a new resolved ticket
                if cur.rowcount == 0:
                    cur.execute(
                        """
                        INSERT INTO itsm_tickets 
                            (ticket_id, status, resolution_notes, resolved_at)
                        VALUES (%s, 'RESOLVED', %s, CURRENT_TIMESTAMP);
                        """,
                        (ticket_id, resolution_notes),
                    )
        finally:
            conn.close()
    except Exception as e:
        print(f"[ITSM] WARNING: DB persistence failed: {e}")

    return {
        "ticket_id": ticket_id,
        "status": "RESOLVED",
        "resolution_notes": resolution_notes[:200],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def get_ticket_status(ticket_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the current status of an ITSM ticket.

    Args:
        ticket_id: The ticket to query.

    Returns:
        Ticket status dictionary, or None if not found.
    """
    try:
        _ensure_itsm_table()
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM itsm_tickets WHERE ticket_id = %s;",
                    (ticket_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None
        finally:
            conn.close()
    except Exception as e:
        print(f"[ITSM] WARNING: Failed to query ticket: {e}")
        return None
