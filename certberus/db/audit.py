import datetime
from typing import Optional, Any
import json
from sqlmodel import Session
from .models import AuditLog
from . import session

async def log_event(
    method: str,
    endpoint: str,
    status_code: int,
    token_type: str,
    request_payload: Any = None,
    response_summary: Optional[str] = None,
    ip_address: Optional[str] = None,
    serial_number: Optional[str] = None
):
    """
    Asynchronously logs an event to the AuditLog table.
    """
    # Mask sensitive fields in payload if it's a dict
    masked_payload = None
    if request_payload:
        if isinstance(request_payload, dict):
            # Shallow copy to avoid modifying original
            payload_copy = request_payload.copy()
            sensitive_keys = ["ca_password", "inter_password", "root_password", "p12_password", "token"]
            for key in sensitive_keys:
                if key in payload_copy:
                    payload_copy[key] = "********"
            masked_payload = json.dumps(payload_copy)
        elif isinstance(request_payload, str):
            masked_payload = request_payload
        else:
            masked_payload = str(request_payload)

    async with session.AsyncSessionLocal() as db_session:
        log_entry = AuditLog(
            token_type=token_type,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            request_payload=masked_payload,
            response_summary=response_summary,
            ip_address=ip_address,
            serial_number=serial_number
        )
        db_session.add(log_entry)
        await db_session.commit()
