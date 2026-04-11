from datetime import datetime
from typing import Optional
import uuid
from sqlmodel import Field, SQLModel

class Authority(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str = Field(index=True, unique=True, description="Name or slug of the CA (e.g., CA-IoT)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = Field(default=True, description="Whether this CA is currently active")

class Certificate(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    serial_number: str = Field(index=True, unique=True, description="Hex representation of x509 serial")
    authority_id: Optional[str] = Field(default=None, foreign_key="authority.id", description="ID of the issuing CA")
    common_name: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None
    fingerprint: str = Field(description="SHA-256 fingerprint of the certificate")
    format: str = Field(default="pem", description="Format emitted (pem or p12)")
    
    # Track the metadata used to create it
    is_ca: bool = Field(default=False)
    profile: str = Field(default="router", description="Device profile used (router, iot, server)")
    status: str = Field(default="active", index=True, description="Status of the certificate (active, revoked)")

class AuditLog(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    token_type: str = Field(description="Type of token used: admin or service")
    endpoint: str = Field(index=True)
    method: str
    status_code: int
    request_payload: Optional[str] = None
    response_summary: Optional[str] = None
    ip_address: Optional[str] = None
    serial_number: Optional[str] = Field(default=None, index=True, description="Affected certificate serial if any")
