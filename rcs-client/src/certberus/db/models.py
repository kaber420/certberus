from datetime import datetime
from typing import Optional
import uuid
from sqlmodel import Field, SQLModel

class Authority(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    name: str = Field(index=True, unique=True, description="Name or slug of the CA (e.g., CA-IoT)")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = Field(default=True, description="Whether this CA is currently active")
    parent_id: Optional[str] = Field(default=None, foreign_key="authority.id", description="ID of the parent Level 2 CA if this is a Level 3 Sub-CA")

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
    pem_content: Optional[str] = Field(default=None, description="The full PEM content of the certificate")

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

# --- ACME Protocol Models ---

class AcmeAccount(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    key_jwk: str = Field(description="JSON representation of the account public key")
    status: str = Field(default="valid", index=True) # valid, deactivated, revoked
    contact: Optional[str] = Field(default=None, description="Contact info (e.g. mailto:admin@example.com)")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AcmeOrder(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    account_id: str = Field(foreign_key="acmeaccount.id", index=True)
    status: str = Field(default="pending", index=True) # pending, ready, processing, valid, invalid
    expires: Optional[datetime] = None
    identifiers: str = Field(description="JSON list of identifiers (e.g. [{'type': 'dns', 'value': 'example.com'}])")
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    error: Optional[str] = None
    certificate_id: Optional[str] = Field(default=None, foreign_key="certificate.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AcmeAuthorization(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    order_id: str = Field(foreign_key="acmeorder.id", index=True)
    identifier: str = Field(description="JSON identifier (e.g. {'type': 'dns', 'value': 'example.com'})")
    status: str = Field(default="pending", index=True) # pending, valid, invalid, deactivated, expired, revoked
    expires: Optional[datetime] = None
    wildcard: bool = Field(default=False)

class AcmeChallenge(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    authz_id: str = Field(foreign_key="acmeauthorization.id", index=True)
    type: str = Field(description="Challenge type (http-01, dns-01)")
    status: str = Field(default="pending", index=True) # pending, processing, valid, invalid
    token: str = Field(index=True)
    key_authorization: Optional[str] = None
    validated: Optional[datetime] = None
    error: Optional[str] = None
