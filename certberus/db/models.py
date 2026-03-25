from datetime import datetime
from typing import Optional
import uuid
from sqlmodel import Field, SQLModel

class Certificate(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    serial_number: str = Field(index=True, unique=True, description="Hex representation of x509 serial")
    common_name: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    revoke_reason: Optional[str] = None
    fingerprint: str = Field(description="SHA-256 fingerprint of the certificate")
    format: str = Field(default="pem", description="Format emitted (pem or p12)")
    
    # Track the metadata used to create it
    is_ca: bool = Field(default=False)
