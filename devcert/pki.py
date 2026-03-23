import os
import datetime
import stat
from pathlib import Path
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class PKIService:
    def __init__(self, storage_path: Optional[Path] = None):
        if storage_path is None:
            # Follow XDG standards for data storage
            data_home = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            storage_path = data_home / "devcert"
            
        self.storage_path = Path(storage_path)
        self.ca_path = self.storage_path / "rootCA.pem"
        self.ca_key_path = self.storage_path / "rootCA-key.pem"
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        # Ensure storage directory has correct permissions (700)
        self.storage_path.chmod(0o700)

    def _set_secure_permissions(self, path: Path):
        """Set file permissions to 600 (read/write only for owner)."""
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def create_ca(self, force: bool = False, password: Optional[str] = None) -> bool:
        if self.ca_path.exists() and not force:
            return False
            
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "devcert CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "devcert development CA"),
        ])
        
        # Use timezone-aware UTC now (best practice)
        now = datetime.datetime.now(datetime.timezone.utc)
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), 
            critical=True,
        ).sign(key, hashes.SHA256())
        
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
            
        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm,
            ))
        
        self._set_secure_permissions(self.ca_key_path)
            
        with open(self.ca_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        return True

    def sign_certificate(self, common_name: str, alt_names: Optional[List[str]] = None, ca_password: Optional[str] = None) -> Tuple[bytes, bytes]:
        if not self.ca_path.exists() or not self.ca_key_path.exists():
            raise FileNotFoundError("CA not initialized. Run 'init' first.")
            
        with open(self.ca_key_path, "rb") as f:
            ca_key_data = f.read()
            
        ca_password_bytes = ca_password.encode() if ca_password else None
        ca_key = serialization.load_pem_private_key(ca_key_data, password=ca_password_bytes)
            
        with open(self.ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            
        cert_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            cert_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=825)
        )
        
        if alt_names:
            sans = [x509.DNSName(name) for name in alt_names]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(sans),
                critical=False,
            )
            
        cert = builder.sign(ca_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        return cert_pem, key_pem
