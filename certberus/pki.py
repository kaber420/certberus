import os
import datetime
import stat
import ipaddress
from pathlib import Path
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class PKIService:
    def __init__(self, storage_path: Optional[Path] = None):
        if storage_path is None:
            data_home = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            storage_path = data_home / "certberus"
            
        self.storage_path = Path(storage_path)
        self.root_ca_path = self.storage_path / "rootCA.pem"
        self.root_ca_key_path = self.storage_path / "rootCA-key.pem"
        self.inter_ca_path = self.storage_path / "intermediateCA.pem"
        self.inter_ca_key_path = self.storage_path / "intermediateCA-key.pem"
        
        # Legacy compatibility for initial requests if needed
        self.ca_path = self.root_ca_path
        self.ca_key_path = self.root_ca_key_path
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.storage_path.chmod(0o700)

    def _set_secure_permissions(self, path: Path):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def create_root_ca(self, force: bool = False, password: Optional[str] = None) -> Optional[x509.Certificate]:
        if self.root_ca_path.exists() and not force:
            return None
            
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "certberus Root CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "certberus Master Trust Anchor"),
        ])
        
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
            now + datetime.timedelta(days=7300) # 20 years for root
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), 
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(key, hashes.SHA256())
        
        encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
            
        with open(self.root_ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            ))
        self._set_secure_permissions(self.root_ca_key_path)
            
        with open(self.root_ca_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        return cert

    def create_intermediate_ca(self, root_password: Optional[str] = None, inter_password: Optional[str] = None, force: bool = False) -> Optional[x509.Certificate]:
        if self.inter_ca_path.exists() and not force:
            return None
            
        if not self.root_ca_path.exists():
            raise FileNotFoundError("Root CA not found. Run create_root_ca first.")

        # Load Root CA
        with open(self.root_ca_key_path, "rb") as f:
            root_key = serialization.load_pem_private_key(f.read(), password=root_password.encode() if root_password else None)
        with open(self.root_ca_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        # Generate Intermediate Key
        inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "certberus Intermediate CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "certberus Signing CA"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            root_cert.subject
        ).public_key(
            inter_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=3650) # 10 years for intermediate
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), # path_length 0: it can't sign other CAs
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        
        inter_cert = builder.sign(root_key, hashes.SHA256())
        
        encryption = serialization.BestAvailableEncryption(inter_password.encode()) if inter_password else serialization.NoEncryption()

        with open(self.inter_ca_key_path, "wb") as f:
            f.write(inter_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            ))
        self._set_secure_permissions(self.inter_ca_key_path)
            
        with open(self.inter_ca_path, "wb") as f:
            f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
            
        return inter_cert

    def sign_certificate(self, common_name: str, alt_names: Optional[List[str]] = None, ca_password: Optional[str] = None) -> Tuple[bytes, bytes, x509.Certificate]:
        # Always use Intermediate CA for signing
        if not self.inter_ca_path.exists() or not self.inter_ca_key_path.exists():
            raise FileNotFoundError("Intermediate CA not found. Run init first.")
            
        with open(self.inter_ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_password.encode() if ca_password else None)
        with open(self.inter_ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            
        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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
            sans = []
            for name in alt_names:
                try:
                    ip_obj = ipaddress.ip_address(name)
                    sans.append(x509.IPAddress(ip_obj))
                except ValueError:
                    sans.append(x509.DNSName(name))
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
            
        cert = builder.sign(ca_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        return cert_pem, key_pem, cert

    def get_full_chain(self) -> bytes:
        """Combine Root and Intermediate CA for the trust chain."""
        with open(self.root_ca_path, "rb") as f:
            root = f.read()
        with open(self.inter_ca_path, "rb") as f:
            inter = f.read()
        return inter + root

    def generate_crl(self, revoked_certs_meta: List[dict], ca_password: Optional[str] = None, days: int = 7) -> bytes:
        """Generate a signed CRL from a list of revoked cert metadata dicts.
        Each dict must have: 'serial_number' (hex str) and 'revoked_at' (datetime).
        """
        if not self.inter_ca_path.exists() or not self.inter_ca_key_path.exists():
            raise FileNotFoundError("Intermediate CA not found. Run init first.")

        with open(self.inter_ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=ca_password.encode() if ca_password else None
            )
        with open(self.inter_ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(ca_cert.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=days))
        )

        for meta in revoked_certs_meta:
            serial_int = int(meta["serial_number"], 16)
            revoked_at = meta["revoked_at"]
            # Ensure timezone-aware
            if revoked_at.tzinfo is None:
                revoked_at = revoked_at.replace(tzinfo=datetime.timezone.utc)

            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial_int)
                .revocation_date(revoked_at)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)

        crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM)
