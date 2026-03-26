import os
import datetime
import stat
import ipaddress
from pathlib import Path
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa

class PKIService:
    def __init__(self, storage_path: Optional[Path] = None, config: Optional[dict] = None):
        from .config import load_config
        self.config = config or load_config()
        
        if storage_path is None:
            storage_path = Path(self.config["core"]["storage_path"])
            
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

    def reload_config(self, new_config: dict):
        """Update PKIService configuration in memory (hot-reload)."""
        self.config = new_config

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
        
        # Name Constraints: The "Double Filter" (Criptographic restriction)
        # Allows restricting the CA to only sign specific domains/IPs
        security_cfg = self.config.get("security", {})
        permitted_domains = security_cfg.get("allowed_domains", [])
        permitted_ips = security_cfg.get("allowed_ips", [])
        
        subtrees = []
        if permitted_domains:
            for d in permitted_domains:
                if d.strip():
                    subtrees.append(x509.DNSName(d.strip()))
        
        if permitted_ips:
            for ip in permitted_ips:
                if ip.strip():
                    try:
                        # Handle both single IPs and networks
                        if "/" in ip:
                            network = ipaddress.ip_network(ip.strip())
                            subtrees.append(x509.IPAddress(network))
                        else:
                            # For NameConstraints, we MUST use a network object (e.g. /32)
                            addr = ipaddress.ip_address(ip.strip())
                            network = ipaddress.ip_network(f"{addr}/{32 if addr.version == 4 else 128}")
                            subtrees.append(x509.IPAddress(network))
                    except ValueError:
                        continue
        
        if subtrees:
            builder = builder.add_extension(
                x509.NameConstraints(permitted_subtrees=subtrees, excluded_subtrees=None),
                critical=True
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

    def validate_names(self, common_name: str, alt_names: Optional[List[str]] = None):
        """Validates that common_name and alt_names are within allowed domains/IPs."""
        security_cfg = self.config.get("security", {})
        allowed_domains = security_cfg.get("allowed_domains", [])
        allowed_ips = security_cfg.get("allowed_ips", [])
        
        # If no restrictions are set, allow all (for dev/testing)
        if not allowed_domains and not allowed_ips:
            return
            
        def is_allowed(name: str):
            # Check if it's an IP
            try:
                ip_obj = ipaddress.ip_address(name)
                for allowed_ip in allowed_ips:
                    try:
                        if "/" in allowed_ip:
                            if ip_obj in ipaddress.ip_network(allowed_ip):
                                return True
                        elif ip_obj == ipaddress.ip_address(allowed_ip):
                            return True
                    except ValueError:
                        continue
                return False
            except ValueError:
                # Check if it's a domain
                for allowed_domain in allowed_domains:
                    if allowed_domain.startswith("*."):
                        suffix = allowed_domain[1:]
                        if name.endswith(suffix) or name == allowed_domain[2:]:
                            return True
                    elif name == allowed_domain:
                        return True
                return False

        if not is_allowed(common_name):
            raise ValueError(f"Common Name '{common_name}' is not allowed by security policy.")
            
        if alt_names:
            for alt in alt_names:
                if not is_allowed(alt):
                    raise ValueError(f"Alternative Name '{alt}' is not allowed by security policy.")

    def sign_certificate(self, common_name: str, alt_names: Optional[List[str]] = None, ca_password: Optional[str] = None, profile: str = "router") -> Tuple[bytes, bytes, x509.Certificate]:
        # Software Filter: Validate names before signing
        self.validate_names(common_name, alt_names)
        
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
        
        eku = [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH] if profile == "iot" else [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
        valid_days = 90 if profile == "iot" else 825
        
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
            now + datetime.timedelta(days=valid_days)
        ).add_extension(
            x509.ExtendedKeyUsage(eku),
            critical=False
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

    def sign_csr(self, csr_pem: str, ca_password: Optional[str] = None, profile: str = "router") -> Tuple[bytes, x509.Certificate]:
        """Signs an existing CSR using the Intermediate CA."""
        if not self.inter_ca_path.exists() or not self.inter_ca_key_path.exists():
            raise FileNotFoundError("Intermediate CA not found. Run init first.")
            
        with open(self.inter_ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_password.encode() if ca_password else None)
        with open(self.inter_ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        
        # Validate names from CSR
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        sans = []
        try:
            ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName) + ext.value.get_values_for_type(x509.IPAddress)
        except x509.ExtensionNotFound:
            pass
            
        self.validate_names(cn, sans)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        eku = [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH] if profile == "iot" else [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
        valid_days = 90 if profile == "iot" else 825
        
        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=valid_days)
        ).add_extension(
            x509.ExtendedKeyUsage(eku),
            critical=False
        )
        
        # Copy extensions from CSR if needed (SAN is already handled by our builder if we wanted to be strict)
        # But for MikroTik, we'll carry over what's in the CSR if it's safe
        for ext in csr.extensions:
            if isinstance(ext.value, x509.SubjectAlternativeName):
                builder = builder.add_extension(ext.value, critical=ext.critical)
                
        cert = builder.sign(ca_key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM), cert

    def get_full_chain(self) -> bytes:
        """Combine Root and Intermediate CA for the trust chain."""
        with open(self.root_ca_path, "rb") as f:
            root = f.read()
        with open(self.inter_ca_path, "rb") as f:
            inter = f.read()
        return inter + root

    def export_p12(self, cert_pem: bytes, key_pem: bytes, friendly_name: str, password: str = "") -> bytes:
        """Export a certificate and its private key as a PKCS#12 container."""
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
        
        with open(self.inter_ca_path, "rb") as f:
            inter_cert = x509.load_pem_x509_certificate(f.read())
        with open(self.root_ca_path, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())
            
        encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
        
        p12 = pkcs12.serialize_key_and_certificates(
            friendly_name.encode('utf-8'),
            key,
            cert,
            [inter_cert, root_cert],
            encryption
        )
        return p12

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
