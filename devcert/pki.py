import os
import datetime
from typing import List, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class PKIService:
    def __init__(self, storage_path: str = None):
        if storage_path is None:
            storage_path = os.path.expanduser("~/.local/share/devcert")
        self.storage_path = storage_path
        self.ca_path = os.path.join(self.storage_path, "rootCA.pem")
        self.ca_key_path = os.path.join(self.storage_path, "rootCA-key.pem")
        
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path, exist_ok=True)

    def create_ca(self, force: bool = False) -> bool:
        if os.path.exists(self.ca_path) and not force:
            return False
            
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "devcert CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "devcert development CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), 
            critical=True,
        ).sign(key, hashes.SHA256())
        
        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            
        with open(self.ca_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        return True

    def sign_certificate(self, common_name: str, alt_names: List[str] = None) -> tuple:
        if not os.path.exists(self.ca_path) or not os.path.exists(self.ca_key_path):
            raise FileNotFoundError("CA not initialized. Run 'init' first.")
            
        with open(self.ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
        with open(self.ca_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            
        cert_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            cert_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=825)
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
