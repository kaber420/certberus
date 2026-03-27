import os
import datetime
import stat
import ipaddress
from pathlib import Path
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa

class SecurityPolicyViolation(Exception):
    pass

class PKIService:
    def __init__(self, storage_path: Optional[Path] = None, config: Optional[dict] = None):
        from .config import load_config
        import logging
        self.config = config or load_config()
        self.logger = logging.getLogger(__name__)
        
        if storage_path is None:
            storage_path = Path(self.config["core"]["storage_path"])
        
        self.storage_path = Path(storage_path)
        self.root_ca_path = self.storage_path / "rootCA.pem"
        self.root_ca_key_path = self.storage_path / "rootCA-key.pem"
        self.inter_ca_path = self.storage_path / "intermediateCA.pem"
        self.inter_ca_key_path = self.storage_path / "intermediateCA-key.pem"
        self.intermediates_path = self.storage_path / "intermediates"
        
        # Legacy compatibility for initial requests if needed
        self.ca_path = self.root_ca_path
        self.ca_key_path = self.root_ca_key_path
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.storage_path.chmod(0o700)
        self.intermediates_path.mkdir(parents=True, exist_ok=True)
        self.intermediates_path.chmod(0o700)

        self.plugins = []
        self._load_plugins()

    def _load_plugins(self):
        plugin_configs = self.config.get("plugins", {})
        for name, cfg in plugin_configs.items():
            if cfg.get("enabled", False):
                try:
                    import importlib
                    module_path = f"certberus.plugins.{name}"
                    module = importlib.import_module(module_path)
                    plugin_class = getattr(module, "Plugin")
                    instance = plugin_class(self, cfg)
                    self.plugins.append(instance)
                    instance.on_init()
                    self.logger.info(f"Loaded plugin: {name}")
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {name}: {e}")

    def trigger_hook(self, method_name: str, **kwargs):
        """Trigger a hook on all enabled plugins."""
        for plugin in self.plugins:
            if hasattr(plugin, method_name):
                try:
                    getattr(plugin, method_name)(**kwargs)
                except Exception as e:
                    self.logger.error(f"Error in plugin {plugin.name()} - {method_name}: {e}")

    def get_authority_paths(self, name: Optional[str]) -> Tuple[Path, Path]:
        slug = name if name and name != "default" else "default"
        cert_path = self.intermediates_path / f"{slug}.pem"
        if slug == "default" and not cert_path.exists() and self.inter_ca_path.exists():
            return self.inter_ca_path, self.inter_ca_key_path
        return cert_path, self.intermediates_path / f"{slug}-key.pem"

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

    def generate_intermediate_csr(
        self,
        name: str = "default",
        country: str = "US",
        org_name: str = "RCS Federated CA",
        common_name: str = "Sovereign Intermediate Authority",
        key_size: int = 2048,
    ) -> Tuple[bytes, bytes]:
        """[RCS EXTENSION] Generates a private key and a CSR to be signed by a Community Root."""
        _, key_path = self.get_authority_paths(name)
        
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        )
        
        extensions = [
            x509.Extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True
            )
        ]
        
        csr = csr_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).sign(key, hashes.SHA256())
        
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        self._set_secure_permissions(key_path)
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()), csr.public_bytes(serialization.Encoding.PEM)

    def activate_intermediate_ca(self, name: str, signed_cert_pem: bytes, root_chain_pem: Optional[bytes] = None):
        """[RCS EXTENSION] Activates an intermediate CA using an external signature."""
        cert_path, _ = self.get_authority_paths(name)
        _, key_path = self.get_authority_paths(name)
        if not key_path.exists():
            raise FileNotFoundError(f"Private key for '{name}' not found.")
            
        with open(cert_path, "wb") as f:
            f.write(signed_cert_pem)
        if root_chain_pem:
            with open(self.root_ca_path, "wb") as f:
                f.write(root_chain_pem)
        return True

    def create_intermediate_ca(
        self,
        name: str = "default",
        root_password: Optional[str] = None,
        inter_password: Optional[str] = None,
        force: bool = False,
        permitted_domains: Optional[List[str]] = None,
        permitted_ips: Optional[List[str]] = None,
        valid_days: int = 3650,
        parent_ca_name: Optional[str] = None,
    ) -> Optional[x509.Certificate]:
        """[BASE FEATURE] Creates an intermediate CA signed by the LOCAL Root CA."""
        cert_path, key_path = self.get_authority_paths(name)
        if cert_path.exists() and not force:
            return None
            
        root_password_bytes = root_password.encode() if root_password else None
        
        if parent_ca_name:
            # Level 3 Sub-CA: Validating signed by Level 2 Intermediate
            parent_cert_path, parent_key_path = self.get_authority_paths(parent_ca_name)
            with open(parent_key_path, "rb") as f:
                parent_key = serialization.load_pem_private_key(f.read(), password=root_password_bytes)
            with open(parent_cert_path, "rb") as f:
                parent_cert = x509.load_pem_x509_certificate(f.read())
        else:
            # Level 2 Intermediate: Validating signed by Level 1 Root
            if not self.root_ca_path.exists() or not self.root_ca_key_path.exists():
                raise FileNotFoundError("Root CA not found. Run create_root_ca first.")
            with open(self.root_ca_key_path, "rb") as f:
                parent_key = serialization.load_pem_private_key(f.read(), password=root_password_bytes)
            with open(self.root_ca_path, "rb") as f:
                parent_cert = x509.load_pem_x509_certificate(f.read())

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
            parent_cert.subject
        ).public_key(
            inter_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + datetime.timedelta(days=valid_days)
        )
        
        # Level 2 CAs have a path_length of 1 (can sign Level 3 CAs). Level 3 CAs have a path_length of 0 (can only sign leaves).
        path_len = 0 if parent_ca_name else 1
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True,
        )
        builder = builder.add_extension(
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
        
        permitted_subtrees = []
        if permitted_domains:
            for d in permitted_domains:
                if d.startswith("*."):
                    d = d[2:]
                permitted_subtrees.append(x509.DNSName(d))
        if permitted_ips:
            for ip in permitted_ips:
                try:
                    network = ipaddress.ip_network(ip)
                    permitted_subtrees.append(x509.IPAddress(network))
                except ValueError:
                    try:
                        addr = ipaddress.ip_address(ip)
                        permitted_subtrees.append(x509.IPAddress(ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}")))
                    except ValueError:
                        pass
        
        if permitted_subtrees:
            builder = builder.add_extension(
                x509.NameConstraints(permitted_subtrees=permitted_subtrees, excluded_subtrees=None),
                critical=True,
            )

        inter_cert = builder.sign(parent_key, hashes.SHA256())
        
        encryption = serialization.BestAvailableEncryption(inter_password.encode()) if inter_password else serialization.NoEncryption()
        with open(key_path, "wb") as f:
            f.write(inter_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, encryption))
        with open(cert_path, "wb") as f:
            f.write(inter_cert.public_bytes(serialization.Encoding.PEM))
            if parent_ca_name:
                with open(parent_cert_path, "rb") as pf:
                    f.write(pf.read())
        return inter_cert

    def validate_names(self, common_name: str, alt_names: Optional[List[str]] = None, ca_cert: Optional[x509.Certificate] = None):
        """Validates that common_name and alt_names are within allowed domains/IPs."""
        names_to_check = [str(common_name)]
        if alt_names:
            names_to_check.extend([str(a) for a in alt_names])
            
        if ca_cert:
            try:
                nc_ext = ca_cert.extensions.get_extension_for_class(x509.NameConstraints)
                nc = nc_ext.value
                
                def match_domain(name: str, constraint: str):
                    if constraint.startswith("."):
                        return name.endswith(constraint) or name == constraint[1:]
                    elif constraint.startswith("*."):
                        suffix = constraint[1:]
                        return name.endswith(suffix) or name == constraint[2:]
                    return name == constraint or name.endswith("." + constraint)

                if nc.permitted_subtrees:
                    for name in names_to_check:
                        is_ip = False
                        try:
                            ip_obj = ipaddress.ip_address(name)
                            is_ip = True
                        except ValueError:
                            pass
                            
                        allowed = False
                        for subtree in nc.permitted_subtrees:
                            if is_ip and isinstance(subtree, x509.IPAddress):
                                if ip_obj in subtree.value:
                                    allowed = True
                                    break
                            elif not is_ip and isinstance(subtree, x509.DNSName):
                                if match_domain(name, subtree.value):
                                    allowed = True
                                    break
                        if not allowed:
                            raise SecurityPolicyViolation(f"Name '{name}' is not permitted by CA Name Constraints.")
            except x509.ExtensionNotFound:
                pass

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
                    elif allowed_domain.startswith("."):
                        if name.endswith(allowed_domain) or name == allowed_domain[1:]:
                            return True
                    elif name == allowed_domain:
                        return True
                return False

        for name in names_to_check:
            if not is_allowed(name):
                raise SecurityPolicyViolation(f"Name '{name}' is not allowed by software security policy.")

    def sign_certificate(self, common_name: str, alt_names: Optional[List[str]] = None, ca_password: Optional[str] = None, profile: str = "router", authority_name: Optional[str] = None) -> Tuple[bytes, bytes, x509.Certificate]:
        ca_cert_path, ca_key_path = self.get_authority_paths(authority_name)
        if not ca_cert_path.exists() or not ca_key_path.exists():
            raise FileNotFoundError(f"Intermediate CA '{authority_name or 'default'}' not found.")
            
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_password.encode() if ca_password else None)
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Validate names before signing
        self.validate_names(common_name, alt_names, ca_cert=ca_cert)
            
        # Plugin Hook: Pre-sign validation
        self.trigger_hook("pre_sign", common_name=common_name, alt_names=alt_names, authority_name=authority_name)
            
        cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        
        api_cfg = self.config.get("api", {})
        host = api_cfg.get("host", "127.0.0.1")
        port = api_cfg.get("port", 8443)
        base_url = f"http://{host}:{port}"
        
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
        
        crl_name = f"crl_{authority_name}.pem" if authority_name and authority_name != "default" else "crl.pem"
        
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(f"{base_url}/{crl_name}")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]), 
            critical=False
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(f"{base_url}/ocsp")),
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(f"{base_url}/ca.pem")),
            ]),
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
        
        # Plugin Hook: Post-issuance processing
        self.trigger_hook("post_issue", cert_obj=cert, cert_pem=cert.public_bytes(serialization.Encoding.PEM))
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = cert_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        return cert_pem, key_pem, cert

    def sign_csr(self, csr_pem: str, ca_password: Optional[str] = None, profile: str = "router", authority_name: Optional[str] = None) -> Tuple[bytes, x509.Certificate]:
        """Signs an existing CSR using the Intermediate CA."""
        ca_cert_path, ca_key_path = self.get_authority_paths(authority_name)
        if not ca_cert_path.exists() or not ca_key_path.exists():
            raise FileNotFoundError(f"Intermediate CA '{authority_name or 'default'}' not found.")
            
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=ca_password.encode() if ca_password else None)
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
            
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        
        # Validate names from CSR
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else ""
        sans = []
        try:
            ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            raw_sans = ext.value.get_values_for_type(x509.DNSName) + ext.value.get_values_for_type(x509.IPAddress)
            sans = [str(s) for s in raw_sans]
        except x509.ExtensionNotFound:
            pass
            
        self.validate_names(cn, sans, ca_cert=ca_cert)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        
        api_cfg = self.config.get("api", {})
        host = api_cfg.get("host", "127.0.0.1")
        port = api_cfg.get("port", 8443)
        base_url = f"http://{host}:{port}"
        
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
        
        crl_name = f"crl_{authority_name}.pem" if authority_name and authority_name != "default" else "crl.pem"
        
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(f"{base_url}/{crl_name}")],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            ]), 
            critical=False
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(f"{base_url}/ocsp")),
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(f"{base_url}/ca.pem")),
            ]),
            critical=False
        )
        
        # Copy extensions from CSR if needed (SAN is already handled by our builder if we wanted to be strict)
        # But for MikroTik, we'll carry over what's in the CSR if it's safe
        for ext in csr.extensions:
            if isinstance(ext.value, x509.SubjectAlternativeName):
                builder = builder.add_extension(ext.value, critical=ext.critical)
                
        # Plugin Hook: Pre-sign validation for CSR
        self.trigger_hook("pre_sign", common_name=csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, authority_name=authority_name)

        cert = builder.sign(ca_key, hashes.SHA256())

        # Plugin Hook: Post-issuance for CSR
        self.trigger_hook("post_issue", cert_obj=cert, cert_pem=cert.public_bytes(serialization.Encoding.PEM))

        return cert.public_bytes(serialization.Encoding.PEM), cert

    def get_full_chain(self, authority_name: Optional[str] = None) -> bytes:
        """Combine Root and Intermediate CA for the trust chain."""
        ca_cert_path, _ = self.get_authority_paths(authority_name)
        with open(self.root_ca_path, "rb") as f:
            root = f.read()
        with open(ca_cert_path, "rb") as f:
            inter = f.read()
        return inter + root

    def export_p12(self, cert_pem: bytes, key_pem: bytes, friendly_name: str, password: str = "", authority_name: Optional[str] = None) -> bytes:
        """Export a certificate and its private key as a PKCS#12 container."""
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
        
        ca_cert_path, _ = self.get_authority_paths(authority_name)
        with open(ca_cert_path, "rb") as f:
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

    def generate_crl(self, revoked_certs_meta: List[dict], ca_password: Optional[str] = None, days: int = 7, authority_name: Optional[str] = None) -> bytes:
        """Generate a signed CRL from a list of revoked cert metadata dicts.
        Each dict must have: 'serial_number' (hex str) and 'revoked_at' (datetime).
        """
        ca_cert_path, ca_key_path = self.get_authority_paths(authority_name)
        if not ca_cert_path.exists() or not ca_key_path.exists():
            raise FileNotFoundError(f"Intermediate CA '{authority_name or 'default'}' not found.")

        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=ca_password.encode() if ca_password else None
            )
        with open(ca_cert_path, "rb") as f:
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
