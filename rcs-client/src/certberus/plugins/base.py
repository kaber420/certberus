import abc
import logging

logger = logging.getLogger(__name__)

class CertberusPlugin(abc.ABC):
    """
    Base class for all Certberus extensions.
    Plugins can hook into various lifecycle events of the PKI engine.
    """
    def __init__(self, pki_service, config):
        self.pki = pki_service
        self.config = config
        self.enabled = config.get("enabled", False)

    @abc.abstractmethod
    def name(self) -> str:
        """Unique identifier for the plugin (e.g., 'yuxi_blockchain')."""
        return ""

    def on_init(self) -> None:
        """Called during PKIService.__init__."""
        pass

    def post_issue(self, cert_obj, cert_pem: bytes, **kwargs) -> None:
        """Called after a leaf certificate is signed."""
        pass

    def pre_sign(self, common_name: str, **kwargs) -> None:
        """Called before signing to perform additional validation."""
        pass

    def on_revoke(self, serial_number: str, **kwargs) -> None:
        """Called when a certificate is revoked."""
        pass
