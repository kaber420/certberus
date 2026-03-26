import os
import shutil
import unittest
import tempfile
from pathlib import Path
from certberus.pki import PKIService
from certberus.config import get_default_config
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12

class TestUniversalPKI(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="certberus_test_univ_")
        self.temp_storage = Path(self.test_dir)
        self.config = get_default_config()
        self.config["security"]["allowed_domains"] = []
        self.config["security"]["allowed_ips"] = []
        self.pki = PKIService(storage_path=self.temp_storage, config=self.config)
        self.pki.create_root_ca()
        self.pki.create_intermediate_ca()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_iot_profile_certificate(self):
        cert_pem, key_pem, cert_obj = self.pki.sign_certificate("device1.omniwisp.router", profile="iot")
        
        validity = (cert_obj.not_valid_after_utc - cert_obj.not_valid_before_utc)
        self.assertTrue(89 <= validity.days <= 91)
        
        eku = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
        self.assertEqual(len(eku), 1)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, eku)

    def test_router_profile_certificate(self):
        cert_pem, key_pem, cert_obj = self.pki.sign_certificate("router1.omniwisp.router", profile="router")
        
        validity = (cert_obj.not_valid_after_utc - cert_obj.not_valid_before_utc)
        self.assertTrue(824 <= validity.days <= 826)
        
        eku = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
        self.assertEqual(len(eku), 2)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, eku)
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, eku)

    def test_p12_export(self):
        cert_pem, key_pem, cert_obj = self.pki.sign_certificate("legacy_server")
        p12_bytes = self.pki.export_p12(cert_pem, key_pem, "legacy_server", "testpassword")
        
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_bytes, b"testpassword"
        )
        
        self.assertIsNotNone(certificate)
        self.assertIsNotNone(private_key)
        self.assertEqual(len(additional_certificates), 2)

if __name__ == "__main__":
    unittest.main()
