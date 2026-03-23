import os
import shutil
import pytest
import stat
from pathlib import Path
from devcert.pki import PKIService

@pytest.fixture
def temp_storage(tmp_path):
    storage = tmp_path / "devcert_test"
    storage.mkdir()
    yield Path(storage)
    shutil.rmtree(storage)

def test_ca_creation_permissions(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    assert pki.create_ca() == True
    
    # Check directory permissions (700)
    assert (temp_storage.stat().st_mode & 0o777) == 0o700
    # Check CA key permissions (600)
    assert (pki.ca_key_path.stat().st_mode & 0o777) == 0o600

def test_password_protected_ca(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    password = "secret-password"
    assert pki.create_ca(password=password) == True
    
    # Signing without password should fail
    with pytest.raises(Exception):
        pki.sign_certificate("localhost")
        
    # Signing with correct password should work
    cert, key = pki.sign_certificate("localhost", ca_password=password)
    assert b"BEGIN CERTIFICATE" in cert
    assert b"BEGIN RSA PRIVATE KEY" in key or b"BEGIN PRIVATE KEY" in key

def test_leaf_certificate_signing(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    pki.create_ca()
    
    cert_pem, key_pem = pki.sign_certificate("localhost", ["localhost", "127.0.0.1"])
    assert b"BEGIN CERTIFICATE" in cert_pem
    assert b"BEGIN PRIVATE KEY" in key_pem or b"BEGIN RSA PRIVATE KEY" in key_pem
