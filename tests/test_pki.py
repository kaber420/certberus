import os
import shutil
import pytest
from devcert.pki import PKIService

@pytest.fixture
def temp_storage(tmp_path):
    storage = tmp_path / "devcert_test"
    storage.mkdir()
    yield str(storage)
    shutil.rmtree(storage)

def test_ca_creation(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    assert pki.create_ca() == True
    assert os.path.exists(pki.ca_path)
    assert os.path.exists(pki.ca_key_path)
    # Second time should return False
    assert pki.create_ca() == False

def test_certificate_signing(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    pki.create_ca()
    
    cert_pem, key_pem = pki.sign_certificate("localhost", ["localhost", "127.0.0.1"])
    
    assert b"BEGIN CERTIFICATE" in cert_pem
    assert b"BEGIN RSA PRIVATE KEY" in key_pem or b"BEGIN PRIVATE KEY" in key_pem
