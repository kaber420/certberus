import os
import shutil
import pytest
from pathlib import Path
from certberus.pki import PKIService

@pytest.fixture
def temp_storage(tmp_path):
    storage = tmp_path / "certberus_test"
    storage.mkdir()
    yield Path(storage)
    shutil.rmtree(storage)

def test_hierarchy_creation(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    
    # 1. Create Root CA
    assert pki.create_root_ca(password="root-pwd") is not None
    assert pki.root_ca_path.exists()
    
    # 2. Create Intermediate CA
    assert pki.create_intermediate_ca(root_password="root-pwd", inter_password="inter-pwd") is not None
    assert pki.inter_ca_path.exists()

def test_chain_signing(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    pki.create_root_ca(password="root-pwd")
    pki.create_intermediate_ca(root_password="root-pwd", inter_password="inter-pwd")
    
    # 3. Sign Leaf Certificate using Intermediate
    cert, key, x509_cert = pki.sign_certificate("localhost", ca_password="inter-pwd")
    assert b"BEGIN CERTIFICATE" in cert
    assert b"BEGIN RSA PRIVATE KEY" in key or b"BEGIN PRIVATE KEY" in key
    
def test_full_chain_generation(temp_storage):
    pki = PKIService(storage_path=temp_storage)
    pki.create_root_ca()
    pki.create_intermediate_ca()
    
    chain = pki.get_full_chain()
    # Chain should contain two certificates
    assert chain.count(b"BEGIN CERTIFICATE") == 2
