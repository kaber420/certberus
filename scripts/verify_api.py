import requests
import time
import subprocess
import os
import sys
import base64
from cryptography import x509

# Configuration
API_URL = "http://127.0.0.1:8443/_certberus"
TOKEN = "dev_token_123"
HEADERS = {"X-Certberus-Token": TOKEN}

def test_api_flow():
    print("🚀 Iniciando prueba de flujo API E2E...")
    
    # 1. Test CA Download
    print("📡 Probando descarga de CA...")
    resp = requests.get(f"{API_URL}/ca.pem")
    if resp.status_code == 200:
        print("✅ CA descargada correctamente.")
    else:
        print(f"❌ Error al descargar CA: {resp.status_code} - {resp.text}")
        return

    # 2. Test Issue Certificate (IoT Profile)
    print("📡 Solicitando certificado IoT (Vida corta & ClientAuth)...")
    payload = {
        "common_name": "iot-sensor-01.local",
        "profile": "iot"
    }
    resp = requests.post(f"{API_URL}/issue", json=payload, headers=HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        cert_text = data["certificate"]
        cert = x509.load_pem_x509_certificate(cert_text.encode())
        
        # Verify validity (~90 days)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        print(f"✅ Certificado IoT recibido. Validez: {delta.days} días.")
        
        # Verify EKU
        eku = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE).value
        if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku and len(eku) == 1:
            print("✅ Restricción EKU (IoT) verificada correctamente.")
        else:
            print("❌ Error: EKU incorrecto para perfil IoT.")
    else:
        print(f"❌ Error al emitir certificado IoT: {resp.status_code} - {resp.text}")

    # 3. Test Issue P12 (Legacy Format)
    print("📡 Solicitando certificado en formato PKCS#12 (.p12)...")
    payload = {
        "common_name": "legacy-app-01.local",
        "format": "p12",
        "p12_password": "exportpassword"
    }
    resp = requests.post(f"{API_URL}/issue", json=payload, headers=HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        if "certificate_p12_base64" in data:
            print("✅ Contenedor P12 recibido correctamente (Base64).")
        else:
            print("❌ Error: P12 no encontrado en la respuesta.")
    else:
        print(f"❌ Error al emitir P12: {resp.status_code} - {resp.text}")

    print("\n✨ Flujo API verificado exitosamente.")

if __name__ == "__main__":
    test_api_flow()
