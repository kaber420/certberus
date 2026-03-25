# Certberus — Próximas Funcionalidades (Fase 3)

> Plan de implementación para PKCS#12, Firma de CSR externo y Endpoint CRL en FastAPI
> Fecha: 2026-03-24

---

## 1. Exportación PKCS#12 (`.p12`) — MikroTik Ready

### El Problema
MikroTik RouterOS acepta importar certificados en dos formatos:
- PEM individual (requiere importar el cert y la llave por separado: dos pasos).
- **PKCS#12 (`.p12`)**: Cert + Llave Privada + Cadena CA en un solo archivo cifrado. Un solo `import`. Mucho más limpio.

### La Solución
Añadir soporte de exportación `.p12` al comando `certberus create`, usando la API nativa de `cryptography`:

```python
from cryptography.hazmat.primitives.serialization import pkcs12

p12_bytes = pkcs12.serialize_key_and_certificates(
    name=common_name.encode(),
    key=private_key,
    cert=leaf_cert,
    cas=[inter_cert, root_cert],   # Cadena de confianza incluida
    encryption_algorithm=pkcs12.PBES2SHA256AndAES256CBC(password.encode())
)
```

### Cambios de Código:
**`certberus/pki.py`**: Añadir `sign_certificate_p12(common_name, alt_names, p12_password)` que retorna `bytes` del p12.

**`certberus/cli.py`**: Extender el comando `create` con flags:
```bash
certberus create router-01 --ip 192.168.10.1 --format p12 --p12-password mikrotik_secret
```

**Nota de Seguridad:** El PKCS#12 tiene la clave privada en su interior, pero está **cifrada con AES-256** usando la contraseña que el usuario provea. Nunca se guarda en disco sin cifrar.

---

## 2. Firma de CSR Externo (`certberus sign`) — Flujo Seguro MikroTik

### El Problema
En el flujo ultra-seguro de PKI empresarial, el dispositivo **genera su propia llave privada** y solo envía al servidor de firmas un CSR (Certificate Signing Request). Esto garantiza que la clave privada **nunca viaja por la red**. MikroTik soporta este flujo nativamente.

### El Flujo:
```
MikroTik                    Certberus
─────────                   ─────────
1. Genera su RSA key pair localmente (nunca sale del router)
2. Genera un CSR → Envía solo el CSR ──→  3. Valida el CSR   
                                           4. Lo firma con CA Intermedia
5. Importa el cert firmado ←── 5. Retorna solo el cert PEM
```

### Cambios de Código:
**`certberus/pki.py`**: Nuevo método `sign_csr(csr_pem_bytes, days=365)` que:
- Valida la estructura del CSR con `x509.load_pem_x509_csr(csr_bytes)`.
- Extrae el Common Name y SANs del CSR original.
- Lo firma con la Intermediate CA.
- Retorna `(cert_pem_bytes, x509_cert)` — **sin llave privada, porque Certberus nunca la conoció**.

**`certberus/cli.py`**: Nuevo comando:
```bash
certberus sign --csr /path/to/device.csr --out /path/to/device.pem --days 365
```

**`certberus/integrations/fastapi.py`**: Nuevo endpoint (habilitado vía `config.toml → sign_csr = true`):
```
POST /api/v1/sign
Content-Type: multipart/form-data
Authorization: Bearer cb_sk_<token>

Body: csr_file (file upload)
Response: { "certificate": "<PEM string>", "serial": "hex" }
```

---

## 3. Endpoint FastAPI `/crl.pem` — Publicación Automática

### El Problema
Para que la revocación funcione de verdad, la CRL debe estar **publicable vía HTTP** en una URL reachable. Windows, iOS, MikroTik y los navegadores consultan periódicamente esa URL (definida dentro del propio certificado como la extensión `CRL Distribution Points`).

### Solución en Dos Partes:

#### A. Endpoint de Descarga Directa
En `certberus/integrations/fastapi.py`, añadir:
```python
@router.get("/crl.pem", response_class=Response)
async def get_crl():
    """Genera y devuelve la CRL firmada como texto PEM."""
    revoked = await db.query_revoked_certs()
    crl_pem = pki.generate_crl(revoked)
    return Response(content=crl_pem, media_type="application/pkix-crl")
```
Habilitado solo si `config.toml → [api.endpoints] crl_publishing = true`.

#### B. CDP (CRL Distribution Point) en los Certificados
Al momento de emitir un certificado, inyectar la URL del servidor como extensión x509 `CRLDistributionPoints`:
```python
crl_uri = f"http://{api_host}:{api_port}/crl.pem"
builder = builder.add_extension(
    x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(crl_uri)],
            relative_name=None, reasons=None, crl_issuer=None
        )
    ]),
    critical=False
)
```
Así los navegadores y MikroTik saben **dónde buscar la CRL** sin configuración manual.

---

## 🗺️ Orden de Implementación Sugerido

| Orden | Tarea | Complejidad | Prioridad |
|-------|-------|------------|-----------|
| 1 | `sign_certificate_p12` en `pki.py` + flags `create --format p12` | Baja | Alta |
| 2 | `sign_csr` en `pki.py` + comando `certberus sign` en CLI | Media | Alta |
| 3 | Endpoint `POST /api/v1/sign` en FastAPI con validación de Token | Alta | Alta |
| 4 | Endpoint `GET /crl.pem` en FastAPI | Baja | Alta |
| 5 | Inyección de CDP en `sign_certificate` / `sign_csr` | Media | Media |
