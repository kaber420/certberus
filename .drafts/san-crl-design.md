# Certberus — Integración de SANs por IP y Listas de Revocación (CRL)

> Documento de diseño arquitectónico y plan de implementación
> Fecha: 2026-03-24

---

## 🏛️ 1. Firmado de IPs en SANs (Subject Alternative Names)

### El Problema
Los Routers MikroTik, antenas Ubiquiti y servidores infraestructurales (on-prem) se gestionan directamente mediante **Direcciones IP** (ej: `https://192.168.88.1`) y no por FQDNs (Nombres de Dominio).
Si emitimos un certificado donde la IP `192.168.88.1` está registrada como un *DNS Nombre* estándar (lo que hace actualmente Certberus v0.1), **Navegadores modernos como Chrome/Edge rechazarán el certificado** por "Name Mismatch", porque el bloque legal para IPs es `x509.IPAddress` y no `x509.DNSName`.

### La Solución Táctica
En `PKIService.sign_certificate()`, cada vez que se reciba un Common Name o una lista de Alternative Names (`alt_names`), evaluaremos semánticamente si el string es una dirección IPv4/IPv6 válida.

**Implementación en Python (`ipaddress` module):**
```python
import ipaddress
from cryptography.x509 import DNSName, IPAddress

sans = []
for name in alt_names:
    try:
        # Si es una IP válida (v4 o v6)...
        ip_obj = ipaddress.ip_address(name)
        sans.append(IPAddress(ip_obj))
    except ValueError:
        # Si arroja ValueError, es un nombre de dominio (DNS)
        sans.append(DNSName(name))
```

**Beneficios inmediatos:**
- `certberus create 10.0.0.1` generará un certificado `IPAddress=10.0.0.1` perfectamente válido para Chrome al conectarte a un equipo en red local.
- Un certificado puede agrupar ambos sin romper la semántica: `certberus create mi-mikrotik --alt 192.168.1.1` inyectará automáticamente un DNS y una IP.

---

## 🚫 2. Listas de Revocación de Certificados (CRL)

### El Problema Escenario
Un técnico se lleva de la empresa su laptop (con un certificado cliente instalado) o el password de un dispositivo MikroTik remoto se vio comprometido. El certificado emitido sigue siendo criptográficamente válido durante sus próximos 3 años, lo cual representa un riesgo de intrusión ("Breach").

El mecanismo estándar que obligan los bancos e ISPs para mitigar esto son las **CRLs**. Una lista periódicamente firmada y descargable que todos los clientes comprueban para saber "si este certificado aún es digno de confianza".

### La Solución Arquitectónica
Dado que ya implementamos **SQLModel** guardando el número de serie de cada certificado, la generación de la CRL pasará de ser un reto imposible a una consulta SQL trivial.

#### A. Nuevo Comando de Revocación
```bash
certberus revoke e59a8c... --reason "keyCompromise"
```
**Efecto:** Busca en la BD SQLite/PostgreSQL el `serial_number`, y actualiza las columnas `revoked_at = NOW()` y `revoke_reason = keyCompromise`.

#### B. Generador de CRL en `PKIService`
El motor criptográfico iterará sobre todos los registros revocados en SQLModel.
```python
builder = x509.CertificateRevocationListBuilder()
builder = builder.issuer_name(inter_ca.subject)
builder = builder.last_update(now)
builder = builder.next_update(now + timedelta(days=7))

# Consultar DB: SELECT * FROM certificate WHERE revoked_at IS NOT NULL
for revoked_cert in db_revoked_certs:
    revoked = x509.RevokedCertificateBuilder().serial_number(
        int(revoked_cert.serial_number, 16)
    ).revocation_date(
        revoked_cert.revoked_at
    ).build()
    builder = builder.add_revoked_certificate(revoked)

# Firmamos la CRL usando la llave privada de la CA Intermedia
crl = builder.sign(inter_ca_key, hashes.SHA256())
```

#### C. Distribución Continua (API Endpoint de FastAPI)
Una vez encendido el API integrado (`config.toml -> [api.endpoints] crl_publishing = true`), FastAPI creará un endpoint automatizado:
`GET /crl.pem`
Dependiendo de qué tan grande sea la BD:
1. Podrá generar la CRL "On The Fly" tras cada petición (útil localmente).
2. Podrá servir un caché generado cada 12 horas por un worker (para ISPs grandes con 50,000 nodos solicitándolo).

*(Nota: MikroTik soporta nativamente consultar una URL HTTP para la CRL, que integrará Certberus directamente a tu infraestructura).*

---

## 🗺️ Orden de Fuego Sugerido:
1. Alterar `PKIService.sign_certificate` para atrapar y clasificar `DNSName` e `IPAddress`. (Rápido, 10 minutos).
2. Crear comando CLI `revoke <serial>` para que haga el UPDATE en la Base de Datos.
3. Crear el método criptográfico en `PKIService` para instanciar el archivo estático `crl.pem`.
4. Extender la API FastAPI para devolver estáticamente ese `/crl.pem`.
