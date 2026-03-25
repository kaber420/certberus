# Certberus — Roadmap de Funcionalidades

> Análisis de las recomendaciones de la comunidad y decisiones de implementación.
> Fecha: 2026-03-24

---

## ✅ Funcionalidades a Implementar (Prioridad Alta)

### 1. SANs con soporte IP + FQDN (Ya parcial, mejorar)
**Estado actual:** `sign_certificate` solo soporta `DNSName`.  
**Acción:** Agregar soporte explícito para `IPAddress` en los SANs del método `sign_certificate` y en el CLI.  
**Por qué:** Crítico para dispositivos MikroTik y endpoints internos que se identifican por IP de gestión.  
```
certberus create router-01 --ip 192.168.10.1 --dns router-01.omniwisp.local
```

---

### 2. Firma de CSR externo (Flujo MikroTik / CSR Pull)
**Estado actual:** No existe.  
**Acción:** Nuevo método en `PKIService`:
```python
def sign_csr(self, csr_pem: bytes, days: int = 365) -> bytes
```
Y nuevo comando CLI:
```
certberus sign --csr /path/to/device.csr --out /path/to/device.pem
```
**Por qué:** MikroTik genera sus propios CSRs. Certberus firma y devuelve únicamente el certificado, sin entregar la clave privada (más seguro).

---

### 3. Exportación PKCS#12 / `.p12`
**Estado actual:** Solo exporta PEM.  
**Acción:** Nuevo método y flag CLI:
```
certberus create nodo-01 --format p12 --p12-password secret
```
**Por qué:** MikroTik acepta `.p12` nativamente. Empaquetar llave + cert + cadena en un solo archivo cifrado simplifica el proceso de despliegue.

---

### 4. CRL — Lista de Revocación de Certificados
**Estado actual:** No existe (`crl_sign=True` en la CA es solo el permiso, falta la implementación).  
**Acción:**
- Mantener un `crl.db` local (SQLite o JSON) con los seriales de certificados emitidos y revocados.
- Generar y firmar un archivo `crl.pem` estándar x509.
- Comando: `certberus revoke --serial <serial>` y `certberus crl --export`.

**Por qué:** Fundamental para entorno ISP real. Si un técnico se va, puedes revocar su certificado de acceso. Sin CRL, la revocación es imposible.

---

## 🧪 Funcionalidades a Evaluar (Prioridad Media)

### 5. CertberusEngine — Refactor como librería
**Estado actual:** `PKIService` funciona bien como clase, pero tiene acoplamiento a paths del filesystem.  
**Acción:** Separar `CertberusEngine` (pura lógica criptográfica, sin I/O) de `PKIService` (que maneja storage).  
**Por qué:** Permite embeberse como librería en OmniWISP u otros proyectos sin dependencias de disco. El módulo de FastAPI ya usa `PKIService` directamente y se beneficiaría.

---

### 6. Certificados Efímeros / Zero Trust
**Concepto:** Certificados de corta duración (ej. 24h–7 días) firmados por nombre de servicio en lugar de IP.  
**Acción:** Flag `--ttl` en el comando `create`:
```
certberus create worker-node-03 --ttl 24h
```
**Por qué:** Útil para microservicios y pipelines CI/CD, no para dispositivos MikroTik (que necesitan certs de larga duración).  
**Decisión sugerida:** Implementar junto o después del refactor del Engine.

---

### 7. Extensiones X.509 personalizadas (Roles/Metadatos)
**Concepto:** Incluir roles como `admin`, `tecnico`, `readonly` en el certificado como OID custom.  
**Acción:** Agregar un campo `--role` opcional al cert que se inyecte como extensión no crítica.  
**Por qué:** Base de una arquitectura Zero Trust real. Los servicios pueden leer el rol del cert sin consultar una BD centralizada.  
**Decisión sugerida:** Evaluar tras tener CRL y PKCS#12 estables. Es la "joya de la corona" arquitectural.

---

## 🗃 Base de Datos Propia — Arquitectura Pluggable

> **Decisión clave:** Certberus tiene su propia BD. No depende de OmniWISP ni de ningún proyecto externo.
> OmniWISP puede *conectarse a la BD de Certberus* como integración opcional, no al revés.

### ORM: SQLModel (SQLAlchemy + Pydantic)

Se usa **SQLModel** como capa única de modelos y base de datos. No se necesita una clase abstracta manual — SQLAlchemy (bajo SQLModel) maneja los backends con el mismo código.

```
certberus/
  db/
    models.py        # SQLModel: Certificate, RevocationEntry
    session.py       # get_session() async, lee CERTBERUS_DB_URL
    migrations.py    # SQLModel.metadata.create_all() en init
```

**Dependencias:**
```toml
[project.optional-dependencies]
db = ["sqlmodel>=0.0.18", "aiosqlite>=0.19"]
db-postgres = ["sqlmodel>=0.0.18", "asyncpg>=0.29"]
```

**Tabla principal `certificates`:**
| Campo | Tipo | Descripción |
|-------|------|-------------|
| `id` | UUID | PK |
| `serial_number` | TEXT | Serial x509 en hex |
| `common_name` | TEXT | CN del certificado |
| `issued_at` | TIMESTAMP | Fecha de emisión |
| `expires_at` | TIMESTAMP | Fecha de expiración |
| `revoked_at` | TIMESTAMP | NULL = activo |
| `revoke_reason` | TEXT | Razón de revocación |
| `format` | TEXT | `pem`, `p12` |
| `fingerprint` | TEXT | SHA-256 del cert |

**Configuración del backend** vía `pyproject.toml` local o variable de entorno:
```bash
# SQLite (default, sin configuración)
certberus init

# PostgreSQL (infraestructura grande / OmniWISP)
export CERTBERUS_DB_URL="postgresql+asyncpg://user:pass@host/certberus"
certberus init
```

El código usa la misma interfaz abstraída — el CLI y el motor no diferencian el backend.

---

## 🔌 Compatibilidad / Interoperabilidad (Futuro)

### mkcert como backend alternativo
- Certberus puede detectar si `mkcert` está instalado y usarlo para instalar la CA en el sistema.
- `certberus install --via mkcert` (delegado) vs `certberus install` (nativo).

### step-ca como backend de firma externo
- `certberus sign --csr device.csr --via step-ca --ca-url https://step.local:9000`
- Útil para organizaciones que ya tienen step-ca y solo quieren el CLI unificado.

**Principio:** El usuario elige el motor. Certberus es el frontend universal.

---

## ❌ Descartadas temporalmente

### ECDSA en Root CA
**Por qué posponer:** Cambio de ruptura — todos los certs existentes se invalidan.  
Implementar en v0.2 con flag `--algo ecdsa` en `init`.  
`sign_certificate` sí puede ofrecer ECDSA en certs de hoja sin impacto en la CA.

---

## 🗺 Orden de Implementación Sugerido

| Orden | Funcionalidad | Prioridad |
|-------|--------------|-----------|
| 1 | SANs con IP address | Alta |
| 2 | Firma de CSR externo | Alta |
| 3 | Exportación PKCS#12 | Alta |
| 4 | `CertberusStore` + backend SQLite | Alta |
| 5 | CRL con datos de la BD propia | Alta |
| 6 | Backend PostgreSQL opcional | Media |
| 7 | Refactor `CertberusEngine` | Media |
| 8 | Certificados efímeros (`--ttl`) | Media |
| 9 | Extensiones X.509 con roles | Baja/v0.3 |
| 10 | Interop mkcert / step-ca | Baja/v0.3 |
| 11 | ECDSA en CA raíz | Baja/v0.2 |
