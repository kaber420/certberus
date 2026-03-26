# Certberus Master Implementation Plan (Unificado)

Este documento centraliza la visión técnica, la arquitectura y el roadmap de **Certberus**, consolidando todos los borradores previos (`.drafts/`) en una sola fuente de verdad.

## 🎯 Visión General
Certberus es un motor PKI (Public Key Infrastructure) nativo de Python, diseñado para infraestructura crítica (Routers MikroTik, servidores on-prem, redes locales). Su objetivo es ser la alternativa profesional y segura a `mkcert`, permitiendo gestión de ciclo de vida completo (Emisión, Firma, Revocación).

---

## 🏗️ 1. Arquitectura Tripartita: "Core-First"

Para maximizar la utilidad, el proyecto se divide en tres capas desacopladas:

### A. Certberus Core (Librería)
*   **Propósito**: Lógica pura de criptografía y manejo de certificados.
*   **Interfaz**: Funciones de Python (`import certberus`).
*   **Responsabilidad**: Firmar X.509, generar llaves, validar CSRs, generar CRLs. No depende de red ni de CLI.

### B. Certberus API (Servicio REST)
*   **Propósito**: Automatización remota y gestión centralizada.
*   **Tecnología**: FastAPI + Uvicorn.
*   **Funciones**:
    *   `GET /ca.pem`: Distribución de la CA raíz.
    *   `GET /crl.pem`: Publicación automática de la lista de revocación (CDP).
    *   `POST /sign`: Firma remota de CSRs (Seguridad: La llave privada nunca sale del router).
*   **Seguridad**: Autenticación vía API Tokens y habilitación modular de endpoints en el config.

### C. Certberus CLI (Herramienta de Usuario)
*   **Propósito**: Gestión humana y configuración.
*   **Tecnología**: Typer + Rich.
*   **Comandos**: `init`, `create`, `revoke`, `serve`, `setup`.

### D. Certberus Client (SDK)
*   **Propósito**: Facilitar el consumo del API desde otras aplicaciones.
*   **Interfaz**: Clase `CertberusClient` que encapsula las llamadas HTTP a los endpoints.
*   **Ventaja**: Permite integrar el servicio sin necesidad de importar la lógica pesada del core o manejar peticiones JSON manuales.

---

## 🛠️ 2. Próximas Funcionalidades (Fase de Desarrollo)

### 🔥 Prioridad Alta: Infraestructura Robusta
*   **[DONE] SAN con soporte IP**: Permitir que `certberus create 10.0.0.1` genere un campo `IPAddress` válido para evitar errores en navegadores y equipos industriales.
*   **Firma de CSR Externo**: Permitir que un MikroTik genere su propia llave y Certberus solo devuelva el certificado firmado.
*   **PKCS#12 (.p12)**: Exportar certificado + llave + cadena en un solo archivo cifrado para importación rápida en RouterOS/Ubiquiti.

### 🚫 Seguridad: Revocación (CRL)
*   **[DONE] Base de Datos**: Uso de **SQLModel** (SQLite por defecto, PostgreSQL para escala) para persistir el estado de todos los certificados.
*   **[DONE] Comando `revoke`**: Marcar certificados como inválidos en la BD.
*   **[DONE] Generador CRL**: Firmar y generar la lista de revocación (Falta publicación automática en API).

---

## 🔒 3. Configuración y Seguridad [DONE]

### `certberus.toml`
Migración a una configuración declarativa basada en TOML, permitiendo:
*   Paths de almacenamiento personalizables.
*   Configuración de base de datos (aiosqlite / psycopg).
*   Toggles de seguridad para el API (activar solo lo que se usa).

### Secrets Management
*   **Env Vars**: Soporte para inyectar contraseñas de la CA o DB vía variables de entorno (`DEVCERT_CA_PASSWORD`).
*   **[DONE] Setup Wizard**: Comando `certberus setup` para una configuración inicial guiada y profesional.

---

## 🗺️ Roadmap de Implementación

1.  **Fase 0 (Actual)**: Consolidación de arquitectura y cambio a LGPL v3.0 (Completado).
2.  **Fase 1 (Nucleo)**: Refactor de `sign_certificate` para SAN/IP, CSR externo y PKCS#12.
3.  **Fase 2 (Persistencia)**: Implementación de SQLModel y esquema de base de datos.
4.  **Fase 3 (Servicio)**: Motor de Revocación (CRL) y Servidor FastAPI modular.
5.  **Fase 4 (Experience)**: CLI Setup Wizard e integración de tokens de seguridad.

---

## ✅ Plan de Verificación

### Pruebas Automatizadas
*   **Unit Tests**: Validar que el parser de SAN distingue correctamente entre DNS e IP.
*   **Integration Tests**: Levantar el servidor FastAPI mockeado y verificar que la descarga de `.p12` y `.pem` (CRL) funciona.

### Pruebas Manuales
*   Importar un certificado generado por IP en Chrome/Firefox y verificar el candado verde.
*   Importar un archivo `.p12` en un Router MikroTik real (o CHR) y verificar consistencia de la llave.
