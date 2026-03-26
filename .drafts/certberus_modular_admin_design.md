# Plan de Diseño: API Modular de Administración y Consola Web

Este documento define la arquitectura para separar el **Plano de Servicio** (Emisión) del **Plano de Control** (Administración) en Certberus, permitiendo integraciones avanzadas con OmniWISP y una interfaz web opcional.

## 1. Arquitectura Modular

Se propone un sistema de **"Módulos Habilitables"** vía `config.toml`:
- `core`: El motor PKI y base de datos (siempre activo).
- `service_api`: Emisión de certificados (consumido por dispositivos y OmniWISP).
- `admin_api`: Gestión de la PKI (consumido por OmniWISP y la Web GUI).
- `web_console`: Interfaz gráfica integrada (opcional).

---

## 2. Definición de Endpoints

### A. Service API (Token de Emisión)
*Destinado a la automatización de llaves y certificados.*

- `GET /ca.pem`: Descargar cadena de confianza.
- `GET /crl.pem`: Descargar lista de revocación (público).
- `POST /issue`: Generar par de llaves + certificado (Formatos PEM/P12).
- `POST /sign`: Firmar un CSR existente (MikroTik).

### B. Admin API (Token de Administración)
*Destinado al control total del sistema y auditoría.*

#### Gestión de Certificados
- `GET /admin/certificates`: Listar todos los certificados emitidos (con filtros por CN, serial, perfil).
- `GET /admin/certificates/{serial}`: Ver detalles técnicos de un certificado.
- `POST /admin/certificates/{serial}/revoke`: Revocar un certificado inmediatamente.

#### Configuración Dinámica
- `GET /admin/config`: Leer la configuración actual (dominios permitidos, IPs, tiempos de vida).
- `PATCH /admin/config`: Actualizar configuración en caliente (ej: añadir un nuevo dominio permitido).

#### Monitoreo y Auditoría
- `GET /admin/stats`: Resumen de actividad (Certs activos, revocados, expirados).
- `GET /admin/health`: Estado de salud del motor PKI y base de datos.

---

## 3. Modelo de Seguridad (Dual Token)

Para evitar que una filtración del token de un router comprometa toda la PKI:

1.  **`SERVICE_TOKEN`**: Solo tiene permisos para los endpoints de `Service API`. Se usa en OmniWISP para la provisión automática.
2.  **`ADMIN_TOKEN`**: Un token de mayor jerarquía para la `Admin API`. Es el que usaría la **Web Console** y los scripts de configuración global.

---

## 4. Estrategia de Web GUI (Consola)

La interfaz web será una **Single Page Application (SPA)** ligera servida opcionalmente por Certberus.
- **Tecnología**: HTML/JS puro o un framework ligero para no engordar el binario.
- **Comunicación**: Consumirá exclusivamente la `Admin API`.
- **Despliegue**: Se puede desactivar completamente si el usuario prefiere administrar por CLI o vía OmniWISP.

---

## 5. Próximos Pasos (Simulacro)

1.  Extender el modelo de base de datos para registrar perfiles y estados extendidos.
2.  Crear el `AdminRouter` en FastAPI.
3.  Implementar la lógica de persistencia de configuración en caliente (HOT-Reload) para evitar reiniciar el servidor al cambiar dominios permitidos.
