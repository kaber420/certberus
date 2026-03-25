# Certberus — Arquitectura de Configuración y Seguridad

> Propuesta de diseño para la gestión segura de las configuraciones, endpoints y modos de operación de Certberus.
> Fecha: 2026-03-24

---

## 🎯 Objetivo
Hacer de Certberus una herramienta que pase de ser un "script local" a un **motor PKI profesional**. Debe poder configurarse de manera segura, flexible (CLI, API, Librería) y tener permisos granulares sobre qué funciones están expuestas, sin acoplarla a OmniWISP ni exponer credenciales en texto plano por error.

---

## 🏗️ 1. Modelo de Configuración: `certberus.toml` + Envs

**El Estándar Profesional:**
La mejor práctica moderna es una combinación de un archivo de configuración declarativo (preferiblemente TOML, ya que Python lo soporta nativamente en 3.11+ y es más seguro que YAML/JSON) sobrecargado por variables de entorno (ideal para contenedores o systemd).

**Ubicación por defecto:**
- Linux: `~/.config/certberus/config.toml` (o `/etc/certberus/config.toml` si corre como servicio global).

### Ejemplo de Estructura de `config.toml`:

```toml
[core]
# Directorio donde se almacenan las CAs y BD
storage_path = "~/.local/share/certberus"
auto_init = false # Si es true, crea la CA si no existe al arrancar el servicio

[database]
# aiosqlite por defecto, o postgresql+asyncpg para producción
url = "sqlite+aiosqlite:///~/.local/share/certberus/certs.db"

[api]
# Configuración del servidor integrado
enabled = true
host = "127.0.0.1"
port = 8443
tls_cert = "certberus_api.pem" # Se auto-firma con la propia CA

[api.endpoints]
# Toggles de seguridad: Exponer solo lo que necesitas
crl_publishing = true       # Permite descargar crl.pem (Público)
ca_publishing = true        # Permite descargar el Root CA publico
sign_csr = false            # Requiere autenticación
issue_cert = false          # Endpoint muy peligroso (devuelve llave privada)

[security]
# ¿Cómo se autentican los clientes que piden firma (ej: MikroTik)?
auth_mode = "token" # "none" (inseguro), "token" (recomendado), "mtls" (avanzado)
```

---

## 🔒 2. Gestión Segura de Secretos (Evitando texto plano)

Si necesitamos guardar contraseñas (ej: la password que protege la llave de la CA, o tokens de API), **NO** deben ir en texto plano en el JSON/TOML.

### Opciones Profesionales:

#### A. Master Environment Variable (Estilo Ansible Vault o Bitwarden)
El archivo `config.toml` se cifra usando Criptografía simétrica (ej. Fernet). Al arrancar el API o CLI, se le pasa un `CERTBERUS_MASTER_KEY` como variable de entorno o se lee de un archivo altamente restringido.
- **Ventaja:** Muy seguro, perfecto para servidores desatendidos (systemd inyecta la env).
- **Desventaja:** Si pierdes The Master Key, pierdes la config.

#### B. Integración con el SO: Keyring (El "Apple Keychain" / "KWallet")
Usar la librería `keyring` de Python.
```bash
certberus auth set-ca-password
# Guarda en el llavero seguro de Linux (SecretService)
```
- **Ventaja:** El usuario no gestiona el cifrado, el S.O lo hace.
- **Desventaja:** No funciona muy bien en servidores "headless" o Docker sin DBus.

#### C. **Recomendación: Encriptación en Reposo Transparente (La "Vía Vault")**
Guardar todo "normal" en el TOML, pero los campos críticos (como contraseñas) van referenciados mediante prefijos:
`db_password = "env:CERT_DB_PASS"` o `ca_password_file = "/etc/certberus/ca.pass"`. Esto permite a systemd cargar secretos de forma hiper-segura y mantener el TOML en repositorios de Git sin riesgo (GitOps).

---

## 🛠️ 3. El CLI: `setup` y Flujo de Usuario

Para que la adopción sea fácil, no obligamos a nadie a escribir TOML a mano. Implementaremos un comando `setup`.

### Comando: `certberus setup`
Un asistente interactivo (CLI Wizard usando la librería `rich` o `InquirerPy`) que hace las preguntas clave y genera el TOML.

**Flujo en terminal:**
```bash
$ certberus setup

🛡️ Bienvenido a la configuración de Certberus
---------------------------------------------

? ¿Dónde deseas almacenar los certificados y la CA? [~/.local/share/certberus]:
? ¿Qué motor de base de datos usarás?
  > SQLite (Mejor para uso local/individual)
    PostgreSQL (Mejor para integración con OmniWISP/Equipos)
? ¿Deseas habilitar el servidor API REST nativo? [Y/n]: Y
? ¿Deseas exponer el endpoint de Firma de CSRs (Para equipos MikroTik)? [y/N]: y
? ¡Atención! Has activado endpoints sensibles. Generando Token de API de Acceso...
  Token generado: cb_sk_9a8b7c6d5e4f3g2h... ¡GÚARDALO SEGURO!

✅ Configuración escrita en ~/.config/certberus/config.toml
🚀 Ejecuta 'certberus serve' para levantar la API.
```

### Otros comandos clave de gestión:
- `certberus config show` -> Muestra el config sumariado.
- `certberus config set api.endpoints.sign_csr true` -> Modifica un valor directo.
- `certberus tokens add mikrotik-01` -> Genera y guarda (hasheado en la DB) un token de acceso para que ese dispositivo hable con el API.

---

## 🌐 4. "Toggles" del Endpoint y Modo API

Al separar Core / DB / API, podemos levantar Certberus en modo daemon (`certberus serve`).

**¿Cómo funciona el servidor integrado?**
Si el usuario pone `certberus serve`, FastAPI arranca. El middleware de FastAPI lee `config.toml -> [api.endpoints]`.
Si una ruta (ej: `POST /api/v1/sign`) está solicitada, pero en el TOML dice `sign_csr = false`, FastAPI levanta un `403 Forbidden: Endpoint disabled by administrator`.

Esto es **seguridad por diseño**. Si a un usuario solo le interesa Certberus para sus proyectos locales de Docker, el API sensible nunca está expuesto.

---

## 🏆 Resumen Estratégico ("The Certberus Way")
1. **Configuración Declarativa**: Usaremos un archivo `.toml` limpio, modificable a mano pero gestionado inteligentemente por el CLI.
2. **Secretos Desacoplados**: Usar referencias de variables de entorno para contraseñas de DB o llaves (Cloud-Native friendly).
3. **Wizard de Setup (`certberus setup`)**: Profesionaliza el producto. Una experiencia de terminal rica te separa de las herramientas amateur.
4. **API Modular (`certberus serve`)**: Activas lo que usas. Por defecto todo lo riesgoso (emitir certs) está bloqueado por API y requiere habilitación explícita y Tokens.
