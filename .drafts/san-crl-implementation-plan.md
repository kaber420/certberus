# Plan de Implementación: SAN y CRL (Enfoque en Infraestructura)

Este plan detalla los pasos para completar la implementación de Subject Alternative Names (SAN) con soporte para IPs y las Listas de Revocación de Certificados (CRL) en Certberus. A diferencia de otras herramientas, Certberus se enfoca en **infraestructura crítica** (Servidores, Contenedores, VMs y redes como MikroTik/Ubiquiti), priorizando la automatización y la seguridad interna sobre el uso local en navegadores.

## Cambios Propuestos

### 1. Configuración y CLI
#### [MODIFY] [cli.py](file:///home/kaber420/Documentos/proyectos/devcert/certberus/cli.py)
- **Asistente `setup`**: Agregar preguntas sobre la publicación de CRL y CA.
- **Comando `serve`**: Implementar el comando para lanzar el servidor FastAPI usando `uvicorn`.
  - Debe cargar la configuración.
  - Debe inicializar la base de datos (`db_session.init_db`).
  - Debe montar el router de Certberus.

### 2. Integración con API (FastAPI)
#### [MODIFY] [fastapi.py](file:///home/kaber420/Documentos/proyectos/devcert/certberus/integrations/fastapi.py)
- **Endpoint `GET /_certberus/crl.pem`**:
  - Consultar certificados revocados en la base de datos.
  - Generar la CRL "on-the-fly" usando `PKIService.generate_crl`.
  - Devolver el archivo PEM.
- **Endpoint `POST /_certberus/revoke`**:
  - Recibir `serial_number` y `reason`.
  - Marcar el certificado como revocado en la base de datos.
  - (Opcional) Token de seguridad para este endpoint.
- **Endpoint `GET /_certberus/ca.pem`**: Asegurar que respeta la configuración `ca_publishing`.

### 3. Endurecimiento de Seguridad (Security Hardening)
#### [MODIFY] [pki.py](file:///home/kaber420/Documentos/proyectos/devcert/certberus/pki.py)
- **Extensión `NameConstraints`**: Modificar `create_intermediate_ca` para inyectar restricciones nativas en la CA Intermedia. Esto impedirá que la CA firme dominios no autorizados (ej: `google.com`).
- **Validación por Software**: Implementar un chequeo preventivo en `sign_certificate` que compare el `common_name` y `alt_names` contra la lista de dominios permitidos definida en la configuración.

#### [MODIFY] [cli.py](file:///home/kaber420/Documentos/proyectos/devcert/certberus/cli.py)
- **`init --secure`**: Añadir opción para configurar dominios permitidos (ej: `*.lan`, `192.168.0.0/16`) durante la creación de la infraestructura.

### 4. Lógica de Negocio (PKI)
#### [VERIFY] [pki.py](file:///home/kaber420/Documentos/proyectos/devcert/certberus/pki.py)
- Confirmar que `generate_crl` maneja correctamente las zonas horarias y el formato de los números de serie.

---

## Plan de Verificación

### Pruebas Automatizadas
- Crear `tests/test_api_crl.py` para probar los nuevos endpoints usando `TestClient` de FastAPI.
- Crear `tests/test_security_constraints.py` para verificar que la CA rechaza firmar dominios no autorizados.

### Verificación Manual
1. Ejecutar `certberus setup` para habilitar la API.
2. Iniciar el servidor: `certberus serve`.
3. Revocar un certificado vía API: `curl -X POST http://localhost:8443/_certberus/revoke -d '{"serial": "...", "reason": "keyCompromise"}'`.
4. Descargar la CRL: `curl http://localhost:8443/_certberus/crl.pem`.
5. Verificar la CRL con OpenSSL.
6. Intentar firmar `facebook.com` y confirmar que Certberus lo bloquea.
