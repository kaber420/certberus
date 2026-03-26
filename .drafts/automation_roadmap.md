# Roadmap: Automatización de PKI (Certberus)

Este documento detalla el plan para integrar capacidades de orquestación y soporte ACME en Certberus, permitiendo una gestión de certificados "Cero-Tacto" (Zero-Touch).

## 1. Orquestador Integrado en Web GUI
El objetivo es permitir que el administrador dispare renovaciones masivas desde la consola web.

### Funcionalidades
- **Tab de Automatización**: Nueva sección en la barra lateral.
- **Gestión de Inventario**: Lista de dispositivos (MikroTik, IoT) con sus IPs y credenciales (encriptadas en DB).
- **Acciones Rápidas**:
  - Botón "Renovar Todo" (Dispara el script de orquestación en segundo plano).
  - Estado en tiempo real: "Pushing to 192.168.1.1...", "Success ✅".
- **Logs de Automatización**: Ver el historial de qué se renovó y cuándo falló.

### Arquitectura
- El backend (`FastAPI`) ejecutará tareas `BackgroundTasks` para no bloquear la UI.
- Uso de `Paramiko` (SSH) o `requests` (REST API) para hablar con los dispositivos finales.

## 2. Servidor ACME Nativo
Soporte para que dispositivos inteligentes (MikroTik v7.4+, servidores Linux) soliciten sus propios certificados.

### Fases
1. **Endpoint de Directorio**: Implementar los estándares RFC 8555.
2. **Validación DNS/HTTP**: Soporte inicial para validación basada en tokens para demostrar control sobre el dominio.
3. **Emisión Automática**: El servidor ACME hablará directamente con el motor interno de Certberus para firmar sin intervención humana.

---

## 3. Próximos Pasos (Backlog)
- [ ] Definir esquema de DB para "Dispositivos".
- [ ] Implementar el driver básico de comunicación con MikroTik API.
- [ ] Añadir la vista "Automation" al `app.js` de la GUI web.
