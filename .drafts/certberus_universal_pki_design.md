# Propuesta Técnica: Certberus como PKI Universal para IoT y Redes

## 1. Visión General
Este documento define los requisitos para que **Certberus** evolucione de una herramienta de desarrollo a un motor de PKI robusto capaz de servir a una amplia gama de dispositivos, desde routers avanzados (MikroTik) hasta controladores IoT limitados (ESP32, cámaras IP, etc.).

## 2. Soporte de Formatos (PKCS#12)
Muchos dispositivos legacy o aplicaciones empresariales requieren el certificado y la clave privada en un solo contenedor protegido.
- **Acción**: Implementar en el motor de PKI la capacidad de exportar en formato `.p12` / `.pfx`.
- **Flujo**: El usuario/equipo solicita un cert y recibe un binario que incluye la cadena completa (Leaf + Intermediate + Root) y la clave privada cifrada.

## 3. Estrategia para Dispositivos "No-Inteligentes"
Dispositivos con stacks de red básicos a menudo no pueden procesar CRLs o realizar validaciones OCSP, y a veces carecen de la lógica para generar un CSR (Certificate Signing Request).

### A. Gestión de Revocación Simplificada
- Para dispositivos que no leen CRL: Implementar **certificados de vida corta** (1-3 meses) con auto-renovación forzada desde el controlador.
- Si un dispositivo se marca como comprometido, el controlador simplemente deja de emitir renovaciones.

### B. Provisión "Side-Loaded"
- Dado que estos dispositivos no pueden generar su propia llave privada (CSR flow), Certberus debe soportar la generación centralizada de la llave privada y el certificado, entregando el par completo de forma segura (vía SSH/SFTP o API interna).

## 4. Matriz de Compatibilidad Sugerida

| Tipo de Dispositivo | Método de Provisión | Validación de Revocación | Formato Requerido |
| :--- | :--- | :--- | :--- |
| **MikroTik (v6/v7)** | CSR Flow (API/SSH) | CRL (Opcional) | PEM (CRT + KEY) |
| **Controladores IoT** | Server-Side Gen | Ninguna (Vida corta) | PEM / DER |
| **Servidores/Apps** | API Issue | OCSP / CRL | PKCS#12 (.p12) |
| **Legacy / Industrial** | Manual | Manual | PKCS#12 / DER |

### C. El "Doble Filtro": Name Constraints (X.509)
Para una seguridad de grado Root CA, se implementará la extensión **Name Constraints** en el certificado de la CA Intermedia. Esto garantiza un doble bloqueo:
1. **Filtro de Software**: Certberus rechaza peticiones fuera de la lista blanca en el API.
2. **Filtro Criptográfico**: El certificado CA Intermedia solo es técnicamente válido para firmar subdominios o IPs específicas (ej. `.omniwisp.router` o `172.16.0.0/12`). Si se intenta usar para `google.com`, los navegadores lo rechazarán automáticamente.

## 5. Seguridad y Control de Emisión
Para evitar el mal uso de la CA, se proponen las siguientes restricciones técnicas:
- **Whitelisting Dinámico**: Solo se emitirán certificados para nombres/IPs en inventario.
- **Name Constraints Estáticos**: La CA Intermedia se genera restringida a los sufijos de red de la organización.
- **Limitación de EKU**: Restringir el uso de llaves (Key Usage) según el perfil del dispositivo (ej. solo `clientAuth` para sensores, `serverAuth` para visibilidad web).

## 6. Próximos Pasos (Coordinación de Equipos)
1. **Equipo Infra**: Definir los perfiles de dispositivos en la DB.
2. **Equipo Backend**: Implementar los endpoints de exportación `.p12` y validación de nombres en Certberus.
