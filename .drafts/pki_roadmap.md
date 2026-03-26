# Certberus: Roadmap & Recommended Improvements

Certberus is already a more powerful and flexible "PKI Engine" than `mkcert` (which is just a simple certificate generator). Below are the recommended improvements to evolve it into a professional, zero-trust PKI for enterprise and IoT environments.

## 1. 🚀 Protocol Support
- **ACME Server Implementation**: Allowing standard clients like `certbot`, `traefik`, or `nginx` to automatically request certificates via ACME protocol. This would make Certberus a truly "drop-in" replacement for Let's Encrypt in local networks.
- **EST/SCEP Support**: Protocols used by enterprise devices (like Cisco or high-end MikroTik) to enroll certificates without custom API calls.

## 2. 🏗️ High-Availability & Scalability
- **External Database Support**: (Partially implemented) Finalize support for PostgreSQL or Redis to allow running multiple API instances behind a load balancer.
- **OCSP Responder**: Currently, clients check revocations via CRL (a file). An OCSP responder would allow real-time certificate status checks over HTTP, which is much faster and more efficient.

## 3. 🔑 Security Enhancements
- **Hardware Security (HSM)**: Support for storing the Root CA private key in a YubiKey, TPM (Trusted Platform Module), or Cloud KMS (AWS/GCP), ensuring the master key is NEVER in plain text on the disk.
- **Sub-Authority Automation**: Automatic "ceremony" to rotate intermediate CAs every 1-2 years, signed by an offline Root CA.

## 4. 🛠️ Integrations (The "Ecosystem")
- **Official Client SDKs**: Create a simple `certberus-py` and `certberus-js` library for developers to integrate "One-Click SSL" in their apps.
- **MikroTik Auto-Provisioner**: A script or service that uses the MikroTik API to automatically install the Root CA and renew device certificates when they reach 80% of their lifespan.
- **Prometheus/Grafana Dashboard**: Export metrics like "issued certs by day", "expiring in 7 days", and "revocation stats".

## 5. 🎨 UX & Administration
- **Web UI Enhancements**:
  - Live log of certificate requests.
  - Revocation "one-click" from the UI.
  - Interactive "CA Tree" visualization.

## 6. 🛡️ Compliance & Best Practices
- **Certificate Transparency (CT) Log**: Log all issuances to a local or private CT log.
- **Audit Logging**: Immutable database of EVERY action taken by Admin or Service tokens.

---

### Comparison with `mkcert`

| Feature | `mkcert` | Certberus |
| :--- | :---: | :---: |
| Local Trust | ✅ | ✅ |
| Multi-Domain | ✅ | ✅ |
| API / Remote Access | ❌ | ✅ |
| Revocations (CRL) | ❌ | ✅ |
| Multiple Intermediates | ❌ | ✅ |
| Database Persistence | ❌ | ✅ |
| Security Filters (IP/Domain) | ❌ | ✅ |
| ACME Support | ❌ | (Planned) |


o ya estamos usando SQLModel, el balanceo es fácil: todas las instancias de Certberus se conectan a la misma base de datos central (PostgreSQL). Así, si la Instancia A revoca un certificado, la Instancia B lo sabe al instante en la siguiente consulta.

Conclusión para tu proyecto: Para que Certberus sea "Cloud-Ready", el siguiente paso lógico no es necesariamente una YubiKey, sino una integración con una API de KMS o un Secret Store. Eso permitiría que Certberus corra en 100 contenedores Docker compartiendo la misma autoridad de forma segura.

¿Te imaginabas que existían "servidores de firmas" o creías que todo era por archivos compartidos?

