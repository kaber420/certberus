# Red de Confianza Soberana (RCS)
## Infraestructura de Certificación Descentralizada y Comunitaria
YuxiCA (yuxiCA) is a decentralized infrastructure designed to democratize trust on the web. By shifting the "source of truth" from centralized corporate entities to a transparent, community-governed federation, we ensure that digital identities are resilient, auditable, and accessible to everyone.

## 🚀 Objectives
- **Decentralized Trust:** Replace the single-point-of-failure Root CA model with a blockchain-based consensus.
- **Transparency:** All certificate lifecycles (issuance, revocation, renewal) are anchored in public or consortium blockchains.
- **Interoperability:** Maintain compatibility with traditional X.509 standards while enabling next-gen DIDs (Decentralized Identifiers).
- **Community Governance:** Use a DAO (Decentralized Autonomous Organization) to manage policies, domain validation rules, and root trust anchors.

## 🛠️ Core Technology Stack
- **Name Constraints (Seguridad Acotada):** Protective measure to limit intermediate CA powers to specific domains (e.g., `*.empresa.comu`), preventing spoofing of global sites.
- **Real-Time Blockchain Revocation:** Eliminates slow CRLs and privacy-invasive OCSP by using the blockchain ledger as the live status source.
- **Standard X.509 Interoperability:** Full compatibility with modern browsers and operating systems.

## 🏗️ Architecture Overview: The Sovereign Hierarchy
YuxiCA decentralizes power through a four-level hierarchy designed for maximum resilience:

1.  **Level 1: Community Root CA (The "International Treaty"):** The offline trust anchor. It only signs certified Intermediate CAs.
2.  **Level 2: Intermediate CAs (The "Governments/Organizations"):** Entities approved by the DAO to manage specific name-spaces (e.g., `.mesh`, `.comunidad`).
3.  **Level 3: Local User Sub-CA (The "ASM Layer"):** A personal authority generated on each node, signed by Level 2, and restricted by **Name Constraints** to local domains.
4.  **Level 4: End-Entity Certificates:** Certificates for local services, Docker containers, and IoT devices, managed automatically by the local node.

## 🤝 Key Features
- **Decentralized Trust:** Replace the single-point-of-failure Root CA model with a blockchain-based consensus.
- **Cross-Signing Compatibility:** Allow dual trust paths (Traditional + YuxiCA) for seamless transition.
- **Transparency:** All certificate lifecycles (issuance, revocation, renewal) are anchored in public or consortium blockchains.
- **DAO Governance:** Token holders or community members vote on admitting or revoking Intermediate CAs.
