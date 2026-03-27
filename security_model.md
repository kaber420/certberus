# Security Model: Granular Trust & ASM Layer

## 1. The 4-Level Sovereign Hierarchy
To protect the community from endpoint compromises, RCS implements a four-level hierarchical model:

| Level | Name | Responsibility | Security Measure |
| :--- | :--- | :--- | :--- |
| **L1** | **Community Root** | Root of Trust (Anchor) | Offline / Hardware MFA |
| **L2** | **Intermediate CA** | TLD / Entity Governance | DAO-Controlled / Name Constraints |
| **L3** | **Local Sub-CA** | User/Device Abstraction | **ASM Layer** / Strict Constraints |
| **L4** | **Leaf Certificate** | Final Service / IoT | Automated Issuance |

## 2. Abstraction of Security (ASM) Layer
The ASM Layer is a local agent that manages the **Level 3 Sub-CA**.

### Blast Radius Mitigation
By issuing a Level 3 CA instead of signing Level 4 certificates directly from Level 2, we achieve:
- **Constraint Enforcement:** The Level 3 CA is cryptographically restricted to a specific scope (e.g., `*.mi-nodo.mesh`).
- **Hardware Binding:** Private keys are stored in the TPM (Trusted Platform Module) or Secure Enclave of the device.
- **Independence:** If the machine is offline, it can still sign its own Level 4 certificates for internal services without contacting Level 2.

### Attack Scenario: Compromised Endpoint
If an attacker gains root access to a node:
1. They may control the Local Sub-CA (Level 3).
2. **However**, they cannot spoof `google.com` or other community nodes because the certificate chain will be rejected by any browser due to **Name Constraints** mismatch.
3. The community can revoke the specific Level 3 serial on-chain, effectively "cutting off" the infected branch without touching the Level 2 infrastructure.

## 3. Implementation Specification: Tiered Security Model
The ASM Layer is designed to be hardware-agnostic, adapting to the highest available security tier on the host:

| Tier | Provider | Best For | Technical Detail |
| :--- | :--- | :--- | :--- |
| **Tier 1** | **Hardware** | PCs, Modern Servers | TPM 2.0 / Apple T2 / Nitro Enclaves |
| **Tier 2** | **OS-Native** | Managed Servers | `systemd-creds`, macOS Keychain, DPAPI |
| **Tier 3** | **Software** | Legacy ARM, Containers | AES-256 Storage with Unix `0600` Perms |

- **X.509 Extensions:** Use `nameConstraints` extension with `permittedSubtrees`.
- **Hardware Integration:** Support for `PKCS#11` and `TPM2.0` providers.
- **Automation:** Integration with `ACME` or local hooks to automate Level 4 rotation.
