# Plan de Implementación: Certberus dPKI (Blockchain Bridge)

Este documento detalla los pasos técnicos para transformar Certberus en una Autoridad de Certificación descentralizada o híbrida (Web3-compatible).

## 1. Diseño de Arquitectura

La idea es mantener la compatibilidad con dispositivos tradicionales (X.509) pero delegar la "verdad" sobre la validez y revocación a una blockchain.

### Componentes Clave
1.  **`BlockchainConnector` (Python):** Servicio que interactua con redes como Ethereum, Polygon o una red privada (Hyperledger/Avalanche Subnet).
2.  **Smart Contract (Solidity):** Un contrato sencillo que actúa como el "Registro de Certificados".
3.  **Anchoring Service:** Proceso en segundo plano que sube el hash de los certificados emitidos a la red.

## 2. Cambios en la Base de Datos (`models.py`)

Añadir campos para rastrear el estado en la blockchain:

```python
class Certificate(SQLModel, table=True):
    # ... campos existentes ...
    blockchain_anchor_tx: Optional[str] = Field(default=None, description="Hash de la transacción de anclaje")
    blockchain_status: str = Field(default="pending", description="Status en la red (pending, anchored, failed)")
    on_chain_id: Optional[str] = Field(default=None, description="Identificador único en el Smart Contract")
```

## 3. Smart Contract (Mockup Lógico)

El contrato guardaría un mapeo de `fingerprint => (isValid, owner, timestamp)`.

-   **`registerCertificate(bytes32 fingerprint)`**: Solo llamable por el administrador de Certberus.
-   **`revokeCertificate(bytes32 fingerprint)`**: Actualiza el estado a `false`.
-   **`isCertificateValid(bytes32 fingerprint)`**: Función pública que cualquiera puede consultar sin intermediarios.

## 4. Flujo de Trabajo (Workflow)

1.  **Emisión:** El usuario solicita un certificado vía Service API.
2.  **Persistencia:** Certberus genera el .pem y lo guarda en la DB local.
3.  **Anclaje (Async):**
    -   Se calcula el SHA-256 del certificado.
    -   Se envía una transacción a la blockchain con el hash.
    -   Se guarda el ID de la transacción en la DB.
4.  **Verificación Externa:**
    -   Un tercero (ej. un servidor VPN o un usuario final) recibe el certificado.
    -   En lugar de consultar a la API de Certberus (centralizada), consulta directamente al Smart Contract usando el hash del certificado.

## 5. Seguridad: Prevención de Certificados Ilegítimos (Anti-Spoofing)

Uno de los mayores riesgos es que alguien emita un certificado para un dominio que no le pertenece (ej. `facebook.com`). En un sistema descentralizado, esto se mitiga mediante un **Consenso de Validación de Dominio (dDV)**.

### Mecanismos de Protección:
1.  **Oráculos Descentralizados (Multi-Node Validation):**
    -   Para registrar un dominio como `.com`, el usuario debe publicar un valor TXT en su DNS.
    -   Múltiples nodos independientes (ej. 5 de 7) deben verificar este registro antes de que el Smart Contract permita el anclaje del certificado.
2.  **Staking y Slashing (Criptoeconomía):**
    -   Los nodos validadores de **yuxiCA** deben depositar una garantía (Stake).
    -   Si se demuestra que un nodo validó un certificado ilegítimo, su garantía es "quemada" (Slashing).
3.  **Governance Whitelists:**
    -   Dominios críticos (bancos, redes sociales gigantes) pueden requerir una validación manual por parte de la DAO o un número mayor de nodos de alta reputación.
4.  **Certificate Transparency (CT) Nativa:**
    -   Como todo es público en la blockchain, cualquier anomalía es visible al instante. Los navegadores pueden rechazar certificados que no tengan una prueba de anclaje (Proof of Anchor) válida en el contrato oficial.

## 7. Protocolos Avanzados de dPKI

Para que **yuxiCA** sea verdaderamente robusta y moderna, puede adoptar protocolos que van más allá de una simple blockchain:

1.  **KERI (Key Event Receipt Infrastructure):**
    -   Permite crear identificadores **auto-certificados** (AIDs).
    -   No depende de una blockchain para la confianza básica, sino de un log de eventos (KEL) firmado por el dueño. La blockchain solo sirve como "testigo" de la cronología.
2.  **IPFS (InterPlanetary File System):**
    -   En lugar de guardar los certificados en un servidor central, se guardan en IPFS usando **Content Addressing** (CIDs).
    -   Esto asegura que el certificado sea inmutable y esté disponible siempre que haya nodos de la comunidad activos.
3.  **ZK-PKI (Zero-Knowledge PKI):**
    -   Permite demostrar que tienes un certificado válido sin revelar quién eres o para qué dominio es (Privacidad Selectiva).
    -   Ideal para casos de uso donde la identidad debe ser privada pero verificable.
4.  **Merkle DAGs y Trees:**
    -   Estructuras de datos que permiten verificar la integridad de millones de certificados de forma extremadamente rápida (como lo hace Git o las blockchains).

## 8. Casos de Uso de yuxiCA
-   **Nodos de IoT:** Cámaras y sensores que se auto-identifican sin un servidor central.
-   **Comunidades Mesh:** Redes de internet comunitarias donde no hay un ISP central.
-   **Web3 Identity:** Logins descentralizados que sustituyen a Google/Facebook Login.
