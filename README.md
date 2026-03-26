# CERTberus

`certberus` is a Python-native alternative to `mkcert`. It allows you to generate locally-trusted SSL certificates for development without external binaries or complex OpenSSL commands.

## Features

- **Zero-Binary**: Pure Python implementation with no external dependencies (only standard cryptography libraries).
- **Secure by Default**: All private keys are generated with restricted permissions (`600`).
- **XDG Support**: Follows Linux standards for data storage (`~/.local/share/certberus`).
- **Password Protection**: Optional encryption for your Root CA key.
- **FastAPI Integration**: Simple helper to expose the CA for automated provisioning.

## Installation

```bash
git clone https://github.com/kaber420/certberus.git
cd certberus
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### 1. Initialize the Root CA
This creates your personal Certificate Authority (only once).

```bash
python -m certberus.cli init
```

### 2. Create a Certificate
Generate a certificate for `localhost` or any local domain.

```bash
python -m certberus.cli create localhost
```

### 3. Trust the CA
Install the Root CA into your system's trust store.

```bash
python -m certberus.cli install
```

## API Server & Dual Token Security

Certberus features a built-in modular REST API with a **Dual Token** security model. This allows safe programmatic integration with routers, IoT devices, and management consoles.

To configure and start the API server:

```bash
python -m certberus.cli setup
python -m certberus.cli serve
```

### Dual Tokens
When enabling the API during `setup`, two authentication tokens are generated and stored in `~/.config/certberus/config.toml`:

- **Service Token** (`cb_svc_...`): Used by end devices or provisioning scripts to request and sign certificates.
- **Admin Token** (`cb_adm_...`): A high-privilege token used for PKI administration and configuration hot-reloading.

### Endpoints

**Service API (Header: `X-Certberus-Token: <Service Token>`)**
- `GET /_certberus/ca.pem` - Download the Root CA (Public).
- `GET /_certberus/crl.pem` - Download the Revocation List (Public).
- `POST /_certberus/issue` - Generate a new keypair and signed certificate.
- `POST /_certberus/sign` - Sign an existing CSR (e.g., from MikroTik).

**Admin API (Header: `X-Certberus-Token: <Admin Token>`)**
- `GET /_certberus/admin/certificates` - List all certificates.
- `GET /_certberus/admin/certificates/{serial}` - Get certificate details.
- `POST /_certberus/admin/certificates/{serial}/revoke` - Revoke a certificate.
- `GET /_certberus/admin/config` - View active security policy (Allowed domains/IPs).
- `PATCH /_certberus/admin/config` - Update config dynamically (Hot-Reload without restarting).
- `GET /_certberus/admin/stats` - PKI usage statistics.

## Automation

For non-interactive environments (CI/CD, setup scripts), you can provide the Root CA password via the `DEVCERT_CA_PASSWORD` environment variable.

```bash
export DEVCERT_CA_PASSWORD=your_secure_password
python -m certberus.cli init --password
python -m certberus.cli create myapp.test
```

## License


LGPL v3.0 License. See [LICENSE](LICENSE) for details.

