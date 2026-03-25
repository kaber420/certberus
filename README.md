# CERTberus

`devcert` is a Python-native alternative to `mkcert`. It allows you to generate locally-trusted SSL certificates for development without external binaries or complex OpenSSL commands.

## Features

- **Zero-Binary**: Pure Python implementation with no external dependencies (only standard cryptography libraries).
- **Secure by Default**: All private keys are generated with restricted permissions (`600`).
- **XDG Support**: Follows Linux standards for data storage (`~/.local/share/devcert`).
- **Password Protection**: Optional encryption for your Root CA key.
- **FastAPI Integration**: Simple helper to expose the CA for automated provisioning.

## Installation

```bash
git clone https://github.com/kaber420/devcert.git
cd devcert
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### 1. Initialize the Root CA
This creates your personal Certificate Authority (only once).

```bash
python -m devcert.cli init
```

### 2. Create a Certificate
Generate a certificate for `localhost` or any local domain.

```bash
python -m devcert.cli create localhost
```

### 3. Trust the CA
Install the Root CA into your system's trust store.

```bash
python -m devcert.cli install
```

## Automation

For non-interactive environments (CI/CD, setup scripts), you can provide the Root CA password via the `DEVCERT_CA_PASSWORD` environment variable.

```bash
export DEVCERT_CA_PASSWORD=your_secure_password
python -m devcert.cli init --password
python -m devcert.cli create myapp.test
```

## License


LGPL v3.0 License. See [LICENSE](LICENSE) for details.

