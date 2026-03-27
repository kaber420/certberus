# RCS Client (yuxi-pki-client)

Your gateway to the Sovereign Trust Network. Use this tool to manage local and mesh certificates trusted by the RCS Community Root.

## Installation
1. Install dependencies:
   ```bash
   pip install typer[all] cryptography web3 rich
   ```
2. Run the client:
   ```bash
   python src/main.py --help
   ```

## Usage
- **Initialize**: `python src/main.py init`
  Downloads the Root CA and provides instructions to trust it on your system.
- **Issue Certificate**: `python src/main.py issue myapp.local`
  Generates a certificate for a local domain instantly.
- **Sync**: `python src/main.py sync`
  Verifies that your local trust is still aligned with the community blockchain.

## Development Vision
This client will soon integrate directly with the Certberus engine for real cryptographic signing and a local DNS proxy for `.mesh` resolution.
