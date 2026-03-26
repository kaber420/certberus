import typer
import os
from pathlib import Path
from typing import Optional, List
from .pki import PKIService
from rich.console import Console
from rich.prompt import Prompt
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from .config import load_config, save_config
import asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from .db import session as db_session
from .db.models import Certificate

async def _save_cert_to_db(cert_obj, is_ca=False, profile="router", authority_name: Optional[str] = "default"):
    config = load_config()
    db_session.init_db(config["database"]["url"])
    await db_session.create_all_tables()
    
    fingerprint = cert_obj.fingerprint(hashes.SHA256()).hex()
    serial_str = hex(cert_obj.serial_number)[2:]
    
    try:
        cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except tuple() + (IndexError,):
        cn = "Unknown"
        
    auth_id = None
    async with db_session.AsyncSessionLocal() as session:
        from .db.models import Authority, Certificate
        # Find or create authority record for legacy/cli certs
        name = authority_name or "default"
        result = await session.execute(select(Authority).where(Authority.name == name))
        auth = result.scalars().first()
        if not auth and name == "default":
            auth = Authority(name="default")
            session.add(auth)
            await session.commit()
            await session.refresh(auth)
        
        if auth:
            auth_id = auth.id

        db_cert = Certificate(
            serial_number=serial_str,
            common_name=cn,
            issued_at=cert_obj.not_valid_before_utc,
            expires_at=cert_obj.not_valid_after_utc,
            fingerprint=fingerprint,
            is_ca=is_ca,
            authority_id=auth_id,
            profile=profile,
            status="active"
        )
        
        session.add(db_cert)
        await session.commit()

def save_cert_to_db(cert_obj, is_ca=False, profile="router", authority_name: Optional[str] = "default"):
    return asyncio.run(_save_cert_to_db(cert_obj, is_ca, profile, authority_name))

app = typer.Typer(help="certberus: A Python-native mkcert alternative.")
console = Console()
pki = PKIService()

def get_password(name: str) -> Optional[str]:
    """Helper to ask for a password securely."""
    pwd = Prompt.ask(f"Enter password to protect {name} (leave empty for none)", password=True)
    if not pwd:
        return None
    confirm = Prompt.ask(f"Confirm password for {name}", password=True)
    if pwd != confirm:
        console.print(f"[red]Passwords for {name} do not match![/red]")
        return "MISMATCH"
    return pwd

@app.command()
def setup():
    """Interactive wizard to configure certberus."""
    console.print("\n[bold cyan]🛡️ Bienvenido a la configuración de Certberus[/bold cyan]")
    console.print("-" * 50 + "\n")
    
    config = load_config()
    
    storage_ans = inquirer.text(
        message="¿Dónde deseas almacenar los certificados y la CA?",
        default=config["core"]["storage_path"]
    ).execute()
    config["core"]["storage_path"] = storage_ans
    
    db_ans = inquirer.select(
        message="¿Qué motor de base de datos usarás?",
        choices=[
            Choice("sqlite", name="SQLite (Mejor para uso local/individual)"),
            Choice("postgres", name="PostgreSQL (Mejor para integración con OmniWISP/Equipos)")
        ],
        default="sqlite"
    ).execute()
    
    if db_ans == "sqlite":
        config["database"]["url"] = f"sqlite+aiosqlite:///{storage_ans}/certs.db"
    else:
        pg_url = inquirer.text(
            message="Ingresa la URL de la base de datos (PostgreSQL)",
            default="postgresql+asyncpg://user:pass@localhost:5432/certberus"
        ).execute()
        config["database"]["url"] = pg_url
        
    api_ans = inquirer.confirm(
        message="¿Deseas habilitar el servidor API REST nativo?",
        default=config["api"]["enabled"]
    ).execute()
    config["api"]["enabled"] = api_ans
    
    if api_ans:
        console.print("\n[bold cyan]Generando tokens de seguridad Dual-Token...[/bold cyan]")
        import secrets
        service_token = f"cb_svc_{secrets.token_hex(16)}"
        admin_token = f"cb_adm_{secrets.token_hex(16)}"
        config["security"]["service_token"] = service_token
        config["security"]["admin_token"] = admin_token
        
        console.print(f"Service Token (Para equipos): [bold green]{service_token}[/bold green]")
        console.print(f"Admin Token (Para consola web): [bold green]{admin_token}[/bold green]")
        
        sign_ans = inquirer.confirm(
            message="¿Deseas exponer el endpoint de Firma de CSRs (Para equipos MikroTik)?",
            default=config["endpoints"]["sign_csr"]
        ).execute()
        config["endpoints"]["sign_csr"] = sign_ans
        
        console.print("\n[bold red]¡Atención![/bold red] Has activado endpoints sensibles.")
        console.print("[dim]Guarda estos tokens. Se han guardado en tu configuración y se usarán para solicitudes automatizadas y administración.[/dim]")
    
    save_config(config)
    console.print("\n[bold green]✅ Configuración generada exitosamente.[/bold green]")
    if api_ans:
        console.print("🚀 Ejecuta [bold cyan]'certberus serve'[/bold cyan] para arrancar la API integrada.")

@app.command()
def serve(
    host: str = typer.Option(None, "--host", help="Host to bind the server to"),
    port: int = typer.Option(None, "--port", help="Port to bind the server to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (development)")
):
    """Start the Certberus REST API server."""
    import uvicorn
    from fastapi import FastAPI
    from .integrations.fastapi import include_certberus_router, lifespan
    
    config = load_config()
    
    if not config["api"]["enabled"]:
        console.print("[yellow]API is disabled in config. Enabling it for this session...[/yellow]")
    
    host = host or config["api"]["host"]
    port = port or config["api"]["port"]
    
    app_api = FastAPI(title="Certberus Universal PKI API", lifespan=lifespan)
    include_certberus_router(app_api)
    
    console.print(f"\n[bold green]🛡️ Certberus API Server Starting[/bold green]")
    console.print(f"URL: [bold cyan]http://{host}:{port}[/bold cyan]")
    console.print("-" * 50 + "\n")
    
    uvicorn.run(app_api, host=host, port=port, reload=reload)

@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Force re-initialization of CA"),
    password: bool = typer.Option(False, "--password", "-p", help="Protect Root and Intermediate with passwords")
):
    """Initialize the certberus Root and Intermediate CAs."""
    root_pwd = os.getenv("DEVCERT_ROOT_PASSWORD")
    inter_pwd = os.getenv("DEVCERT_INTER_PASSWORD")
    
    if password:
        if not root_pwd:
            root_pwd = get_password("Root CA")
            if root_pwd == "MISMATCH": return
        if not inter_pwd:
            inter_pwd = get_password("Intermediate CA")
            if inter_pwd == "MISMATCH": return

    try:
        # Create Root CA
        root_cert = pki.create_root_ca(force=force, password=root_pwd)
        if root_cert:
            save_cert_to_db(root_cert, is_ca=True, profile="ca")
            console.print(f"[green]Root CA initialized at {pki.root_ca_path}[/green]")
        else:
            console.print("[yellow]Root CA already exists.[/yellow]")
            
        # Create Intermediate CA (signed by Root)
        inter_cert = pki.create_intermediate_ca(root_password=root_pwd, inter_password=inter_pwd, force=force)
        if inter_cert:
            save_cert_to_db(inter_cert, is_ca=True, profile="ca", authority_name="default")
            console.print(f"[green]Intermediate CA initialized at {pki.inter_ca_path}[/green]")
            # Save chain
            chain_path = pki.storage_path / "chain.pem"
            with open(chain_path, "wb") as f:
                f.write(pki.get_full_chain())
            console.print(f"[dim]Trust chain saved at {chain_path}[/dim]")
        else:
            console.print("[yellow]Intermediate CA already exists.[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error during initialization: {e}[/red]")

@app.command()
def create(
    common_name: str = typer.Argument(..., help="Common name for the certificate (e.g. localhost)"),
    alt_names: Optional[List[str]] = typer.Option(None, "--alt", "-a", help="Alternative names (SANs)"),
    output_dir: str = typer.Option(".", "--output", "-o", help="Directory to save certificates"),
    profile: str = typer.Option("router", "--profile", help="Device profile for key usage limits (router, iot, server)")
):
    """Create a signed certificate for development."""
    if alt_names is None:
        alt_names = [common_name]
    elif common_name not in alt_names:
        alt_names.append(common_name)
        
    pwd = os.getenv("DEVCERT_INTER_PASSWORD")
    
    # Try signing to see if password is needed
    try:
        if not pwd:
            try:
                pki.sign_certificate(common_name, alt_names, profile=profile)
            except (ValueError, TypeError) as e:
                if "password" in str(e).lower():
                    pwd = Prompt.ask(f"Intermediate CA key is password protected. Enter password", password=True)
                else:
                    raise e
    except FileNotFoundError:
        console.print("[red]CA hierarchy not initialized. Run 'init' first.[/red]")
        return
    except Exception as e:
        console.print(f"[red]Error checking CA: {e}[/red]")
        return
        
    try:
        cert, key, x509_cert = pki.sign_certificate(common_name, alt_names, ca_password=pwd, profile=profile)
        save_cert_to_db(x509_cert, is_ca=False, profile=profile, authority_name="default")
        
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        cert_name = common_name.replace("*", "star")
        cert_file = out_path / f"{cert_name}.crt"
        key_file = out_path / f"{cert_name}.key"
        chain_file = out_path / f"{cert_name}-fullchain.crt"
        
        with open(cert_file, "wb") as f: f.write(cert)
        with open(key_file, "wb") as f: f.write(key)
        
        # Combine leaf and intermediate CA for fullchain
        with open(pki.inter_ca_path, "rb") as f: inter = f.read()
        with open(chain_file, "wb") as f: f.write(cert + inter)
        
        key_file.chmod(0o600)
            
        console.print(f"[green]Certificate created for {common_name} in {output_dir}[/green]")
        console.print(f"[dim]Saved leaf: {cert_file.name}, fullchain: {chain_file.name}[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@app.command()
def install():
    """Install the Root CA into the system trust store (requires sudo)."""
    import subprocess
    
    ca_path = pki.root_ca_path
    if not ca_path.exists():
        console.print("[red]Root CA not found. Run 'init' first.[/red]")
        return
        
    console.print(f"Installing Root CA from {ca_path}...")
    
    dest_path = "/usr/local/share/ca-certificates/certberus-rootCA.crt"
    try:
        subprocess.run(["sudo", "cp", str(ca_path), dest_path], check=True)
        subprocess.run(["sudo", "update-ca-certificates"], check=True)
        console.print("[green]Root CA installed and trusted by the system.[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to install CA: {e}[/red]")

@app.command()
def revoke(
    serial: str = typer.Argument(..., help="Hex serial number of the certificate to revoke"),
    reason: str = typer.Option("unspecified", "--reason", "-r", help="Revocation reason (keyCompromise, superseded, unspecified…)")
):
    """Mark a certificate as revoked in the database."""
    import datetime
    from sqlmodel import select

    async def _revoke():
        config = load_config()
        db_session.init_db(config["database"]["url"])
        await db_session.create_all_tables()
        async with db_session.AsyncSessionLocal() as session:
            result = await session.execute(
                select(Certificate).where(Certificate.serial_number == serial)
            )
            cert = result.scalars().first()
            if not cert:
                console.print(f"[red]Certificate with serial {serial} not found.[/red]")
                return
            if cert.revoked_at:
                console.print(f"[yellow]Certificate already revoked on {cert.revoked_at}.[/yellow]")
                return
            cert.revoked_at = datetime.datetime.now(datetime.timezone.utc)
            cert.revoke_reason = reason
            session.add(cert)
            await session.commit()
            console.print(f"[green]✅ Certificate '{cert.common_name}' (serial: {serial[:12]}…) revoked.[/green]")
            console.print(f"[dim]Reason: {reason}. Run 'certberus crl' to regenerate the CRL file.[/dim]")

    asyncio.run(_revoke())

@app.command()
def crl(
    output: str = typer.Option("crl.pem", "--output", "-o", help="Output path for the CRL file"),
    days: int = typer.Option(7, "--days", "-d", help="Days until CRL expires"),
    ca_password: Optional[str] = typer.Option(None, "--password", "-p", help="Intermediate CA password (if protected)")
):
    """Generate and export a signed Certificate Revocation List (CRL)."""
    from sqlmodel import select

    async def _build_crl():
        config = load_config()
        db_session.init_db(config["database"]["url"])
        await db_session.create_all_tables()
        async with db_session.AsyncSessionLocal() as session:
            result = await session.execute(
                select(Certificate).where(Certificate.revoked_at != None)  # noqa: E711
            )
            revoked = result.scalars().all()

        if not revoked:
            console.print("[yellow]No revoked certificates found. CRL will be empty.[/yellow]")

        revoked_meta = [
            {"serial_number": c.serial_number, "revoked_at": c.revoked_at}
            for c in revoked
        ]

        pwd = ca_password or os.getenv("CERTBERUS_INTER_PASSWORD")
        crl_pem = pki.generate_crl(revoked_meta, ca_password=pwd, days=days)

        out_path = Path(output)
        out_path.write_bytes(crl_pem)
        console.print(f"[green]✅ CRL generated: {out_path.resolve()} ({len(revoked)} revoked cert(s)).[/green]")
        console.print(f"[dim]Valid for {days} days. Publish this file so devices can download it via HTTP.[/dim]")

    asyncio.run(_build_crl())

if __name__ == "__main__":
    app()
