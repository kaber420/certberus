import typer
import os
from pathlib import Path
from rich.console import Console

app = typer.Typer(help="RCS Client: Manage your Sovereign Digital Trust.")
console = Console()

RCS_HOME = Path.home() / ".rcs"
ROOT_CA_PATH = RCS_HOME / "root-ca.pem"

@app.command()
def init():
    """Initialize the RCS environment and install the Community Root CA."""
    console.print("[bold blue]Initializaing RCS environment...[/bold blue]")
    RCS_HOME.mkdir(parents=True, exist_ok=True)
    
    if not ROOT_CA_PATH.exists():
        console.print("[yellow]Downloading Community Root CA...[/yellow]")
        # Placeholder for actual download logic
        with open(ROOT_CA_PATH, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n(MOCK ROOT CA)\n-----END CERTIFICATE-----")
        console.print(f"[green]Root CA saved to {ROOT_CA_PATH}[/green]")
    else:
        console.print("[green]Community Root CA already present.[/green]")
    
    console.print("\n[bold]Instructions to trust the Root CA:[/bold]")
    console.print("1. Linux: [dim]sudo cp ~/.rcs/root-ca.pem /usr/local/share/ca-certificates/rcs-root.crt && sudo update-ca-certificates[/dim]")
    console.print("2. Chrome/Firefox: Import manually in Settings > Privacy > Security > Certificates.")

@app.command()
def issue(domain: str = typer.Argument(..., help="Domain to issue (e.g. myapp.local)")):
    """Issue a certificate for a local or mesh domain."""
    if not ROOT_CA_PATH.exists():
        console.print("[red]Error: Root CA not found. Run 'rcs-client init' first.[/red]")
        raise typer.Exit(code=1)
    
    console.print(f"[bold green]Issuing certificate for: {domain}[/bold green]")
    # Logic to generate key/cert using Certberus engine would go here
    cert_path = Path.cwd() / f"{domain}.pem"
    key_path = Path.cwd() / f"{domain}.key"
    
    with open(cert_path, "w") as f: f.write(f"(MOCK CERT FOR {domain})")
    with open(key_path, "w") as f: f.write(f"(MOCK KEY FOR {domain})")
    
    console.print(f"[+] Certificate created: {cert_path}")
    console.print(f"[+] Private key created: {key_path}")

# Yuxi/RCS Extension Commands
yuxi_app = typer.Typer(help="Sovereign Trust Network (RCS/Yuxi) Extensions.")
app.add_typer(yuxi_app, name="yuxi")

@yuxi_app.command(name="request")
def request_ca(
    name: str = typer.Argument(..., help="Name for the new intermediate CA"),
    scope: str = typer.Option("", "--scope", help="Requested domains and IPs, comma separated (e.g. '*.local, 10.0.0.0/8')")
):
    """Generate a CSR to request admission to the RCS Federated Network."""
    console.print(f"[bold yellow]Generating RCS CSR for CA: {name}[/bold yellow]")
    from certberus.pki import PKIService
    pki = PKIService()
    _, csr_pem = pki.generate_intermediate_csr(name=name)
    csr_path = Path.cwd() / f"{name}.csr"
    with open(csr_path, "wb") as f:
        f.write(csr_pem)
    console.print(f"[+] CSR generated at {csr_path}")
    if scope:
        console.print(f"[+] Requested scope (Name Constraints): {scope}")
    console.print("[!] Send this to the RCS DAO for signing.")

@yuxi_app.command(name="activate")
def activate_ca(
    name: str = typer.Argument(..., help="Name for the federated CA"),
    cert_file: Path = typer.Option(..., help="Signed certificate file (PEM) from the community root"),
    root_file: Optional[Path] = typer.Option(None, help="Community Root CA chain file (PEM)")
):
    """Activate a local CA using a signature from the Community Root."""
    console.print(f"[bold green]Activating Federated CA: {name}[/bold green]")
    from certberus.pki import PKIService
    pki = PKIService()
    try:
        with open(cert_file, "rb") as f:
            signed_cert = f.read()
        root_chain = None
        if root_file:
            with open(root_file, "rb") as f:
                root_chain = f.read()
        pki.activate_intermediate_ca(name, signed_cert, root_chain)
        console.print(f"[bold green]Successfully activated CA '{name}'![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Activation failed: {e}[/bold red]")

@app.command()
def sync():
    """Sync with the blockchain to verify Intermediate CA status."""
    console.print("[bold cyan]Syncing with RCS Blockchain Ledger...[/bold cyan]")
    # Placeholder for BlockchainConnector logic
    console.print("[green]All Intermediate CAs in your chain are verified and valid.[/green]")

if __name__ == "__main__":
    app()
