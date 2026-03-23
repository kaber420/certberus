import typer
import os
from pathlib import Path
from typing import Optional, List
from .pki import PKIService
from rich.console import Console
from rich.prompt import Prompt

app = typer.Typer(help="devcert: A Python-native mkcert alternative.")
console = Console()
pki = PKIService()

@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Force re-initialization of CA"),
    password: bool = typer.Option(False, "--password", "-p", help="Protect Root CA with a password")
):
    """Initialize the devcert Root CA."""
    pwd = None
    if password:
        pwd = Prompt.ask("Enter password to protect Root CA", password=True)
        confirm = Prompt.ask("Confirm password", password=True)
        if pwd != confirm:
            console.print("[red]Passwords do not match![/red]")
            return

    try:
        success = pki.create_ca(force=force, password=pwd)
        if success:
            console.print(f"[green]Root CA initialized at {pki.ca_path}[/green]")
            console.print(f"[dim]Permissions set to 600 for {pki.ca_key_path.name}[/dim]")
        else:
            console.print("[yellow]Root CA already exists. Use --force to recreate it.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@app.command()
def create(
    common_name: str = typer.Argument(..., help="Common name for the certificate (e.g. localhost)"),
    alt_names: Optional[List[str]] = typer.Option(None, "--alt", "-a", help="Alternative names (SANs)"),
    output_dir: str = typer.Option(".", "--output", "-o", help="Directory to save certificates")
):
    """Create a signed certificate for development."""
    if alt_names is None:
        alt_names = [common_name]
    elif common_name not in alt_names:
        alt_names.append(common_name)
        
    pwd = None
    # Check if CA key is password protected by trying to load it without one
    # Note: A better way would be to catch the specific exception from cryptography
    try:
        pki.sign_certificate(common_name, alt_names)
    except (ValueError, TypeError) as e:
        if "password" in str(e).lower():
            pwd = Prompt.ask(f"CA key at {pki.ca_key_path.name} is password protected. Enter password", password=True)
        else:
            console.print(f"[red]Error checking CA: {e}[/red]")
            return
    except FileNotFoundError:
        console.print("[red]CA not found. Run 'init' first.[/red]")
        return
    except Exception:
        # If it worked, we'll run it again below with actual saving
        pass
        
    try:
        cert, key = pki.sign_certificate(common_name, alt_names, ca_password=pwd)
        
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        cert_name = common_name.replace("*", "star")
        cert_file = out_path / f"{cert_name}.crt"
        key_file = out_path / f"{cert_name}.key"
        
        with open(cert_file, "wb") as f:
            f.write(cert)
        with open(key_file, "wb") as f:
            f.write(key)
            
        # Set permissions for the newly created leaf key
        key_file.chmod(0o600)
            
        console.print(f"[green]Certificate and key created for {common_name} in {output_dir}[/green]")
        console.print(f"[dim]Key file {key_file.name} secured with 600 permissions.[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@app.command()
def install():
    """Install the Root CA into the system trust store (requires sudo)."""
    import subprocess
    
    ca_path = pki.ca_path
    if not ca_path.exists():
        console.print("[red]CA not found. Run 'init' first.[/red]")
        return
        
    console.print(f"Installing CA from {ca_path}...")
    
    # Linux (Ubuntu/Debian) logic
    dest_path = "/usr/local/share/ca-certificates/devcert-rootCA.crt"
    try:
        # Copy file
        subprocess.run(["sudo", "cp", str(ca_path), dest_path], check=True)
        # Update trust store
        subprocess.run(["sudo", "update-ca-certificates"], check=True)
        console.print("[green]Root CA installed and trusted by the system.[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to install CA: {e}. Do you have sudo permissions?[/red]")

if __name__ == "__main__":
    app()
