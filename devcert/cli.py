import typer
import os
from .pki import PKIService
from rich.console import Console

app = typer.Typer()
console = Console()
pki = PKIService()

@app.command()
def init(force: bool = typer.Option(False, "--force", "-f", help="Force re-initialization of CA")):
    """Initialize the devcert Root CA."""
    success = pki.create_ca(force=force)
    if success:
        console.print(f"[green]Root CA initialized at {pki.ca_path}[/green]")
    else:
        console.print("[yellow]Root CA already exists. Use --force to recreate it.[/yellow]")

@app.command()
def create(
    common_name: str = typer.Argument(..., help="Common name for the certificate (e.g. localhost)"),
    alt_names: list[str] = typer.Option(None, "--alt", "-a", help="Alternative names (SANs)"),
    output_dir: str = typer.Option(".", "--output", "-o", help="Directory to save certificates")
):
    """Create a signed certificate for development."""
    if alt_names is None:
        alt_names = [common_name]
    elif common_name not in alt_names:
        alt_names.append(common_name)
        
    try:
        cert, key = pki.sign_certificate(common_name, alt_names)
        
        cert_name = common_name.replace("*", "star")
        cert_path = os.path.join(output_dir, f"{cert_name}.crt")
        key_path = os.path.join(output_dir, f"{cert_name}.key")
        
        with open(cert_path, "wb") as f:
            f.write(cert)
        with open(key_path, "wb") as f:
            f.write(key)
            
        console.print(f"[green]Certificate and key created for {common_name} in {output_dir}[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@app.command()
def install():
    """Install the Root CA into the system trust store (requires sudo)."""
    import subprocess
    
    ca_path = pki.ca_path
    if not os.path.exists(ca_path):
        console.print("[red]CA not found. Run 'init' first.[/red]")
        return
        
    console.print(f"Installing CA from {ca_path}...")
    
    # Linux (Ubuntu/Debian) logic
    dest_path = "/usr/local/share/ca-certificates/devcert-rootCA.crt"
    try:
        # Copy file
        subprocess.run(["sudo", "cp", ca_path, dest_path], check=True)
        # Update trust store
        subprocess.run(["sudo", "update-ca-certificates"], check=True)
        console.print("[green]Root CA installed and trusted by the system.[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to install CA: {e}. Do you have sudo permissions?[/red]")

if __name__ == "__main__":
    app()
