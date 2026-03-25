import os
from pathlib import Path
import toml

def get_default_config_path() -> Path:
    config_home = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "certberus" / "config.toml"

def get_default_storage_path() -> Path:
    data_home = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return data_home / "certberus"

def get_default_config():
    storage = get_default_storage_path()
    return {
        "core": {
            "storage_path": str(storage),
            "auto_init": False
        },
        "database": {
            "url": f"sqlite+aiosqlite:///{storage}/certs.db"
        },
        "api": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8443,
            "tls_cert": "certberus_api.pem",
            "tls_key": "certberus_api_key.pem"
        },
        "endpoints": {
            "crl_publishing": True,
            "ca_publishing": True,
            "sign_csr": False,
            "issue_cert": False
        },
        "security": {
            "auth_mode": "token"
        }
    }

def load_config(path: Path = None):
    if path is None:
        path = get_default_config_path()
    
    if not path.exists():
        return get_default_config()
        
    with open(path, "r") as f:
        user_config = toml.load(f)
        
    # Merge with default config to ensure all keys exist
    config = get_default_config()
    for section, values in user_config.items():
        if section in config and isinstance(values, dict):
            config[section].update(values)
        else:
            config[section] = values
            
    return config

def save_config(config: dict, path: Path = None):
    if path is None:
        path = get_default_config_path()
        
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        toml.dump(config, f)
