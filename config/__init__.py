"""Configuration package for Ransomware Tripwire & Automated Host Isolation."""
from pathlib import Path
import yaml

CONFIG_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = CONFIG_DIR / "tripwire_config.yaml"

def load_config(config_path: Path = CONFIG_FILE) -> dict:
    """Load tripwire YAML configuration."""
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)
