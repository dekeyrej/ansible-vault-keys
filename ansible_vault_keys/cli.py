import argparse
from ansible_vault_keys import __version__

def read_commandline_args():
    ap = argparse.ArgumentParser(description="Selectively encrypt sensitive variables")
    ap.add_argument("command", choices=["encrypt", "decrypt", "view"], help="Command to execute")  # maybe "edit" in the future
    ap.add_argument("input", help="Path to input YAML file")
    ap.add_argument("--output", nargs="?", default=None, help="Path to output YAML file (optional), defaults to input file, will clobber without warning")
    ap.add_argument("--vault-password-file", default='vault.password', help="Path to vault password file")
    ap.add_argument("--keys", nargs="+", default=[], help="Keys to encrypt")
    ap.add_argument("--dry-run", action="store_true", help="Show changes without writing to file")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args()