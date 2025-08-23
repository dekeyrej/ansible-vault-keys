import logging
import sys
from ansible.parsing.vault import VaultLib, VaultSecret
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ruamel.yaml.scalarstring import LiteralScalarString
from ruamel.yaml.comments import TaggedScalar

def find_ansible_config():
    import os
    # look for ansible.cfg in ./ansible.cfg, ~/.ansible.cfg, /etc/ansible/ansible.cfg
    config_paths = [
        './ansible.cfg',
        os.path.expanduser('~/.ansible.cfg'),
        '/etc/ansible/ansible.cfg'
    ]
    for path in config_paths:
        if os.path.exists(path):
            logging.debug(f"Found Ansible config at: {path}")
            return path
    logging.warning("No Ansible config found.")
    return None

def initialize_vault(password_file_path=None):
    logging.debug(f"Passed vault password file: {password_file_path}")
    if not password_file_path:
        config_file_path = find_ansible_config()
        if config_file_path:
            import configparser
            config = configparser.ConfigParser()
            config.read(config_file_path)
            password_file_path = config.get("defaults", "vault_password_file", fallback=password_file_path)
        else:
            logging.error("No Ansible config found.")
            sys.exit(1)
    try:
        with open(password_file_path, 'r') as pf:
            vault_password = pf.read().strip()
    except FileNotFoundError:
        logging.error(f"File not found: {password_file_path}")
        sys.exit(1)
    return VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(vault_password.encode()))])

def ansible_vault_encrypt_str(vault, value_str) -> str:
    try:
        encrypted_value = vault.encrypt(value_str)
        return encrypted_value.decode('utf-8')  # Decode bytes to string
    except Exception as e:
        logging.error(f"Error encrypting vault: {e}")
        return value_str
    
def ansible_vault_decrypt_str(vault, value_str) -> str:
    try:
        decrypted_value = vault.decrypt(value_str)
        return decrypted_value.decode('utf-8')  # Decode bytes to string
    except Exception as e:
        logging.error(f"Error decrypting vault: {e}")
        return value_str

def vault_tagged_scalar(vault, value_str):
    if isinstance(value_str, TaggedScalar):  # it's already encrypted
        return value_str
    encrypted_value = ansible_vault_encrypt_str(vault, value_str)
    if encrypted_value.startswith('$ANSIBLE_VAULT;'):
        return TaggedScalar(LiteralScalarString(encrypted_value), tag='!vault', style='|')
    else: # quietly failed to encrypt the string
        return encrypted_value
    
