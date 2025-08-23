import os
import sys
import tempfile
import pytest
from tools.ansible_vault_keys import main as vault_main

from ruamel.yaml import YAML

yaml = YAML()
yaml.preserve_quotes = True
yaml.default_flow_style = False

@pytest.fixture
def vault_file(tmp_path):
    path = tmp_path / "vault_password.txt"
    path.write_text("hunter2")
    return str(path)

@pytest.fixture
def sample_yaml(tmp_path):
    content = """
    username: admin
    password: secret
    api:
      key: hunter2
    """
    path = tmp_path / "sample.yaml"
    path.write_text(content)
    return str(path)

def test_encrypt_and_decrypt_flow(monkeypatch, sample_yaml, vault_file):
    # Encrypt
    monkeypatch.setattr(sys, "argv", [
        "prog",
        "encrypt",
        sample_yaml,
        "--vault-password-file", vault_file,
        "--keys", "password", "api.key"
    ])
    vault_main.main()

    # Load and check encryption
    with open(sample_yaml) as f:
        data = yaml.load(f)
    assert "encrypted_keys" in data
    assert set(data["encrypted_keys"]) == {"password", "api.key"}
    assert data["password"].tag == "!vault"
    
    # Decrypt
    monkeypatch.setattr(sys, "argv", [
        "prog",
        "decrypt",
        sample_yaml,
        "--vault-password-file", vault_file
    ])
    vault_main.main()

    # Load and check decryption
    with open(sample_yaml) as f:
        data = yaml.load(f)
    assert data["password"] == "secret"
    assert data["api"]["key"] == "hunter2"

    