import os
import sys
import tempfile
import pytest
from ansible_vault_keys import main as vault_main

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
    items:
    - name: item1
      value: 123
    - name: item2
      value: 456
    api:
      key: hunter2
    """
    path = tmp_path / "sample.yaml"
    path.write_text(content)
    return str(path)

@pytest.fixture
def bad_sample_yaml(tmp_path):
    content = """
    username: admin
    password: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      33396266623537323464346438616364613537336231323232353761303638613135393765353637
      3137643136636264326534636263393661643434636662360a336139376632633735393162643833
      30306531326131636337306533343637306537383431323161333361336564313334633033633833
      6237343334653633380a373934653636306365653961383736633361353231346139383433373731
      6661
    items:
    - name: item1
      value: 123
    - name: item2
      value: 456
    api:
      key: !vault |
        $ANSIBLE_VAULT;1.1;AES256
        33313233663063303835633531393164656336666666636230363633383665623333363338626463
        3633666565383739326132333266396239663062313630620a366130656331396238363661623938
        64643431326635396432396661313738653930326532626562313765303137626335363763323133
        6337326138666232360a303936626436313038633137643238643462666237636362666436643738
        3132
    """
    path = tmp_path / "bad_sample.yaml"
    path.write_text(content)
    return str(path)

def test_encrypt_and_decrypt_flow(monkeypatch, sample_yaml, vault_file):
    # Encrypt
    monkeypatch.setattr(sys, "argv", [
        "prog",
        "encrypt",
        sample_yaml,
        "--vault-password-file", vault_file,
        "--keys", "password", "api.key",  "items.*.value", "bobs.*", "api.user"
    ])
    vault_main.main()

    # Load and check encryption
    with open(sample_yaml) as f:
        data = yaml.load(f)
    assert "encrypted_keys" in data
    assert set(data["encrypted_keys"]) == {"password", "api.key", "items.0.value", "items.1.value"}
    assert data["password"].tag == "!vault"
    
    # Decrypt
    monkeypatch.setattr(sys, "argv", [
        "prog",
        "decrypt",
        sample_yaml,
        "--keys", "password", "api.key",
        "--vault-password-file", vault_file
    ])
    vault_main.main()

    # Load and check decryption
    with open(sample_yaml) as f:
        data = yaml.load(f)
    assert data["password"] == "secret"
    assert data["api"]["key"] == "hunter2"

def test_encrypt_and_view_flow(monkeypatch, sample_yaml, vault_file, capsys):
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
        "view",
        sample_yaml,
        "--vault-password-file", vault_file
    ])
    vault_main.main()
    # Capture output
    captured = capsys.readouterr()
    assert "username: admin" in captured.out
    assert "password: secret" in captured.out
    assert "key: hunter2" in captured.out

def test_decrypt_flow(monkeypatch, bad_sample_yaml, vault_file):

    # Decrypt
    monkeypatch.setattr(sys, "argv", [
        "prog",
        "decrypt",
        bad_sample_yaml,
        "--keys", "password", "api.key",
        "--vault-password-file", vault_file
    ])
    vault_main.main()

    # Load and check decryption
    with open(bad_sample_yaml) as f:
        data = yaml.load(f)
    assert data["password"] == "secret"
    assert data["api"]["key"] == "hunter2"

def test_encrypt_dry_run(monkeypatch, sample_yaml, vault_file, capsys):
    # Encrypt
    monkeypatch.setattr(sys, "argv", [
        "prog",
        "encrypt",
        sample_yaml,
        "--vault-password-file", vault_file,
        "--keys", "password", "api.key",
        "--dry-run"
    ])
    vault_main.main()
    # Capture output
    captured = capsys.readouterr()
    assert "username: admin" in captured.out
    assert "password: !vault |" in captured.out
    assert "encrypted_keys:" in captured.out