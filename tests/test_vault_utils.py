import pytest
from tools.ansible_vault_keys.vault_utils import (
    initialize_vault,
    ansible_vault_encrypt_str,
    ansible_vault_decrypt_str,
    vault_tagged_scalar,
)
from ruamel.yaml.comments import TaggedScalar
from ruamel.yaml.scalarstring import LiteralScalarString

@pytest.fixture
def vault():
    return initialize_vault("tools/tests/vault_password.txt")

def test_encrypt_decrypt_roundtrip(vault):
    original = "hunter2"
    encrypted = ansible_vault_encrypt_str(vault, original)
    decrypted = ansible_vault_decrypt_str(vault, encrypted)
    assert decrypted == original

def test_vault_tagged_scalar_format(vault):
    value = "hunter2"
    tagged = vault_tagged_scalar(vault, value)
    assert isinstance(tagged, TaggedScalar)
    assert tagged.tag == "!vault"
    assert isinstance(tagged.value, LiteralScalarString)
    assert tagged.style == "|"

def test_vault_tagged_scalar_passthrough(vault):
    value = "already_encrypted"
    tagged = TaggedScalar(LiteralScalarString(value), tag="!vault", style="|")
    result = vault_tagged_scalar(vault, tagged)
    assert result is tagged  # should return unchanged

def test_encrypt_failure(monkeypatch, vault):
    monkeypatch.setattr(vault, "encrypt", lambda x: (_ for _ in ()).throw(Exception("fail")))
    result = ansible_vault_encrypt_str(vault, "hunter2")
    assert result == "hunter2"  # fallback to original

def test_initialize_vault_no_password_file_no_ansible_cfg(monkeypatch):
    # Simulate no ansible.cfg found
    monkeypatch.setattr("tools.ansible_vault_keys.vault_utils.find_ansible_config", lambda: None)

    # Expect sys.exit(1) due to missing password file
    with pytest.raises(SystemExit) as excinfo:
        initialize_vault(None)

    assert excinfo.value.code == 1

def test_initialize_vault_with_config_fallback(monkeypatch, tmp_path):
    # Create a vault password file
    vault_file = tmp_path / "vault_password.txt"
    vault_file.write_text("hunter2")

    # Create a fake ansible.cfg that points to it
    config_file = tmp_path / "ansible.cfg"
    config_file.write_text(f"""
[defaults]
vault_password_file = {vault_file}
""")

    # Monkeypatch find_ansible_config to return our fake config
    monkeypatch.setattr("tools.ansible_vault_keys.vault_utils.find_ansible_config", lambda: str(config_file))

    # Call initialize_vault with None to trigger fallback
    vault = initialize_vault(None)

    # Assert it can encrypt/decrypt a known string
    encrypted = vault.encrypt("secret").decode("utf-8")
    decrypted = vault.decrypt(encrypted).decode("utf-8")
    assert decrypted == "secret"
