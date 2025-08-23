import pytest
from tools.ansible_vault_keys.dotpath_utils import (
    expand_dot_path_wildcards,
    encrypt_dot_path_recursively,
    decrypt_dot_path_recursively,
    decrypt_all_tagged_scalars,
)
from tools.ansible_vault_keys.vault_utils import initialize_vault
from ruamel.yaml.comments import TaggedScalar

@pytest.fixture
def vault():
    return initialize_vault("tools/tests/vault_password.txt")

@pytest.fixture
def sample_data():
    return {
        "servers": [
            {"password": "one"},
            {"password": "two"},
        ],
        "api": {
            "key": "hunter2"
        }
    }

def test_expand_dot_path_wildcards(sample_data):
    paths = expand_dot_path_wildcards(sample_data, "servers.*.password")
    assert paths == ["servers.0.password", "servers.1.password"]

def test_encrypt_dot_path_recursively(vault, sample_data):
    success = encrypt_dot_path_recursively(sample_data, "api.key", vault)
    assert success
    assert isinstance(sample_data["api"]["key"], TaggedScalar)

def test_decrypt_dot_path_recursively(vault, sample_data):
    encrypt_dot_path_recursively(sample_data, "api.key", vault)
    success = decrypt_dot_path_recursively(sample_data, "api.key", vault)
    assert success
    assert sample_data["api"]["key"] == "hunter2"

def test_decrypt_all_tagged_scalars(vault, sample_data):
    encrypt_dot_path_recursively(sample_data, "api.key", vault)
    encrypt_dot_path_recursively(sample_data, "servers.0.password", vault)
    paths = decrypt_all_tagged_scalars(sample_data, vault)
    assert set(paths) == {"api.key", "servers.0.password"}
    assert sample_data["api"]["key"] == "hunter2"
    assert sample_data["servers"][0]["password"] == "one"