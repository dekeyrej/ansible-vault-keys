import pytest
from ansible_vault_keys.dotpath_utils import (
    expand_dot_path_wildcards,
    encrypt_dot_path_recursively,
    decrypt_all_tagged_scalars,
)
from ansible_vault_keys.vault_utils import initialize_vault
from ruamel.yaml.comments import TaggedScalar

@pytest.fixture
def vault():
    return initialize_vault("tests/vault_password.txt")

@pytest.fixture
def sample_data():
    return {
        "somekey": "value",
        "servers": [
            {"password": "one"},
            {"password": "two"},
        ],
        "api": {
            "key": "hunter2"
        },
        "simplelist": [
            "item1",
            "item2"
        ]
    }

def test_expand_dot_path_wildcards(sample_data):
    paths = expand_dot_path_wildcards(sample_data, "simplelist.*")
    assert paths == ["simplelist.0", "simplelist.1"]
    paths = expand_dot_path_wildcards(sample_data, "servers.*.password")
    assert paths == ["servers.0.password", "servers.1.password"]
    paths = expand_dot_path_wildcards(sample_data, "api.*")
    assert paths == ["api.key"]
    paths = expand_dot_path_wildcards(sample_data, "servers.1.password")
    assert paths == ["servers.1.password"]

def test_encrypt_dot_path_recursively(vault, sample_data):
    success = encrypt_dot_path_recursively(sample_data, "api.key", vault)
    assert success
    assert isinstance(sample_data["api"]["key"], TaggedScalar)
    success = encrypt_dot_path_recursively(sample_data, "simplelist.0", vault)
    assert success
    assert isinstance(sample_data["simplelist"][0], TaggedScalar)
    success = encrypt_dot_path_recursively(sample_data, "servers.1.username", vault)
    assert not success
    success = encrypt_dot_path_recursively(sample_data, "simplelist.username", vault)
    assert not success
    success = encrypt_dot_path_recursively(sample_data, "somekey.1", vault)
    assert not success

# def test_decrypt_dot_path_recursively(vault, sample_data):
#     encrypt_dot_path_recursively(sample_data, "api.key", vault)
#     success = decrypt_dot_path_recursively(sample_data, "api.key", vault)
#     assert success
#     assert sample_data["api"]["key"] == "hunter2"
#     encrypt_dot_path_recursively(sample_data, "servers.0.password", vault)
#     success = decrypt_dot_path_recursively(sample_data, "servers.0.password", vault)
#     assert success
#     assert sample_data["servers"][0]["password"] == "one"
#     encrypt_dot_path_recursively(sample_data, "simplelist.0", vault)
#     success = decrypt_dot_path_recursively(sample_data, "simplelist.0", vault)
#     assert success
#     assert sample_data["simplelist"][0] == "item1"
#     encrypt_dot_path_recursively(sample_data, "simplelist.0", vault)
#     success = decrypt_dot_path_recursively(sample_data, "simplelist.3", vault)
#     assert not success
#     encrypt_dot_path_recursively(sample_data, "simplelist.0", vault)
#     success = decrypt_dot_path_recursively(sample_data, "simplelist.1", vault)
#     assert not success
#     encrypt_dot_path_recursively(sample_data, "api.key", vault)
#     success = decrypt_dot_path_recursively(sample_data, "api.user", vault)
#     assert not success
#     encrypt_dot_path_recursively(sample_data, "api.key", vault)
#     success = decrypt_dot_path_recursively(sample_data, "api.key.version", vault)
#     assert not success

def test_decrypt_all_tagged_scalars(vault, sample_data):
    encrypt_dot_path_recursively(sample_data, "api.key", vault)
    encrypt_dot_path_recursively(sample_data, "servers.0.password", vault)
    encrypt_dot_path_recursively(sample_data, "simplelist.0", vault)
    paths = decrypt_all_tagged_scalars(sample_data, vault)
    assert set(paths) == {"api.key", "servers.0.password", "simplelist.0"}
    assert sample_data["api"]["key"] == "hunter2"
    assert sample_data["servers"][0]["password"] == "one"
    assert sample_data["simplelist"][0] == "item1"