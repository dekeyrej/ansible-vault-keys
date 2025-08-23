import os
import tempfile

import pytest
from ansible_vault_keys.yaml_io import read_input_file, write_output_file
from ruamel.yaml import YAML

yaml = YAML()
yaml.preserve_quotes = True
yaml.default_flow_style = False

def test_read_input_file_parses_yaml():
    sample = """
    # This is a comment
    username: admin
    password: secret
    """
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write(sample)
        f.flush()
        path = f.name

    data = read_input_file(path)
    assert data["username"] == "admin"
    assert data["password"] == "secret"
    os.remove(path)

def test_read_input_file_parses_bad_yaml():
    sample = """
    # This is a comment
    username:admin
    password: secret
    """
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write(sample)
        f.flush()
        path = f.name

    with pytest.raises(SystemExit):
        data = read_input_file(path)

    os.remove(path)

def test_read_input_file_parses_non_existent_yaml():

    with pytest.raises(SystemExit):
        data = read_input_file('non_existent_file.yaml')


def test_write_output_file_preserves_formatting():
    data = {
        "username": "admin",
        "password": "secret"
    }
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        path = f.name

    write_output_file(path, data)

    with open(path, "r") as f:
        output = f.read()

    assert "username: admin" in output
    assert "password: secret" in output
    os.remove(path)

def test_round_trip_preserves_data():
    original = {
        "username": "admin",
        "password": "secret"
    }
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        path = f.name

    write_output_file(path, original)
    loaded = read_input_file(path)
    assert loaded == original
    os.remove(path)