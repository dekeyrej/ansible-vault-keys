import sys
import argparse
import pytest
from ansible_vault_keys.cli import read_commandline_args

def test_encrypt_command_parsing(monkeypatch):
    test_args = [
        "encrypt",
        "sample.yaml",
        "--vault-password-file", "vault_password.txt",
        "--keys", "password", "api_key",
        "--dry-run"
    ]
    monkeypatch.setattr(sys, "argv", ["prog"] + test_args)
    args = read_commandline_args()

    assert args.command == "encrypt"
    assert args.input == "sample.yaml"
    assert args.vault_password_file == "vault_password.txt"
    assert args.keys == ["password", "api_key"]
    assert args.dry_run is True

def test_decrypt_command_ignores_keys(monkeypatch):
    test_args = [
        "decrypt",
        "sample.yaml",
        "--keys", "should_be_ignored"
    ]
    monkeypatch.setattr(sys, "argv", ["prog"] + test_args)
    args = read_commandline_args()

    assert args.command == "decrypt"
    assert args.input == "sample.yaml"
    assert args.keys == ["should_be_ignored"]  # still parsed, but ignored later

def test_missing_required_args(monkeypatch):
    test_args = ["encrypt"]
    monkeypatch.setattr(sys, "argv", ["prog"] + test_args)
    with pytest.raises(SystemExit):
        read_commandline_args()

def test_default_output(monkeypatch):
    test_args = ["encrypt", "sample.yaml"]
    monkeypatch.setattr(sys, "argv", ["prog"] + test_args)
    args = read_commandline_args()
    assert args.output is None  # will default to input file later