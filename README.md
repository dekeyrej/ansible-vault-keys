# ansible-vault-keys

![Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-Passing-green?style=flat-square)
![License](https://img.shields.io/github/license/dekeyrej/ansible-vault-keys?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![Repo Size](https://img.shields.io/github/repo-size/dekeyrej/ansible-vault-keys?style=flat-square)
![Last Commit](https://img.shields.io/github/last-commit/dekeyrej/ansible-vault-keys?style=flat-square)
[![PyPI](https://img.shields.io/pypi/v/ansible-vault-keys?style=flat-square)](https://pypi.org/project/ansible-vault-keys/)
![Encryption Style](https://img.shields.io/badge/Encryption-Selective%20%26%20Elegant-purple?style=flat-square)
![YAML Fidelity](https://img.shields.io/badge/YAML-Roundtrip%20Safe-yellow?style=flat-square)

Selective encryption of YAML keys using Ansible Vault — with full round-trip support.

## ✨ Why?

Ansible Vault is great for securing secrets, but encrypting entire files makes them opaque and hard to document. 

This tool lets you encrypt only the sensitive keys in your YAML files, preserving:

- ✅ Comments
- ✅ Key order
- ✅ Formatting
- ✅ Readability

No more guessing what's inside a vault-encrypted blob. Just mark the keys you want to encrypt, and keep the rest visible.

## 🧙‍♂️ Philosophy

This tool is itended to be a _companion_ to `ansible-vault`, not a replacement. It’s built for clarity, maintainability, and expressive workflows — especially when documenting or collaborating on infrastructure.

Think of it as a scribe that encrypts only what must be hidden, while preserving the story around it. In keeping with the design goals - Your YAML remains readable, annotated, and collaborative — even when secrets are tucked away.

## 🚀 Quickstart

Encrypt selected keys in a YAML file:

```bash
ansible-vault-keys encrypt somevars.yaml
```

Decrypt them later:
```bash
ansible-vault-keys decrypt somevars.yaml
```

View decrypted values without modifying the file
```bash
ansible-vault-keys view somevars.yaml
```

### 🧾 Before

```yaml
# somevars.yaml
plain: value
# this one is sensitive v
password: somesensitivevalue
user: bob
# so is this one v
apikey: nue6756be8cs83jn2l4
encrypted_keys: [password, apikey]
```

### 🔐 After Encryption

```yaml
# somevars.yaml
plain: value
# this one is sensitive v
password: !vault |  # 🔐 Encrypted keys are marked with !vault
  $ANSIBLE_VAULT;1.1;AES256
  ...
user: bob
# so is this one v
apikey: !vault |   # 🔐 Encrypted keys are marked with !vault
  $ANSIBLE_VAULT;1.1;AES256
  ...
encrypted_keys: [password, apikey]
```

```🔐 Encrypted keys are marked with !vault``` This comment is for illustration only — it’s not included in the actual output.


#### Commands Table:
| Command | Description |
|--------|-------------|
| `encrypt` | Encrypts keys listed in `encrypted_keys` or specified with --keys  |
| `decrypt` | Decrypts all vault-encrypted values |
| `view` | Displays decrypted values without modifying the file |

#### Flags Table:
| Flag | Description |
|------|-------------|
| `--dry-run` | Show changes without writing to file |
| `--vault-password-file` | Path to vault password file (default: `vault.password`) |
| `--keys` | Merge with `encrypted_keys` list from YAML |

### **Clarify the `--keys` Behavior**

> ⚠️ Note: `--keys` are merged with any existing `encrypted_keys` list during encryption.

### Usage:
```bash
usage: ansible-vault-keys [-h] [--output [OUTPUT]] [--vault-password-file VAULT_PASSWORD_FILE] [--keys KEYS [KEYS ...]] [--dry-run] {encrypt,decrypt,view} input

Selectively encrypt sensitive variables

positional arguments:
  {encrypt,decrypt,view}
                        Command to execute
  input                 Path to input YAML file

options:
  -h, --help            show this help message and exit
  --output [OUTPUT]     Path to output YAML file (optional), defaults to input file, will clobber without warning
  --vault-password-file VAULT_PASSWORD_FILE
                        Path to vault password file
  --keys KEYS [KEYS ...]
                        Keys to encrypt
  --dry-run             Show changes without writing to file
```


## 📦 Install

Install locally for CLI use:
```bash
pip install .
```

Or build a wheel:
```bash
python -m build
```

After installation, the ansible-vault-keys command will be available in your shell.

## 📝 License
MIT
