from ansible_vault_keys.vault_utils import ansible_vault_decrypt_str, vault_tagged_scalar
from ruamel.yaml.comments import TaggedScalar

# def resolve_dot_path(data, path):
#     keys = path.split('.')
#     for key in keys[:-1]:
#         data = data.get(key, {})
#     return data, keys[-1]

# def encrypt_dot_path(data, path, vault):
#     parent, final_key = resolve_dot_path(data, path)
#     if final_key in parent:
#         parent[final_key] = vault_tagged_scalar(vault, parent[final_key])
#         return True
#     return False

def expand_dot_path_wildcards(data, path):
    """
    Expands wildcard dot-paths like 'servers.*.password' into concrete paths.
    Returns a list of matching dot-path strings.
    """
    def recurse(current, keys, prefix):
        if not keys:
            return [prefix]

        key = keys[0]
        rest = keys[1:]
        results = []

        if isinstance(current, dict):
            if key == '*':
                for k in current:
                    results += recurse(current[k], rest, f"{prefix}.{k}" if prefix else k)
            elif key in current:
                results += recurse(current[key], rest, f"{prefix}.{key}" if prefix else key)

        elif isinstance(current, list):
            if key == '*':
                for i, item in enumerate(current):
                    results += recurse(item, rest, f"{prefix}.{i}" if prefix else str(i))
            elif key.isdigit() and int(key) < len(current):
                results += recurse(current[int(key)], rest, f"{prefix}.{key}" if prefix else key)

        return results

    return recurse(data, path.split('.'), '')

def encrypt_dot_path_recursively(data, path, vault):
    """
    Recursively traverses a dot-path and encrypts the final value.
    Supports dicts and lists. Returns True if encryption succeeded.
    """
    keys = path.split('.')
    current = data
    try:
        for i, key in enumerate(keys):
            is_last = i == len(keys) - 1
            # Handle list index
            if isinstance(current, list):
                index = int(key)
                if is_last:
                    current[index] = vault_tagged_scalar(vault, current[index])
                    return True
                current = current[index]
            # Handle dict key
            elif isinstance(current, dict):
                if is_last:
                    if key in current:
                        current[key] = vault_tagged_scalar(vault, current[key])
                        return True
                    else:
                        return False
                current = current.get(key)
            else:
                return False  # Unexpected structure
    except (KeyError, IndexError, ValueError, TypeError):
        return False

def decrypt_all_tagged_scalars(data, vault, path_prefix=''):
    """
    Recursively decrypts all vault-tagged scalars in the structure.
    Returns a list of dot-paths that were decrypted.
    """
    decrypted_paths = []
    if isinstance(data, dict):
        for key, value in data.items():
            full_path = f"{path_prefix}.{key}" if path_prefix else key
            if isinstance(value, TaggedScalar):
                data[key] = ansible_vault_decrypt_str(vault, value)
                decrypted_paths.append(full_path)
            else:
                decrypted_paths += decrypt_all_tagged_scalars(value, vault, full_path)

    elif isinstance(data, list):
        for i, item in enumerate(data):
            full_path = f"{path_prefix}.{i}" if path_prefix else str(i)
            if isinstance(item, TaggedScalar):
                data[i] = ansible_vault_decrypt_str(vault, item)
                decrypted_paths.append(full_path)
            else:
                decrypted_paths += decrypt_all_tagged_scalars(item, vault, full_path)

    return decrypted_paths

# Deprecated: superseded by decrypt_all_tagged_scalars
# Retained for reference; not used in current workflows
# def decrypt_dot_path_recursively(data, path, vault):
#     """
#     Recursively traverses a dot-path and decrypts the final value if it's vault-tagged.
#     Returns True if decryption succeeded.
#     """
#     keys = path.split('.')
#     current = data
#     try:
#         for i, key in enumerate(keys):
#             is_last = i == len(keys) - 1

#             if isinstance(current, list):
#                 index = int(key)
#                 if is_last:
#                     if isinstance(current[index], TaggedScalar):
#                         current[index] = ansible_vault_decrypt_str(vault, current[index])
#                         return True
#                     return False
#                 current = current[index]
#             elif isinstance(current, dict):
#                 if is_last:
#                     if isinstance(current.get(key), TaggedScalar):
#                         current[key] = ansible_vault_decrypt_str(vault, current[key])
#                         return True
#                     return False
#                 current = current.get(key)
#             else:
#                 return False
#     except (KeyError, IndexError, ValueError, TypeError):
#         return False
