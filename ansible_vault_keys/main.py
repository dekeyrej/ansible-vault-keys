import logging
from ansible_vault_keys.cli import read_commandline_args
from ansible_vault_keys.vault_utils import initialize_vault
from ansible_vault_keys.yaml_io import read_input_file, write_output_file, display_output
from ansible_vault_keys.dotpath_utils import expand_dot_path_wildcards, encrypt_dot_path_recursively, decrypt_all_tagged_scalars

logging.basicConfig(level=logging.INFO)

def main():
    args = read_commandline_args()
    logging.debug(f"Command line arguments: {args}")
    # set local variables based on args
    command = args.command
    input_file = args.input
    output_file = args.output or input_file
    password_file_path = args.vault_password_file
    keys_to_encrypt = args.keys
    dry_run = args.dry_run

    vault = initialize_vault(password_file_path)
    vars = read_input_file(input_file)
    if command in ['decrypt', 'view'] and keys_to_encrypt:
        logging.warning("'Keys to encrypt' are ignored for decrypt/view commands")
    else:
        keys_to_encrypt = list(set(keys_to_encrypt) | set(vars.get('encrypted_keys', [])))
        logging.info(f"Keys to encrypt: {keys_to_encrypt}")

    if 'encrypted_keys' in vars:
        logging.debug(f"Encrypted keys found: {vars['encrypted_keys']}")
        write_comment = False
    else:
        write_comment = True

    # perform the right logic for the command
    if command == 'encrypt':
        if keys_to_encrypt:
            expanded_keys = []
            for key in keys_to_encrypt:
                if '*' in key:
                    expanded_keys += expand_dot_path_wildcards(vars, key)
                else:
                    expanded_keys.append(key)
            encrypted_keys = []
            for key in expanded_keys:
                success = encrypt_dot_path_recursively(vars, key, vault)
                if success:
                    encrypted_keys.append(key)
                else:
                    logging.warning(f"Dot-path key not found: {key}")
            vars['encrypted_keys'] = list(set(encrypted_keys))
            if write_comment:
                vars.yaml_set_comment_before_after_key('encrypted_keys', before='List of encrypted dot-paths')
            if dry_run:
                display_output(vars)
            else:
                write_output_file(output_file, vars)
    elif command in ['decrypt', 'view']:
        decrypted_keys = decrypt_all_tagged_scalars(vars, vault)
        vars['encrypted_keys'] = list(set(decrypted_keys))
        if write_comment:
            vars.yaml_set_comment_before_after_key('encrypted_keys', before='List of decrypted dot-paths')
        if command == 'decrypt':
            write_output_file(output_file, vars)
        elif command == 'view':
            display_output(vars)

if __name__ == "__main__":  # pragma: no cover
    main()
