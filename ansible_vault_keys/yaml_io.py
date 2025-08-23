import logging
import sys
import ruamel.yaml

logging.basicConfig(level=logging.INFO)

yaml = ruamel.yaml.YAML()
yaml.preserve_quotes = True
yaml.default_flow_style = False

def read_input_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return yaml.load(f)
    except ruamel.yaml.error.YAMLError as e:
        logging.error(f"Error loading YAML file: {e}")
        sys.exit(1)
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)

def write_output_file(file_path, data):
    with open(file_path, 'w') as f:
        yaml.dump(data, f)
    logging.info(f"Changes written to {file_path}")

def display_output(data):
    yaml.dump(data, sys.stdout)
    logging.info("No changes made.")