"""
Module for reading and loading a YAML configuration file.

This module reads the content of 'dangerous.yaml' located in the same
directory and loads it using PyYAML.
"""

import os
import yaml

def load_yaml_file(filename="dangerous.yaml"):
    """
    Load and return the contents of the given YAML file as a Python object.
    """
    yaml_path = os.path.join(os.path.dirname(__file__), filename)
    with open(yaml_path, "r", encoding="utf-8") as f:
        content = f.read()
    return yaml.load(content, Loader=yaml.SafeLoader)  # safer

def main():
    config = load_yaml_file()
    print(config)

if __name__ == "__main__":
    main()