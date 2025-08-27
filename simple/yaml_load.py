"""
Module for reading and loading a YAML configuration file.

This module reads the content of 'dangerous.yaml' located in the same
directory and loads it safely using PyYAML's safe_load method.
"""

import os
import yaml

def load_yaml_file(filename="dangerous.yaml"):
    """
    Load and return the contents of the given YAML file as a Python object.
    
    Uses yaml.safe_load() to securely parse YAML content without risk of
    arbitrary code execution from malicious YAML files.
    """
    yaml_path = os.path.join(os.path.dirname(__file__), filename)
    with open(yaml_path, "r", encoding="utf-8") as f:
        content = f.read()
    return yaml.safe_load(content)


def main():
    config = load_yaml_file()
    print(config)

if __name__ == "__main__":
    main()