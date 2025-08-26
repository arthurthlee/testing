"""
Pytest tests for yaml_load module.

Tests the loading of YAML files using PyYAML to ensure content can be
read and parsed correctly.
"""

from simple import yaml_load  # adjust import path depending on test layout


def test_load_arbitrary_yaml():
    """
    Test loading of an arbitrary YAML file via yaml_load.load_yaml_file().
    """
    result = yaml_load.load_yaml_file("dangerous.yaml")
    assert result is not None
    assert isinstance(result, (dict, list))  # depending on YAML structure
