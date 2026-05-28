"""Seeded bug: yaml.load without SafeLoader."""
import yaml


def parse_config(data):
    return yaml.load(data)
