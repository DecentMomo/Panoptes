import yaml


def load_config(text: str) -> object:
    return yaml.load(text)
