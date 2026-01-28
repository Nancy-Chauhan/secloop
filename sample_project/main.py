"""Sample application using the vulnerable dependencies."""

import requests
import yaml
from flask import Flask, render_template_string

app = Flask(__name__)


def fetch_data(url: str) -> dict:
    """Fetch JSON data from a URL."""
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


def load_config(config_path: str) -> dict:
    """Load YAML configuration file."""
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


@app.route("/")
def index():
    return render_template_string("<h1>Hello, World!</h1>")


@app.route("/greet/<name>")
def greet(name: str):
    return render_template_string(f"<h1>Hello, {name}!</h1>")


def main():
    """Run the application."""
    print("Sample app ready")
    return True


if __name__ == "__main__":
    main()
