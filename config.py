# config.py
import json
import os

# Define the configuration file name
CONFIG_FILE = "keylogger_config.json"

def load_config():
    """
    Loads the configuration from the JSON file.
    If the file does not exist, a default configuration is created and saved.
    """
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "white_listed_programs": [],
            "auto_kill_programs": [],
            "kbd_names": ["/dev/input/event0", "/dev/input/event1"]  # update with your keyboard device paths
        }
        save_config(default_config)
        return default_config
    else:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)

def save_config(config):
    """
    Saves the configuration to the JSON file.
    """
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
