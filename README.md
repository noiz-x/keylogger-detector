# Keylogger Detector Framework

This project is a Python-based tool designed to detect potential keylogger processes on Linux systems. It combines several detection techniques:

- **Userland Detection:**  
  Identifies suspicious processes by checking which processes have keyboard device files open (e.g. `/dev/input/event*`) and by using heuristic keyword matching with [psutil](https://pypi.org/project/psutil/).

- **Process Management:**  
  Supports both auto-killing of processes (based on a configurable blacklist) and safe mode that prompts the user for confirmation before terminating any process.

> **Important:**  
> This tool must be executed on Linux with root privileges. Use caution when terminating processes to avoid system instability.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Dynamic Keyboard Device Detection](#dynamic-keyboard-device-detection)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Modules Overview](#modules-overview)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Dual Detection Techniques:**  
  - **Device-based Detection:** Monitors keyboard device files (using `fuser` and the `/dev/input/by-path` directory).  
  - **Heuristic Detection:** Scans running processes with psutil for suspicious keywords (e.g., "keylogger", "logkeys", "spy", "monitor").

- **Configurable Auto-Kill and Safe Modes:**  
  Automatically terminates blacklisted processes or prompts the user for confirmation in safe mode.

- **Dynamic Whitelisting/Blacklisting:**  
  Update trusted processes (whitelist) or add processes for auto-killing (blacklist) via configuration.

- **Robust System Checks:**  
  The tool checks the Linux platform, verifies root privileges, and ensures required commands are available before execution.

---

## Requirements

- **Operating System:** Linux
- **Python Version:** Python 3.x
- **Python Packages:**  
  - `psutil`
- **System Commands/Packages:**  
  - `fuser`
  - `which`

> **Note:** Ensure that your Linux distribution has these commands installed. You may need to install them using your package manager if they are absent.

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/noiz-x/keylogger-detector.git
   cd keylogger-detector
   ```

2. **(Optional) Create a Virtual Environment:**

   This is recommended to prevent conflicts with system-wide packages:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python Dependencies:**

   Install the `psutil` module (if not already installed):

   ```bash
   pip install psutil
   ```

4. **Ensure Root Privileges:**  
   The script must be run with root privileges. Use `sudo` when executing the main script.

---

## Configuration

The framework uses a JSON configuration file (default: `keylogger_config.json`) to store settings. If the file does not exist, the **config.py** module automatically creates it with default values. Additionally, the script dynamically detects the keyboard device files if the `kbd_names` field is empty.

### Sample Configuration File

```json
{
    "white_listed_programs": [
        "gnome-shell",
        "Xorg",
        "python3"
    ],
    "auto_kill_programs": [
        "suspicious_process_name"
    ],
    "kbd_names": [
        "/dev/input/by-path/pci-0000:00:14.0-usb-0:1.3:1.0-event-kbd"
    ]
}
```

### Dynamic Keyboard Device Detection

Instead of hardcoding the keyboard event file (e.g., `/dev/input/event0`), the tool automatically detects the correct device file by scanning the `/dev/input/by-path/` directory for entries containing the keyword `"kbd"`. 

**How It Works:**

1. **Automatic Detection:**  
   The function `get_keyboard_device_files()` in `utils.py` scans `/dev/input/by-path/` for files with names that include `"kbd"` and uses `get_real_path()` to resolve any symbolic links.

2. **Verifying Your Keyboard Device:**  
   You can manually check which device file is being used by running:

   ```bash
   ls -l /dev/input/by-path/ | grep kbd
   ```

   This command lists all keyboard-related device files. The script then updates the `kbd_names` field in the configuration file with the detected paths.

3. **Integration in Configuration:**  
   When `config.py` loads the configuration, if the `"kbd_names"` field is empty or missing, it automatically populates it with the detected device files.

---

## Usage

Run the main script (`keylogger_detector.py`) with root privileges:

```bash
sudo python3 keylogger_detector.py [OPTIONS]
```

### Command-Line Options

- `-h, --help`  
  Show the help message and exit.

- `-v, --verbose`  
  Enable verbose mode to display detailed information during execution.

- `-a, --auto-kill`  
  Automatically kill processes that are in the auto-kill list.

- `-s, --safe`  
  Safe mode: prompt for confirmation before killing any process.

### Example

To run the detector in verbose and safe mode:

```bash
sudo python3 keylogger_detector.py -v -s
```

---

## Project Structure

```
keylogger-detector/
├── keylogger_detector.py    # Main script for keylogger detection
├── config.py                # Configuration module (loads/saves JSON config and dynamically detects keyboard devices)
├── utils.py                 # Utility functions for system checks, device file handling, and process management
├── keylogger_config.json    # JSON configuration file (auto-generated if missing)
└── README.md                # This README file
```

---

## Modules Overview

### keylogger_detector.py

- **Purpose:**  
  Implements the core logic to detect suspicious processes that might be keyloggers by combining device-based and heuristic detection.
  
- **Functionality:**  
  - Reads configuration settings.
  - Checks for required privileges and system conditions.
  - Retrieves keyboard device files and associated process IDs.
  - Supports auto-kill and safe termination modes.
  - Optionally updates whitelist/blacklist configurations.

### config.py

- **Purpose:**  
  Manages configuration settings stored in `keylogger_config.json`.
  
- **Key Functions:**  
  - `load_config()`: Reads the configuration from the JSON file, auto-generates defaults if missing, and dynamically detects keyboard devices.
  - `save_config()`: Writes updates to the configuration file.

### utils.py

- **Purpose:**  
  Provides utility functions for system-level operations.
  
- **Key Functions:**  
  - `check_platform()`: Confirms the script is running on Linux.
  - `check_root()`: Verifies the script is executed with root privileges.
  - `check_packages()`: Ensures necessary commands (`fuser`, `which`) are installed.
  - `get_keyboard_device_files()`: Scans `/dev/input/by-path/` for keyboard device files containing the keyword `"kbd"`.
  - `get_real_path()`: Resolves symbolic links to their actual paths.
  - `get_pids_using_file()`: Retrieves process IDs using a specific device file via `fuser`.
  - `get_process_name()`: Reads a process's name from `/proc/[pid]/comm`.
  - `kill_processes()` and `kill_process()`: Terminate processes using the SIGKILL signal.

---

## Troubleshooting

- **ModuleNotFoundError:**  
  Ensure that `config.py` and `utils.py` are present in the same directory as `keylogger_detector.py`.

- **Permission Issues:**  
  Run the script as root using `sudo` to avoid permission errors, especially when accessing device files and killing processes.

- **Missing Packages/Commands:**  
  Use your package manager to install any missing dependencies, e.g., `fuser` and `which`.

- **Keyboard Device Files Not Found:**  
  Verify that the `kbd_names` in the configuration file accurately reflect your system. Use:
  
  ```bash
  ls -l /dev/input/by-path/ | grep kbd
  ```
  
  to check the correct paths.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.