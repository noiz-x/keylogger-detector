#!/usr/bin/env python3
import os       # For path operations, getuid, kill
import subprocess  # For executing shell commands
import signal   # For sending signals to processes
import sys      # For exit

def check_platform():
    """
    Check if the platform is Linux.
    
    Raises:
        SystemExit: If the platform is not Linux.
    """
    if sys.platform != 'linux':
        print("[-] This script only works on Linux.")
        sys.exit(1)

def check_root():
    """
    Check if the script is run as root (sudo).
    
    Raises:
        SystemExit: If not run as root.
    """
    if os.getuid() != 0:
        print("[-] Please run as root.")
        sys.exit(1)

def check_packages():
    """
    Check if all required packages/commands are installed.
    Required packages: fuser, which
    
    Raises:
        SystemExit: If any required package is missing.
    """
    packages = ['fuser', 'which']
    missing_packages = []

    for package in packages:
        # Using subprocess.call to see if the command exists
        if subprocess.call(['which', package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            missing_packages.append(package)
    if missing_packages:
        print("[-] Missing packages: {}".format(', '.join(missing_packages)))
        sys.exit(1)

def get_keyboard_device_files(names):
    """
    Get paths corresponding to keyboard device files by searching /dev/input/by-path.
    Uses get_real_path() to resolve symlinks.
    
    Args:
        names (list): List of strings to search for in file names (e.g. ['kbd']).
    
    Returns:
       list: Paths to keyboard device files.
    """
    keyboard_device_files = []
    for root, dirs, files in os.walk('/dev/input/by-path'):
        for file in files:
            if any(name in file for name in names):
                keyboard_device_files.append(get_real_path(os.path.join(root, file)))
    return keyboard_device_files

def get_real_path(path):
    """
    Resolve a path of a file.
    
    Args:
        path (str): Path to a file. Possibly a symlink.
    
    Returns:
        str: The resolved (real) path.
    """
    if os.path.islink(path):
        return os.path.realpath(path)
    else:
        return path

def get_pids_using_file(path):
    """
    Get all process IDs using a file. (A wrapper for fuser.)
    
    Args:
        path (str): Path to a file (usually /dev/input/eventX).
    
    Returns:
        list: List of process IDs (as strings).
    
    Raises:
        SystemExit: If fuser fails to run.
    """
    try:
        # fuser outputs PIDs separated by spaces
        output = subprocess.check_output(['fuser', path]).decode('utf-8')
        pids = output.strip().split()
        return pids
    except subprocess.CalledProcessError:
        print("[-] Error: fuser failed to run on", path)
        sys.exit(1)

def get_process_name(pid):
    """
    Get the name of a process using /proc/[pid]/comm.
    
    Args:
        pid (int or str): Process ID.
    
    Returns:
        str: Name of the process.
    """
    try:
        with open(f'/proc/{pid}/comm') as f:
            return f.read().strip()
    except Exception as e:
        print(f"[-] Unable to get process name for PID {pid}: {e}")
        return None

def kill_processes(pids):
    """
    Kill processes given their PIDs.
    
    Args:
        pids (list): List of process IDs.
    """
    for pid in pids:
        kill_process(pid)

def kill_process(pid):
    """
    Kill a single process using SIGKILL.
    
    Args:
        pid (int or str): Process ID of the process to kill.
    """
    try:
        os.kill(int(pid), signal.SIGKILL)
        print(f"[+] Killed process {pid}: {get_process_name(pid)}")
    except ProcessLookupError:
        print(f"[-] Process {pid} not found.")
    except Exception as e:
        print(f"[-] Error killing process {pid}: {e}")
