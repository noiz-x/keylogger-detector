#!/usr/bin/env python3
import subprocess
import time
import os
import sys
import psutil
from config import CONFIG_FILE, load_config, save_config
from utils import (
    check_platform,
    check_root,
    check_packages,
    get_keyboard_device_files,
    get_real_path,
    get_pids_using_file,
    get_process_name,
    kill_processes,
    kill_process
)

# Global variables/CLI options
auto_kill_option = False
verbose_option = False
safe_option = False
add_white_list_option = False
add_black_list_option = False
debug_option = False
kernel_detection_option = False

# Suspicious keywords for heuristic detection
SUSPICIOUS_KEYWORDS = ['keylogger', 'logkeys', 'spy', 'monitor']

def debug(option, to_print):
    if option:
        print('[Debug]', to_print)

def print_help():
    print('Usage: python3 keylogger_detector.py [OPTIONS]')
    print('Options:')
    print('  -h, --help\t\t\tPrint this help message')
    print('  -v, --verbose\t\t\tVerbose mode. Informative information will be displayed during execution')
    print('  -a, --auto-kill\t\tAutomatically kill blacklisted processes')
    print('  -s, --safe\t\t\tSafe mode. Ask to confirm before killing a process')
    print('  -w, --add-white-list\t\tActivate prompt to add program names to the whitelist')
    print('  -b, --add-black-list\t\tAutomatically add program names chosen to kill to the blacklist')
    print('  -d, --debug\t\t\tDebug mode. Print debug statements')
    print('  -k, --kernel-detection\t\tRun the kernel keylogger detector (not fully implemented)')

def set_input_options():
    """
    Set input options based on command line arguments.

    Invalid arguments are ignored.

    Raises:
        SystemExit: If -h or --help is passed as an argument, the help message is printed and the program exits.
    """
    global auto_kill_option, verbose_option, safe_option, add_white_list_option
    global debug_option, add_black_list_option, kernel_detection_option
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg in ('-h', '--help'):
                print_help()
                sys.exit(0)
            elif arg in ('-v', '--verbose'):
                verbose_option = True
            elif arg in ('-a', '--auto-kill'):
                auto_kill_option = True
            elif arg in ('-s', '--safe'):
                safe_option = True
            elif arg in ('-w', '--add-white-list'):
                add_white_list_option = True
            elif arg in ('-b', '--add-black-list'):
                add_black_list_option = True
            elif arg in ('-d', '--debug'):
                debug_option = True
            elif arg in ('-k', '--kernel-detection'):
                kernel_detection_option = True

def confirm_kill_process(process_name, times=0):
    """
    Prompt the user to confirm killing a process.
    Used in safe mode.

    Args:
        process_name (str): Name of the process to kill.
        times (int): Number of times the prompt has been displayed with invalid input. Defaults to 0.

    Returns:
        bool: True if user confirms the kill, False otherwise.

    Raises:
        SystemExit: If invalid input is provided more than 5 times.
    """
    if times > 5:
        print('Too many invalid inputs. Exiting.')
        sys.exit(1)
    if times > 0:
        print('Invalid input. Please enter y or n.')
    answer = input(f"Do you want to kill {process_name}? (y/n): ").strip().lower()
    if answer == 'y':
        return True
    elif answer == 'n':
        return False
    else:
        return confirm_kill_process(process_name, times+1)

def detect_kernel(module):
    """
    Run a kernel keylogger detection using a systemtap script.
    This is a placeholder and not fully implemented.

    Args:
        module (str): Path and name of the module being tested.

    Returns:
        str or int: Module path if detected as logging keystrokes, 0 otherwise.
    """
    if verbose_option:
        print('[Verbose] Started kernel keylogger detection')
    process = subprocess.Popen(['stap', 'funcall_trace.stp', '-T', '10'], stdout=subprocess.PIPE, text=True)
    for i in range(2):
        subprocess.Popen(['sudo', 'insmod', module])
        time.sleep(1)
        print(".", end="")
        subprocess.Popen(['sudo', 'rmmod', module])
        time.sleep(1)
    subprocess.Popen(['sudo', 'insmod', module])
    print(".")
    out = process.communicate()[0]
    if verbose_option:
        print('[Verbose] Kernel detection output:', out)
    if out.strip() == "[-]":
        return module
    print("FAILED")
    return 0

def getpath(sus_modules):
    """
    Get the path for a list of module names by searching the filesystem.
    
    Args:
        sus_modules (list[str]): List of module names.
        
    Returns:
        list[str]: List of full paths for the modules.
    """
    for i in range(len(sus_modules)):
        sus_modules[i] = find_file(sus_modules[i] + ".ko")
    return sus_modules

def find_file(filename):
    """
    Search for a file starting from the root directory.
    
    Args:
        filename (str): The filename to search for.
        
    Returns:
        str: The full path of the file if found, otherwise an empty string.
    """
    result = []
    for root, dirs, files in os.walk("/"):
        if filename in files:
            file_path = os.path.join(root, filename)
            result.append(file_path)
    return ''.join(result)

def unload_mod(modules):
    """
    Attempt to unload a list of modules.
    
    Args:
        modules (list[str]): List of module paths to unload.
        
    Returns:
        list[str]: List of modules that remain loaded.
    """
    failed_unloads = []
    for module in modules:
        result = subprocess.run(['sudo', 'rmmod', module], capture_output=True, text=True)
        if result.returncode == 0:
            if verbose_option:
                print(f"[Verbose] Unloaded module: {module}")
        else:
            if verbose_option:
                print(f"[Verbose] Failed to unload module: {module}")
                print("[Verbose]", result.stderr)
            failed_unloads.append(module)
    remaining = compare_mods(failed_unloads, modules)
    if verbose_option:
        print("[Verbose] Remaining modules after unload attempt:", remaining)
    return remaining

def tidy_up(entries):
    """
    Cleans entries by taking only the first word of each line.
    
    Args:
        entries (list[str]): Lines from a file.
        
    Returns:
        list[str]: Cleaned entries.
    """
    cleaned_entries = []
    for entry in entries:
        parts = entry.split()
        if parts:
            cleaned_entries.append(parts[0])
    return cleaned_entries

def compare_mods(A, B):
    """
    Return elements that are in B but not in A.
    
    Args:
        A (list[str]): List to subtract.
        B (list[str]): Original list.
        
    Returns:
        list[str]: Elements in B but not in A.
    """
    return list(set(B) - set(A))

def get_whitelist(file_path):
    """
    Read a whitelist file and return its lines.
    
    Args:
        file_path (str): Path to the whitelist file.
        
    Returns:
        list[str]: List of whitelisted process names.
    """
    try:
        with open(file_path, 'r') as file:
            lines = file.read().splitlines()
            return lines
    except IOError:
        print(f'Error: Failed to load whitelist from {file_path}')
        return []

def list_modules(command):
    """
    Execute a shell command and return its output lines.
    
    Args:
        command (str): The command to execute.
        
    Returns:
        list[str]: Output lines from the command.
    """
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip().split('\n')
    else:
        print(f"Command failed with error: {result.stderr}")
        return []

def detect_userland_keyloggers():
    """
    Detect potential userland keylogger processes using psutil by checking
    for suspicious keywords in process names and command lines.
    
    Returns:
        list[psutil.Process]: List of suspicious processes.
    """
    suspicious_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = proc.info['name'] or ""
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            combined = (name + " " + cmdline).lower()
            if any(keyword in combined for keyword in SUSPICIOUS_KEYWORDS):
                suspicious_processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return suspicious_processes

def detect_keyloggers():
    """
    Detect (userland) keylogger processes by checking which processes have a
    keyboard device file open (/dev/input/event*) and by using heuristic detection.
    
    The main function of the program. It uses configuration settings, command line options,
    and user input to determine which processes might be keyloggers and optionally kill them.
    """
    # 1. Setup and initialization
    debug(True, str(sys.argv))
    check_platform()
    global auto_kill_option, verbose_option, safe_option, add_white_list_option, kernel_detection_option, debug_option
    set_input_options()
    if verbose_option:
        print('[Verbose] Input options set')
    
    check_root()
    if verbose_option:
        print('[Verbose] Root access confirmed')
    
    check_packages()
    if verbose_option:
        print('[Verbose] Required packages are installed')
    
    config = load_config()
    if verbose_option:
        print('[Verbose] Configuration loaded')
    
    white_listed_programs = config.get('white_listed_programs', [])
    auto_kill_programs = config.get('auto_kill_programs', [])
    kbd_names = config.get('kbd_names', [])
    if verbose_option:
        print('[Verbose] Configuration parsed')
    
    # 2. Get keyboard device files
    keyboard_device_files = get_keyboard_device_files(kbd_names)
    if verbose_option:
        print('[Verbose] Keyboard device files found:', keyboard_device_files)
    
    # 3. Get PIDs using keyboard device files
    pids = []
    for device_file in keyboard_device_files:
        pids += get_pids_using_file(device_file)
    pids = sorted(list(set(pids)))
    if verbose_option:
        print('[Verbose] Process IDs using keyboard device files:', pids)
    
    # 4. Get process names from PIDs
    process_names = []
    name_pid_dict = {}
    for pid in pids:
        name = get_process_name(pid)
        if name:
            process_names.append(name)
            name_pid_dict.setdefault(name, []).append(pid)
    process_names = sorted(list(set(process_names)))
    if verbose_option:
        print('[Verbose] Process names using keyboard device files:', process_names)
    
    # 4.1. Heuristic detection using psutil (additional check)
    psutil_suspicious = detect_userland_keyloggers()
    if verbose_option and psutil_suspicious:
        print('[Verbose] Additional suspicious processes detected via psutil:')
        for proc in psutil_suspicious:
            print(f"\tPID: {proc.pid}, Name: {proc.name()}")
    
    # 5. Auto-kill option: kill processes that are in the auto-kill list
    if auto_kill_option:
        for name in process_names:
            if name in auto_kill_programs:
                if verbose_option:
                    print('[Verbose] Auto-killable process found:', name)
                if safe_option:
                    if confirm_kill_process(name):
                        kill_processes(name_pid_dict.get(name, []))
                else:
                    kill_processes(name_pid_dict.get(name, []))
                if verbose_option:
                    print('[Verbose] Process auto-killed:', name)
    
    # 6. Identify suspicious processes (not whitelisted and not auto-killed)
    suspicious_processes = []
    for name in process_names:
        if ((name not in white_listed_programs and name not in auto_kill_programs) or 
            (name in auto_kill_programs and not auto_kill_option)):
            suspicious_processes.append(name)
        else:
            # Also consider processes with suspicious keywords
            if any(keyword in name.lower() for keyword in SUSPICIOUS_KEYWORDS):
                if name not in suspicious_processes:
                    suspicious_processes.append(name)
    
    if verbose_option:
        print('[Verbose] Suspicious processes detected:', suspicious_processes)
    
    # If no suspicious processes are found, exit unless kernel detection is enabled
    if not suspicious_processes:
        print("[+] No suspicious userland keylogger processes found.")
        if not kernel_detection_option:
            sys.exit(0)
    
    # 7. Prompt user for which processes to kill (if not auto-killed)
    print('[-] The following suspicious processes were found:')
    for name in suspicious_processes:
        print(f'\t{name}')
    
    if safe_option:
        print('[Safe] You are in safe mode. You will be asked to confirm before each kill.')
        print('[Safe] Note: Killing critical processes may cause system instability.')
    
    print('Enter the names of the processes to kill, separated by a space (or press Enter to skip):')
    to_kill = input().split()
    if not to_kill:
        print('[+] No processes selected for termination.')
    
    if verbose_option:
        print('[Verbose] Processes selected for termination:', to_kill)
    
    # Kill the selected processes
    if safe_option:
        for name in to_kill:
            for pid in name_pid_dict.get(name, []):
                if confirm_kill_process(name):
                    debug(debug_option, f'Killing process: {name} (PID: {pid})')
                    kill_process(pid)
                    if verbose_option:
                        print('[Verbose] Process killed:', name)
    else:
        for name in to_kill:
            for pid in name_pid_dict.get(name, []):
                debug(debug_option, f'Killing process: {name} (PID: {pid})')
                kill_process(pid)
                if verbose_option:
                    print('[Verbose] Process killed:', name)
    
    # 8. Update whitelist/blacklist if options are set
    if add_white_list_option:
        print('Enter the names of any processes to whitelist, separated by a space:')
        to_whitelist = input().split()
        if to_whitelist:
            white_listed_programs += to_whitelist
            if verbose_option:
                print('[Verbose] Processes added to whitelist:', to_whitelist)
    
    to_kill = list(set(to_kill))
    if add_black_list_option:
        auto_kill_programs.extend(to_kill)
        if verbose_option:
            print('[Verbose] Processes added to auto-kill list:', to_kill)
    
    # 9. Save updated configuration
    config['auto_kill_programs'] = list(set(auto_kill_programs))
    config['white_listed_programs'] = list(set(white_listed_programs))
    config['kbd_names'] = list(set(kbd_names))
    save_config(config)
    if verbose_option:
        print('[Verbose] Configuration saved.')
    
    # 10. Kernel keylogger detection (if enabled)
    if kernel_detection_option:
        whitelist = get_whitelist("whitelist.txt")
        lsmod_output = list_modules("lsmod")
        sus_modules = compare_mods(whitelist, lsmod_output)
        sus_modules = tidy_up(sus_modules)
        sus_modules = unload_mod(sus_modules)
        time.sleep(1)
        sus_modules = getpath(sus_modules)
        suspects = []
        if verbose_option:
            print("[Verbose] Suspect kernel modules:", sus_modules)
        if not sus_modules and verbose_option:
            print("[Verbose] No suspect kernel modules found.")
        for module in sus_modules:
            if not module:  # Skip if empty path
                continue
            suspects.append(detect_kernel(module))
            time.sleep(1)
        print("The following kernel modules may be logging your keystrokes:")
        for i, suspect in enumerate(suspects):
            print(f"[{i}] {suspect}")
        print("Enter the number of the module you want to remove:")
        user_input = input().split()
        for j in user_input:
            try:
                module_to_remove = suspects[int(j)]
                subprocess.Popen(['sudo', 'rmmod', module_to_remove])
            except (IndexError, ValueError):
                print("Invalid selection.")
        if not user_input:
            print("No modules removed.")
    
    print('[+] Keylogger detection complete. Exiting.')

if __name__ == '__main__':
    detect_keyloggers()
