import os
import subprocess
from termcolor import colored
import re
import requests
from packaging import version

def fetch_os_info():
    os_info = {}

    # Run cat /proc/version or uname -a
    try:
        proc_version = subprocess.check_output(['cat', '/proc/version'], stderr=subprocess.DEVNULL).decode().strip()
        os_info['proc_version'] = proc_version
    except subprocess.CalledProcessError:
        try:
            uname_a = subprocess.check_output(['uname', '-a'], stderr=subprocess.DEVNULL).decode().strip()
            os_info['uname_a'] = uname_a
        except subprocess.CalledProcessError as e:
            os_info['uname_a'] = f"Error: {e}"

    # Run lsb_release -a
    try:
        lsb_release = subprocess.check_output(['lsb_release', '-a'], stderr=subprocess.DEVNULL).decode().strip()
        os_info['lsb_release'] = lsb_release
    except subprocess.CalledProcessError as e:
        os_info['lsb_release'] = f"Error: {e}"

    # Run cat /etc/os-release
    try:
        os_release = subprocess.check_output(['cat', '/etc/os-release'], stderr=subprocess.DEVNULL).decode().strip()
        os_info['os_release'] = os_release
    except subprocess.CalledProcessError as e:
        os_info['os_release'] = f"Error: {e}"

    return os_info

def extract_kernel_version(proc_version, uname_a):
    version_regex = r"Linux version (\d+\.\d+\.\d+)"  # Regular expression to match kernel version
    match = re.search(version_regex, proc_version)
    if match:
        return match.group(1)
    match = re.search(version_regex, uname_a)
    if match:
        return match.group(1)
    return None

def check_sudo_version():
    try:
        sudo_version_output = subprocess.check_output(['sudo', '--version'], stderr=subprocess.DEVNULL).decode().strip()
        sudo_version = re.search(r"Sudo version (\d+\.\d+\.\d+)", sudo_version_output)
        if sudo_version:
            return sudo_version.group(1)
        else:
            return None
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"

def check_path_writable():
    path_dirs = os.environ.get('PATH', '').split(':')
    writable_dirs = []

    for dir in path_dirs:
        if os.access(dir, os.W_OK):
            writable_dirs.append(dir)

    return writable_dirs

def check_env_variables():
    env_info = {}
    try:
        env_vars = subprocess.check_output(['env'], stderr=subprocess.DEVNULL).decode().strip().split('\n')
        for var in env_vars:
            if any(keyword in var.lower() for keyword in ['password', 'key', 'secret']):
                key, value = var.split('=', 1)
                env_info[key] = value
    except subprocess.CalledProcessError as e:
        env_info['error'] = f"Error: {e}"

    return env_info

def check_kernel_exploits(kernel_version):
    if not kernel_version:
        return {"error": "Kernel version not found."}

    kernel_info = {
        "kernel_version": kernel_version
    }

    try:
        searchsploit_result = subprocess.check_output(['searchsploit', f'Linux Kernel {kernel_version}'], stderr=subprocess.DEVNULL).decode().strip()
        kernel_info['searchsploit'] = searchsploit_result
    except subprocess.CalledProcessError as e:
        kernel_info['searchsploit'] = f"Error: {e}"

    return kernel_info

def check_sudo_exploits(sudo_version):
    if not sudo_version:
        return {"error": "Sudo version not found."}

    sudo_info = {
        "sudo_version": sudo_version
    }

    try:
        searchsploit_result = subprocess.check_output(['searchsploit', f'sudo {sudo_version}'], stderr=subprocess.DEVNULL).decode().strip()
        sudo_info['searchsploit'] = searchsploit_result
    except subprocess.CalledProcessError as e:
        sudo_info['searchsploit'] = f"Error: {e}"

    return sudo_info

def check_drives():
    drive_info = {}

    # List devices
    try:
        devices = subprocess.check_output(['ls', '/dev'], stderr=subprocess.DEVNULL).decode().split('\n')
        sd_devices = [dev for dev in devices if re.search(r'^sd', dev, re.I)]
        drive_info['devices'] = sd_devices
    except subprocess.CalledProcessError as e:
        drive_info['devices_error'] = f"Error: {e}"

    # Check /etc/fstab for unmounted drives and sensitive information
    try:
        fstab_content = subprocess.check_output(['cat', '/etc/fstab'], stderr=subprocess.DEVNULL).decode().strip().split('\n')
        fstab_entries = [line for line in fstab_content if not line.startswith('#') and not re.search(r'\W*\#', line)]
        drive_info['fstab_entries'] = fstab_entries

        sensitive_info = [line for line in fstab_content if re.search(r"(user|username|login|pass|password|pw|credentials)[=:]", line, re.I)]
        drive_info['sensitive_info'] = sensitive_info
    except subprocess.CalledProcessError as e:
        drive_info['fstab_error'] = f"Error: {e}"

    return drive_info


def print_ascii_art():
    ascii_art = """
░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 

*************************%%#########%**************************
**************@@*****###################*********#*************
**************@@@@@%######################%**@@@@@*************
**************@@@@@@@%######################@@@@@@@@@%*********
*************@@@@@@@@%######################%@@@@@@@@#*********
************@@@@@@@@#%#############%##%#####%@@@@@@@@**********
************%@@@@@@@%##############%##%######%@@@@@@***********
*************@@@@@@@##############%###%*##%##%@@@*@************
**************@%@@@%#########%####%###***#%##%@@@**************
**************#@@@@%######%%%%%%**###%****%%#%@@@@*************
**************%@@@@%#####%#%%##%*%#%%****@@%%@%@@@#************
**************@@@@@%####%%*@@%%*#******@#%*#*@%@@@@************
*************#@@@@%####%%%**#%%%*******#@#%*%%%@@@@************
*************%@@%@%###*#**%*****************@%%@@@@@***********
*************#%#######*%%**%***************#%%%@@**************
************#%########%**%*********##%*****##%%%***************
***********###############@%#******##****%##%%##***************
*********###############%%@%***********######%###%*************
******%##################%@*******%**%######%######%***********
*****###################%%@@@@@@##%%#######%%#########%********
****%##%#################%**@@@@@@@@##%#%#%%%###########*******
****###%#######%##%######*%************%#%#%#%###%#####%#******
*****##%###%##%###%%#****%*%**************#%##############*****
*****%###%#%##%#***********#**************##%###########%******
*****#%##%#######%********%***************%###%#######%#*******
*########%#########%***********************##########%%####****
*#############%#####%#*********************############%####%**
**#%##%###%#####%#######%***%@@#**********%######%#######%####*
**####%#############%#####%@@@@@@@@@@@@@@@@############%#%##%**
#####%#%%###%##########%####@@@@@@@@@@@@@@@###############%****
##############%#########%%###@@@@@@@@@@@@@@##%####%#########%%%


    """
    print(colored(ascii_art, 'yellow'))

def print_os_info(os_info):
    for key, value in os_info.items():
        print(colored(f"\n{key}:", 'green'))
        print(colored(value, 'yellow'))

def print_env_info(env_info):
    if env_info:
        print(colored("\nSensitive Environment Variables Found:", 'red', attrs=['bold']))
        for key, value in env_info.items():
            print(colored(f"{key}: {value}", 'yellow'))
    else:
        print(colored("\nNo sensitive environment variables found.", 'green'))

def print_kernel_exploits(kernel_info):
    for key, value in kernel_info.items():
        print(colored(f"\n{key}:", 'green'))
        print(colored(value, 'yellow'))

def print_sudo_exploits(sudo_info):
    for key, value in sudo_info.items():
        print(colored(f"\n{key}:", 'green'))
        print(colored(value, 'yellow'))

def print_drive_info(drive_info):
    print(colored("\nDrive Information:", 'magenta', attrs=['bold']))
    if 'devices' in drive_info:
        print(colored("\nDevices found:", 'green'))
        for device in drive_info['devices']:
            print(colored(device, 'yellow'))
    if 'fstab_entries' in drive_info:
        print(colored("\nfstab Entries:", 'green'))
        for entry in drive_info['fstab_entries']:
            print(colored(entry, 'yellow'))
    if 'sensitive_info' in drive_info:
        if drive_info['sensitive_info']:
            print(colored("\nSensitive Information in fstab:", 'red', attrs=['bold']))
            for info in drive_info['sensitive_info']:
                print(colored(info, 'yellow'))
        else:
            print(colored("\nNo sensitive information found in fstab.", 'green'))

def check_useful_binaries():
    binaries = [
        'nmap', 'aws', 'nc', 'ncat', 'netcat', 'nc.traditional', 'wget', 'curl',
        'ping', 'gcc', 'g++', 'make', 'gdb', 'base64', 'socat', 'python', 'python2',
        'python3', 'perl', 'php', 'ruby', 'xterm', 'doas', 'sudo', 'fetch', 'docker',
        'lxc', 'ctr', 'runc', 'rkt', 'kubectl'
    ]
    found_binaries = {}
    for binary in binaries:
        path = subprocess.run(['which', binary], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if path.stdout:
            found_binaries[binary] = path.stdout.decode().strip()

    return found_binaries

def check_compilers():
    compilers = {}

    # Check for GCC using dpkg on Debian-based systems
    try:
        dpkg_compilers = subprocess.check_output(['dpkg', '--list'], stderr=subprocess.DEVNULL).decode()
        gcc_compilers = re.findall(r'^ii\s+(gcc-[\d\.]+)', dpkg_compilers, re.MULTILINE)
        if gcc_compilers:
            compilers['dpkg'] = gcc_compilers
    except subprocess.CalledProcessError:
        pass

    # Check for GCC using apt on Debian-based systems
    try:
        apt_compilers = subprocess.check_output(['apt', 'list', '--installed', 'gcc*'], stderr=subprocess.DEVNULL).decode()
        gcc_compilers = re.findall(r'^gcc-[\d\.]+', apt_compilers, re.MULTILINE)
        if gcc_compilers:
            compilers['apt'] = gcc_compilers
    except subprocess.CalledProcessError:
        pass

    # Check for GCC using yum on Red Hat-based systems
    try:
        yum_compilers = subprocess.check_output(['yum', 'list', 'installed', 'gcc*'], stderr=subprocess.DEVNULL).decode()
        gcc_compilers = re.findall(r'^gcc-[\d\.]+', yum_compilers, re.MULTILINE)
        if gcc_compilers:
            compilers['yum'] = gcc_compilers
    except FileNotFoundError:
        # Yum is not installed or not available on this system
        compilers['yum'] = "yum not available on this system"
    except subprocess.CalledProcessError:
        pass

    # Check for GCC, G++, etc., directly
    try:
        gcc_path = subprocess.check_output(['which', 'gcc'], stderr=subprocess.DEVNULL).decode().strip()
        if gcc_path:
            compilers['gcc'] = gcc_path
    except subprocess.CalledProcessError:
        pass

    try:
        gpp_path = subprocess.check_output(['which', 'g++'], stderr=subprocess.DEVNULL).decode().strip()
        if gpp_path:
            compilers['g++'] = gpp_path
    except subprocess.CalledProcessError:
        pass

    return compilers


def main():
    print_ascii_art()
    os_info = fetch_os_info()
    
    print(colored("OS Information:", 'magenta', attrs=['bold']))
    print_os_info(os_info)

    print(colored("\nChecking writable directories in PATH:", 'magenta', attrs=['bold']))
    writable_dirs = check_path_writable()
    if writable_dirs:
        print(colored("Writable directories found in PATH:", 'red', attrs=['bold']))
        for dir in writable_dirs:
            print(colored(dir, 'yellow'))
    else:
        print(colored("No writable directories found in PATH.", 'green'))

    print(colored("\nChecking environment variables for sensitive information:", 'magenta', attrs=['bold']))
    env_info = check_env_variables()
    print_env_info(env_info)

    print(colored("\nChecking for kernel exploits:", 'magenta', attrs=['bold']))
    proc_version = os_info.get('proc_version', '')
    uname_a = os_info.get('uname_a', '')
    kernel_version = extract_kernel_version(proc_version, uname_a)
    kernel_info = check_kernel_exploits(kernel_version)
    print_kernel_exploits(kernel_info)

    print(colored("\nChecking for sudo exploits:", 'magenta', attrs=['bold']))
    sudo_version = check_sudo_version()
    sudo_info = check_sudo_exploits(sudo_version)
    print_sudo_exploits(sudo_info)

    print(colored("\nChecking for mounted and unmounted drives:", 'magenta', attrs=['bold']))
    drive_info = check_drives()
    print_drive_info(drive_info)

    print(colored("\n[-] Checking for useful binaries...", 'yellow'))
    useful_binaries = check_useful_binaries()
    print(colored("[+] Useful Binaries:", 'green'), useful_binaries)

    print(colored("\n[-] Checking for compilers...", 'yellow'))
    compilers = check_compilers()
    print(colored("[+] Compilers:", 'green'), compilers)

    
if __name__ == "__main__":
    main()
