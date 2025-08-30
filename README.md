# prilux 🦊

**Summary**
A Python-based Linux enumeration script for post-exploitation auditing and CTF workflows that collects OS/distro/kernel details, flags writable PATH entries, hunts for secrets in environment variables and fstab, queries SearchSploit for kernel/sudo version exploits, lists block devices, and reports useful tooling (interpreters, net utilities, container CLIs, compilers) to inform potential privilege escalation paths. This mirrors standard privesc recon playbooks used by practitioners and checklists like LinEnum/LinPEAS-style routines.

**What it does**

➞ OS and kernel discovery: Reads /proc/version, uname -a, lsb_release -a, and /etc/os-release to fingerprint the platform and kernel for exploit matching.  
➞ Kernel version parsing: Extracts a version in the form X.Y.Z to drive exploit searches.  
➞ Sudo version check: Parses local sudo version via sudo --version for targeted exploit lookups.  
➞ Writable PATH audit: Identifies writable directories in PATH that enable command hijacking escalation scenarios.  
➞ Environment secret scan: Greps env for likely keys/passwords/secrets to surface accidental credential exposure.  
➞ Exploit lookups with SearchSploit: Queries Exploit-DB via searchsploit for “Linux Kernel <version>” and “sudo <version>”.  
➞ Drive and fstab review: Lists sd* devices and scans /etc/fstab for entries and potential embedded credentials.  
➞ Tooling inventory: Reports presence of nmap, nc/curl/wget, interpreters (python/perl/php/ruby), containers (docker/kubectl), and compilers (gcc/g++), including package checks.  
➞ Colorized output: Uses termcolor to present findings clearly; ASCII banner for visual identification.  

**When to use**

➞ After initial foothold to rapidly assess privilege escalation vectors on Linux targets in CTFs, labs, and controlled assessments.  
➞ To map kernel/sudo versions to known public exploits and validate feasibility based on local tooling availability.  
➞ To spot quick wins like writable PATH directories, exposed env secrets, or credentialed fstab mounts.  

**Prerequisites**

➞ Python 3 with termcolor and packaging installed; requests is imported but not used functionally in the current script.  
➞ Optional but recommended: searchsploit installed and updated (Exploit-DB CLI).  
➞ Appropriate permissions to read /proc/version, /etc/os-release, /etc/fstab, and run basic system commands.  

**Installation**

➞ Save the script file to the target system (e.g., enum.py).  
➞ Install Python deps: pip3 install termcolor packaging requests.  
➞ Install SearchSploit if using exploit lookups: follow the Exploit-DB instructions (package or Git install), and update the local DB.  

**Usage**

➞ Grant execute permission if desired: chmod +x enum.py; run with Python 3: python3 enum.py.  
➞ No arguments are required; the script prints colorized sections as it enumerates.  
➞ Network access is not required for core checks; SearchSploit uses the local exploit index.  


Prilux is a tool for carrying out extensive enmeration for Linux privilege escalation.
![image](https://github.com/user-attachments/assets/1d56deb6-02e5-4fae-ae33-b2366bf138be)
