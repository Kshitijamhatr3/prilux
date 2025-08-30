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

Prilux is a tool for carrying out extensive enmeration for Linux privilege escalation.
![image](https://github.com/user-attachments/assets/1d56deb6-02e5-4fae-ae33-b2366bf138be)
