import streamlit as st
import random

# --- Question Definitions (Combined from quiz100.py and quiz200.py) ---

# Level 1 Questions
malware_questions_l1 = [
    {"id": 101, "field": "Malware Analysis", "question": "What is a 'dropper' in malware terminology?", "options": ["A malware that deletes files", "A program that installs malware", "A tool for debugging", "A file encryptor"], "correct_answer": "A program that installs malware", "language_required": "C/C++"},
    {"id": 102, "field": "Malware Analysis", "question": "Which Windows tool is useful for monitoring system activity of malware?", "options": ["Task Manager", "Procmon", "Regedit", "Explorer"], "correct_answer": "Procmon", "language_required": "C/C++"},
    {"id": 103, "field": "Malware Analysis", "question": "What is the function of a sandbox in malware research?", "options": ["To encrypt data", "To run malware in isolation", "To hide IP", "To clean a system"], "correct_answer": "To run malware in isolation", "language_required": "Python"},
    {"id": 104, "field": "Malware Analysis", "question": "What does the tool IDA Pro help with?", "options": ["Network sniffing", "Static binary analysis", "File encryption", "Email phishing"], "correct_answer": "Static binary analysis", "language_required": "C/C++"},
    {"id": 105, "field": "Malware Analysis", "question": "What is 'polymorphic malware'?", "options": ["Uses a constant signature", "Avoids scanning", "Changes code to avoid detection", "Only affects Linux"], "correct_answer": "Changes code to avoid detection", "language_required": "C/C++"},
    {"id": 106, "field": "Malware Analysis", "question": "Which tool helps analyze malware memory usage?", "options": ["Wireshark", "Volatility", "Burp Suite", "sqlmap"], "correct_answer": "Volatility", "language_required": "Python"},
    {"id": 107, "field": "Malware Analysis", "question": "What does PE file stand for?", "options": ["Protected Execution", "Program Executable", "Portable Executable", "Platform Emulator"], "correct_answer": "Portable Executable", "language_required": "C/C++"},
    {"id": 108, "field": "Malware Analysis", "question": "Which of these is a behavior-based malware detection tool?", "options": ["YARA", "Procmon", "Cuckoo Sandbox", "Ghidra"], "correct_answer": "Cuckoo Sandbox", "language_required": "Python"},
    {"id": 109, "field": "Malware Analysis", "question": "What technique does malware use to prevent reverse engineering?", "options": ["Signature-based scanning", "Obfuscation", "Keylogging", "System call tracing"], "correct_answer": "Obfuscation", "language_required": "C/C++"},
    {"id": 110, "field": "Malware Analysis", "question": "Which of the following is used for dynamic malware analysis?", "options": ["IDA Pro", "OllyDbg", "Cuckoo", "Radare2"], "correct_answer": "Cuckoo", "language_required": "Python"}
]

pentest_questions_l1 = [
    {"id": 201, "field": "Penetration Testing", "question": "Which tool is commonly used for network scanning in penetration testing?", "options": ["Wireshark", "Nmap", "John the Ripper", "Snort"], "correct_answer": "Nmap", "language_required": "Python"},
    {"id": 202, "field": "Penetration Testing", "question": "What is the purpose of the Metasploit framework?", "options": ["Firewall testing", "Packet analysis", "Exploit development and execution", "Log aggregation"], "correct_answer": "Exploit development and execution", "language_required": "Ruby"},
    {"id": 203, "field": "Penetration Testing", "question": "Which type of testing simulates an attack with zero internal knowledge?", "options": ["Black Box", "White Box", "Gray Box", "Regression"], "correct_answer": "Black Box", "language_required": "N/A"},
    {"id": 204, "field": "Penetration Testing", "question": "Which tool is best for password cracking?", "options": ["Nikto", "Hydra", "Burp Suite", "Tcpdump"], "correct_answer": "Hydra", "language_required": "C/C++"},
    {"id": 205, "field": "Penetration Testing", "question": "What is the use of Burp Suite in penetration testing?", "options": ["Scanning ports", "Sniffing packets", "Intercepting web traffic", "Checking antivirus strength"], "correct_answer": "Intercepting web traffic", "language_required": "Java"},
    {"id": 206, "field": "Penetration Testing", "question": "Which protocol is commonly targeted during wireless penetration testing?", "options": ["HTTP", "SSH", "WPA2", "SNMP"], "correct_answer": "WPA2", "language_required": "Python"},
    {"id": 207, "field": "Penetration Testing", "question": "Which scripting language is often used for quick exploit development?", "options": ["Perl", "Python", "Bash", "Ruby"], "correct_answer": "Python", "language_required": "Python"},
    {"id": 208, "field": "Penetration Testing", "question": "What does SQL injection target?", "options": ["Filesystem", "Network routers", "Databases", "Memory buffers"], "correct_answer": "Databases", "language_required": "SQL"},
    {"id": 209, "field": "Penetration Testing", "question": "Nikto is primarily used for what purpose?", "options": ["Port scanning", "Web server vulnerability scanning", "Password cracking", "Network sniffing"], "correct_answer": "Web server vulnerability scanning", "language_required": "Perl"},
    {"id": 210, "field": "Penetration Testing", "question": "What is 'pivoting' in the context of a penetration test?", "options": ["Changing user agent", "Gaining root access", "Using one compromised host to attack others", "Logging out attackers"], "correct_answer": "Using one compromised host to attack others", "language_required": "Python"}
]

forensics_questions_l1 = [
    {"id": 301, "field": "Digital Forensics", "question": "What does 'chain of custody' refer to in digital forensics?", "options": ["User password recovery", "Evidence handling process", "Backup procedure", "Antivirus scan report"], "correct_answer": "Evidence handling process", "language_required": "N/A"},
    {"id": 302, "field": "Digital Forensics", "question": "Which tool is widely used to acquire disk images?", "options": ["EnCase", "Autopsy", "Wireshark", "Nmap"], "correct_answer": "EnCase", "language_required": "N/A"},
    {"id": 303, "field": "Digital Forensics", "question": "Which format is commonly used for forensic disk images?", "options": ["ISO", "EWF (Expert Witness Format)", "MP4", "PNG"], "correct_answer": "EWF (Expert Witness Format)", "language_required": "N/A"},
    {"id": 304, "field": "Digital Forensics", "question": "Volatility is primarily used to analyze which type of data?", "options": ["Logs", "Disk images", "Memory dumps", "Encrypted emails"], "correct_answer": "Memory dumps", "language_required": "Python"},
    {"id": 305, "field": "Digital Forensics", "question": "What does MAC in MAC times stand for?", "options": ["Modify, Access, Change", "Move, Alert, Cache", "Monitor, Analyze, Capture", "Memory, Access, Copy"], "correct_answer": "Modify, Access, Change", "language_required": "N/A"},
    {"id": 306, "field": "Digital Forensics", "question": "Which of the following tools is used for forensic analysis of mobile devices?", "options": ["FTK", "Oxygen Forensic Detective", "Wireshark", "Ettercap"], "correct_answer": "Oxygen Forensic Detective", "language_required": "N/A"},
    {"id": 307, "field": "Digital Forensics", "question": "What is the first step in a digital forensic investigation?", "options": ["Image acquisition", "Report writing", "Data recovery", "Evidence presentation"], "correct_answer": "Image acquisition", "language_required": "N/A"},
    {"id": 308, "field": "Digital Forensics", "question": "Autopsy is a GUI front end for which digital forensic tool?", "options": ["Volatility", "The Sleuth Kit", "FTK", "Metasploit"], "correct_answer": "The Sleuth Kit", "language_required": "Java"},
    {"id": 309, "field": "Digital Forensics", "question": "Which hash function is commonly used to verify integrity of evidence?", "options": ["MD5", "AES", "RSA", "SHA-1"], "correct_answer": "MD5", "language_required": "Python"},
    {"id": 310, "field": "Digital Forensics", "question": "Which layer of the OSI model does a forensic packet capture tool operate at?", "options": ["Layer 1", "Layer 3", "Layer 7", "Layer 2"], "correct_answer": "Layer 2", "language_required": "N/A"}
]

cloud_questions_l1 = [
    {"id": 401, "field": "Cloud Security", "question": "Which of the following is a major concern in cloud computing?", "options": ["Low storage", "Internet speed", "Data breaches", "File format issues"], "correct_answer": "Data breaches", "language_required": "N/A"},
    {"id": 402, "field": "Cloud Security", "question": "What does IAM stand for in cloud environments?", "options": ["Internet Access Manager", "Identity and Access Management", "Internal Account Monitor", "Instance Allocation Module"], "correct_answer": "Identity and Access Management", "language_required": "Python"},
    {"id": 403, "field": "Cloud Security", "question": "Which type of cloud offers the highest level of control and customization?", "options": ["Public cloud", "Private cloud", "Hybrid cloud", "Community cloud"], "correct_answer": "Private cloud", "language_required": "N/A"},
    {"id": 404, "field": "Cloud Security", "question": "Which of these cloud providers offers a shared responsibility model?", "options": ["AWS", "Google Drive", "Dropbox", "OneDrive"], "correct_answer": "AWS", "language_required": "Python"},
    {"id": 405, "field": "Cloud Security", "question": "What is the primary goal of encryption in cloud services?", "options": ["Reduce latency", "Enhance connectivity", "Protect data", "Create backups"], "correct_answer": "Protect data", "language_required": "Python"},
    {"id": 406, "field": "Cloud Security", "question": "Which protocol is commonly used for secure API access in cloud services?", "options": ["FTP", "SOAP", "OAuth", "SMTP"], "correct_answer": "OAuth", "language_required": "Python"},
    {"id": 407, "field": "Cloud Security", "question": "What is 'multi-tenancy' in cloud computing?", "options": ["Single-user VMs", "Multiple users sharing resources", "Dedicated hardware", "Offline computing"], "correct_answer": "Multiple users sharing resources", "language_required": "N/A"},
    {"id": 408, "field": "Cloud Security", "question": "Which of these helps monitor security compliance in cloud setups?", "options": ["AWS Config", "Google Docs", "Docker Hub", "Nmap"], "correct_answer": "AWS Config", "language_required": "Python"},
    {"id": 409, "field": "Cloud Security", "question": "What does a WAF protect in cloud environments?", "options": ["Storage services", "Virtual machines", "Web applications", "Network cables"], "correct_answer": "Web applications", "language_required": "Python"},
    {"id": 410, "field": "Cloud Security", "question": "Which of the following is a cloud security best practice?", "options": ["Using default passwords", "Disabling MFA", "Encrypting data in transit", "Exposing all ports"], "correct_answer": "Encrypting data in transit", "language_required": "Python"}
]

network_questions_l1 = [
    {"id": 501, "field": "Network Security", "question": "What is the main function of a firewall?", "options": ["Store data", "Filter network traffic", "Scan emails", "Encrypt hard drives"], "correct_answer": "Filter network traffic", "language_required": "N/A"},
    {"id": 502, "field": "Network Security", "question": "Which protocol is used to securely browse websites?", "options": ["HTTP", "FTP", "HTTPS", "SSH"], "correct_answer": "HTTPS", "language_required": "Python"},
    {"id": 503, "field": "Network Security", "question": "Which of the following tools is used for packet capturing?", "options": ["Wireshark", "Burp Suite", "Nessus", "Splunk"], "correct_answer": "Wireshark", "language_required": "C/C++"},
    {"id": 504, "field": "Network Security", "question": "What does DDoS stand for?", "options": ["Distributed Data of Service", "Dedicated Denial of Service", "Distributed Denial of Service", "Domain Denial of Security"], "correct_answer": "Distributed Denial of Service", "language_required": "N/A"},
    {"id": 505, "field": "Network Security", "question": "What kind of attack involves intercepting communication between two parties?", "options": ["Phishing", "DoS", "MITM", "SQL Injection"], "correct_answer": "MITM", "language_required": "Python"},
    {"id": 506, "field": "Network Security", "question": "Which device helps prevent unauthorized access to a network?", "options": ["Router", "Modem", "Firewall", "Switch"], "correct_answer": "Firewall", "language_required": "Python"},
    {"id": 507, "field": "Network Security", "question": "What is the purpose of port scanning?", "options": ["Email tracking", "Identifying open ports and services", "Data encryption", "Routing traffic"], "correct_answer": "Identifying open ports and services", "language_required": "Python"},
    {"id": 508, "field": "Network Security", "question": "Which command is used to test network connectivity?", "options": ["connect", "ping", "traceroute", "firewall-cmd"], "correct_answer": "ping", "language_required": "Shell"},
    {"id": 509, "field": "Network Security", "question": "What does IDS stand for?", "options": ["Internet Data System", "Intrusion Detection System", "Internal Device Security", "Information Decryption Server"], "correct_answer": "Intrusion Detection System", "language_required": "Python"},
    {"id": 510, "field": "Network Security", "question": "Which of the following is a commonly used IDS tool?", "options": ["Snort", "Git", "Slack", "Terraform"], "correct_answer": "Snort", "language_required": "C/C++"}
]

vmware_questions_l1 = [
    {"id": 601, "field": "VMware Security", "question": "What is the primary purpose of VMware Tools?", "options": ["Malware scanning", "Improve VM performance and functionality", "Patch VMware vulnerabilities", "Create firewall rules"], "correct_answer": "Improve VM performance and functionality", "language_required": "N/A"},
    {"id": 602, "field": "VMware Security", "question": "Which product allows centralized management of VMware environments?", "options": ["vSphere", "vCenter Server", "ESXi", "Workstation"], "correct_answer": "vCenter Server", "language_required": "N/A"},
    {"id": 603, "field": "VMware Security", "question": "Which VMware feature is used for fault tolerance?", "options": ["DRS", "vMotion", "HA", "Snapshots"], "correct_answer": "HA", "language_required": "N/A"},
    {"id": 604, "field": "VMware Security", "question": "Which protocol does VMware use for remote console access?", "options": ["SSH", "VNC", "VMRC", "RDP"], "correct_answer": "VMRC", "language_required": "N/A"},
    {"id": 605, "field": "VMware Security", "question": "What is a key security concern with VM snapshots?", "options": ["Automatic updates", "Large file sizes", "Snapshot sprawl and outdated data", "Script injection"], "correct_answer": "Snapshot sprawl and outdated data", "language_required": "N/A"},
    {"id": 606, "field": "VMware Security", "question": "Which component enforces security hardening on VMware ESXi?", "options": ["vShield", "vMotion", "VMTools", "vSAN"], "correct_answer": "vShield", "language_required": "N/A"},
    {"id": 607, "field": "VMware Security", "question": "Which language is typically used to automate VMware tasks via PowerCLI?", "options": ["Bash", "Python", "PowerShell", "Go"], "correct_answer": "PowerShell", "language_required": "PowerShell"},
    {"id": 608, "field": "VMware Security", "question": "What is the ESXi lockdown mode used for?", "options": ["Disable VMs", "Disable network access", "Restrict remote CLI access to host", "Increase storage"], "correct_answer": "Restrict remote CLI access to host", "language_required": "N/A"},
    {"id": 609, "field": "VMware Security", "question": "Which security measure prevents unauthorized USB device usage in a VM?", "options": ["Device Guard", "Virtual Machine Encryption", "USB arbitrator settings", "UAC"], "correct_answer": "USB arbitrator settings", "language_required": "N/A"},
    {"id": 610, "field": "VMware Security", "question": "Which command-line interface is used for direct ESXi management?", "options": ["esxcli", "vmcli", "vsh", "esxadmin"], "correct_answer": "esxcli", "language_required": "Shell"}
]

iot_questions_l1 = [
    {"id": 701, "field": "IoT Security", "question": "What is the biggest security concern in IoT devices?", "options": ["Battery life", "Physical size", "Lack of encryption", "Antenna strength"], "correct_answer": "Lack of encryption", "language_required": "N/A"},
    {"id": 702, "field": "IoT Security", "question": "Which protocol is commonly used for secure communication in IoT?", "options": ["HTTP", "MQTT", "FTP", "SNMP"], "correct_answer": "MQTT", "language_required": "Python"},
    {"id": 703, "field": "IoT Security", "question": "What does a 'firmware update' address in IoT devices?", "options": ["Change device color", "Fix bugs and security flaws", "Increase battery life", "Enable new features"], "correct_answer": "Fix bugs and security flaws", "language_required": "N/A"},
    {"id": 704, "field": "IoT Security", "question": "Which of these is a common attack vector for IoT devices?", "options": ["Physical tampering", "Overheating", "Weak default credentials", "Screen cracking"], "correct_answer": "Weak default credentials", "language_required": "N/A"},
    {"id": 705, "field": "IoT Security", "question": "What is the primary role of a gateway in an IoT ecosystem?", "options": ["Data visualization", "Connecting devices to the cloud", "Device charging", "Firmware updates only"], "correct_answer": "Connecting devices to the cloud", "language_required": "N/A"},
    {"id": 706, "field": "IoT Security", "question": "Which type of encryption is suitable for low-power IoT devices?", "options": ["AES", "RSA", "ECC", "Blowfish"], "correct_answer": "ECC", "language_required": "N/A"},
    {"id": 707, "field": "IoT Security", "question": "What is a botnet in the context of IoT?", "options": ["Smart home network", "Group of compromised devices", "Secure device update system", "Data analytics platform"], "correct_answer": "Group of compromised devices", "language_required": "N/A"},
    {"id": 708, "field": "IoT Security", "question": "Which security principle is most crucial for IoT updates?", "options": ["Over-the-air (OTA) updates", "Manual updates", "Signed firmware updates", "Monthly updates"], "correct_answer": "Signed firmware updates", "language_required": "N/A"},
    {"id": 709, "field": "IoT Security", "question": "Which standard ensures secure communication between IoT devices?", "options": ["USB", "Bluetooth", "TLS", "NFC"], "correct_answer": "TLS", "language_required": "N/A"},
    {"id": 710, "field": "IoT Security", "question": "What is the common issue with hardcoded credentials in IoT devices?", "options": ["Slow performance", "Easy for attackers to guess", "High power consumption", "Complex to manage"], "correct_answer": "Easy for attackers to guess", "language_required": "N/A"}
]

appsec_questions_l1 = [
    {"id": 801, "field": "Application Security", "question": "Which attack involves inserting malicious code into a web application via input fields?", "options": ["Brute Force", "XSS", "DDoS", "MITM"], "correct_answer": "XSS", "language_required": "JavaScript"},
    {"id": 802, "field": "Application Security", "question": "What is the primary goal of input validation?", "options": ["Optimize performance", "Prevent injection attacks", "Create better UI", "Enhance SEO"], "correct_answer": "Prevent injection attacks", "language_required": "Python"},
    {"id": 803, "field": "Application Security", "question": "Which type of injection exploits database queries?", "options": ["Shell Injection", "Command Injection", "SQL Injection", "HTML Injection"], "correct_answer": "SQL Injection", "language_required": "Python"},
    {"id": 804, "field": "Application Security", "question": "Which HTTP header is used to prevent clickjacking?", "options": ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"], "correct_answer": "X-Frame-Options", "language_required": "JavaScript"},
    {"id": 805, "field": "Application Security", "question": "Which practice ensures sensitive data is unreadable when intercepted?", "options": ["Caching", "Obfuscation", "Encryption", "Minification"], "correct_answer": "Encryption", "language_required": "Python"},
    {"id": 806, "field": "Application Security", "question": "Which tool is commonly used to test web applications for security flaws?", "options": ["Postman", "Burp Suite", "VS Code", "Fiddler"], "correct_answer": "Burp Suite", "language_required": "Python"},
    {"id": 807, "field": "Application Security", "question": "Which term describes automatic security checks during development?", "options": ["DevOps", "Code Analysis", "Static Application Security Testing (SAST)", "CI/CD"], "correct_answer": "Static Application Security Testing (SAST)", "language_required": "Python"},
    {"id": 808, "field": "Application Security", "question": "Which vulnerability allows attackers to execute scripts in another user’s browser?", "options": ["CSRF", "SQLi", "XSS", "RFI"], "correct_answer": "XSS", "language_required": "JavaScript"},
    {"id": 809, "field": "Application Security", "question": "Which HTTP method should be avoided for sensitive data in URLs?", "options": ["GET", "POST", "PUT", "DELETE"], "correct_answer": "GET", "language_required": "N/A"},
    {"id": 810, "field": "Application Security", "question": "Which OWASP project provides a list of top 10 web application vulnerabilities?", "options": ["MITRE", "CWE", "OWASP Top 10", "NIST CSF"], "correct_answer": "OWASP Top 10", "language_required": "N/A"}
]

reverse_engineering_questions_l1 = [
    {"id": 901, "field": "Reverse Engineering", "question": "Which tool is commonly used for analyzing binary executables?", "options": ["Wireshark", "Burp Suite", "IDA Pro", "Metasploit"], "correct_answer": "IDA Pro", "language_required": "Assembly"},
    {"id": 902, "field": "Reverse Engineering", "question": "What is the primary purpose of a disassembler?", "options": ["Obfuscate source code", "Convert source to binary", "Convert binary to assembly", "Patch applications"], "correct_answer": "Convert binary to assembly", "language_required": "Assembly"},
    {"id": 903, "field": "Reverse Engineering", "question": "Which file format is commonly used in Windows for executables?", "options": ["ELF", "EXE", "APK", "BIN"], "correct_answer": "EXE", "language_required": "C/C++"},
    {"id": 904, "field": "Reverse Engineering", "question": "Which tool is widely used for dynamic analysis of Windows binaries?", "options": ["OllyDbg", "Nmap", "tcpdump", "Nikto"], "correct_answer": "OllyDbg", "language_required": "C/C++"},
    {"id": 905, "field": "Reverse Engineering", "question": "What is the purpose of unpacking in reverse engineering?", "options": ["Speed up execution", "Restore obfuscated code", "Compile code", "Add encryption"], "correct_answer": "Restore obfuscated code", "language_required": "Assembly"},
    {"id": 906, "field": "Reverse Engineering", "question": "What is commonly used to inspect the behavior of a program at runtime?", "options": ["Debugger", "Decompiler", "Proxy", "Scanner"], "correct_answer": "Debugger", "language_required": "C"},
    {"id": 907, "field": "Reverse Engineering", "question": "Which technique converts compiled code back into a high-level approximation?", "options": ["Disassembly", "Linking", "Decompilation", "Encoding"], "correct_answer": "Decompilation", "language_required": "C/C++"},
    {"id": 908, "field": "Reverse Engineering", "question": "Which architecture is associated with x86 assembly?", "options": ["ARM", "RISC-V", "Intel", "SPARC"], "correct_answer": "Intel", "language_required": "Assembly"},
    {"id": 909, "field": "Reverse Engineering", "question": "Which of the following best describes a 'string reference' in RE?", "options": ["A breakpoint type", "A pointer to hardcoded text data", "A symbol table", "An opcode shortcut"], "correct_answer": "A pointer to hardcoded text data", "language_required": "Assembly"},
    {"id": 910, "field": "Reverse Engineering", "question": "Which open-source tool can be used as an alternative to IDA Pro?", "options": ["Wireshark", "Ghidra", "Netcat", "Ettercap"], "correct_answer": "Ghidra", "language_required": "Java"}
]

cryptography_questions_l1 = [
    {"id": 1001, "field": "Cryptography", "question": "What is the primary purpose of a cryptographic hash function?", "options": ["Encrypt data", "Authenticate users", "Ensure data integrity", "Generate keys"], "correct_answer": "Ensure data integrity", "language_required": "Python"},
    {"id": 1002, "field": "Cryptography", "question": "Which algorithm is asymmetric?", "options": ["AES", "RSA", "SHA-256", "MD5"], "correct_answer": "RSA", "language_required": "Python"},
    {"id": 1003, "field": "Cryptography", "question": "Which key length is considered secure for AES encryption?", "options": ["56 bits", "128 bits", "512 bits", "2048 bits"], "correct_answer": "128 bits", "language_required": "Python"},
    {"id": 1004, "field": "Cryptography", "question": "What does SSL/TLS primarily provide?", "options": ["Data compression", "Secure communication", "Virus scanning", "Network routing"], "correct_answer": "Secure communication", "language_required": "Python"},
    {"id": 1005, "field": "Cryptography", "question": "Which cryptographic method uses the same key for encryption and decryption?", "options": ["Asymmetric", "Symmetric", "Hashing", "Digital Signature"], "correct_answer": "Symmetric", "language_required": "Python"},
    {"id": 1006, "field": "Cryptography", "question": "What is a digital signature used for?", "options": ["Encrypt files", "Verify authenticity and integrity", "Speed up encryption", "Store keys"], "correct_answer": "Verify authenticity and integrity", "language_required": "Python"},
    {"id": 1007, "field": "Cryptography", "question": "Which library in Python is commonly used for cryptographic operations?", "options": ["pycrypto", "scikit-learn", "tensorflow", "requests"], "correct_answer": "pycrypto", "language_required": "Python"},
    {"id": 1008, "field": "Cryptography", "question": "What is a 'nonce' in cryptography?", "options": ["A random number used once", "A key generation method", "An encryption algorithm", "A decryption method"], "correct_answer": "A random number used once", "language_required": "Python"},
    {"id": 1009, "field": "Cryptography", "question": "Which of the following is NOT a hashing algorithm?", "options": ["SHA-256", "RSA", "MD5", "SHA-1"], "correct_answer": "RSA", "language_required": "Python"},
    {"id": 1010, "field": "Cryptography", "question": "What is the role of a Certificate Authority (CA)?", "options": ["Issue digital certificates", "Encrypt data", "Manage firewalls", "Scan for malware"], "correct_answer": "Issue digital certificates", "language_required": "N/A"}
]


# Level 2 Questions
malware_questions_l2 = [
    {"id": "malware_l2_q1", "field": "Malware Analysis", "question": "Which API call is most commonly monitored for malware process injection?", "options": ["CreateProcess", "WriteProcessMemory", "LoadLibrary", "ReadProcessMemory"], "correct_answer": "WriteProcessMemory", "language_required": "N/A"},
    {"id": "malware_l2_q2", "field": "Malware Analysis", "question": "What is the purpose of a packer in malware distribution?", "options": ["To debug code", "To analyze traffic", "To obfuscate binaries", "To patch vulnerabilities"], "correct_answer": "To obfuscate binaries", "language_required": "N/A"},
    {"id": "malware_l2_q3", "field": "Malware Analysis", "question": "Which Windows Registry key is often used for persistence by malware?", "options": ["HKCU\\Software\\Classes", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCR\\AppID", "HKU\\DEFAULT"], "correct_answer": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "language_required": "N/A"},
    {"id": "malware_l2_q4", "field": "Malware Analysis", "question": "How does a polymorphic virus differ from a regular one?", "options": ["It changes its signature", "It targets hardware", "It can’t be decompiled", "It encrypts files"], "correct_answer": "It changes its signature", "language_required": "N/A"},
    {"id": "malware_l2_q5", "field": "Malware Analysis", "question": "Which disassembler is most popular in advanced malware reverse engineering?", "options": ["OllyDbg", "Ghidra", "Burp Suite", "Nmap"], "correct_answer": "Ghidra", "language_required": "N/A"},
    {"id": "malware_l2_q6", "field": "Malware Analysis", "question": "What type of malware is often embedded inside Microsoft Office macros?", "options": ["Worm", "Trojan", "Dropper", "Macro virus"], "correct_answer": "Macro virus", "language_required": "N/A"},
    {"id": "malware_l2_q7", "field": "Malware Analysis", "question": "What is a common file extension used by ransomware?", "options": [".exe", ".zip", ".enc", ".dll"], "correct_answer": ".enc", "language_required": "N/A"},
    {"id": "malware_l2_q8", "field": "Malware Analysis", "question": "Which tool is used to analyze dynamic behavior of malware?", "options": ["IDA Pro", "Wireshark", "Cuckoo Sandbox", "Volatility"], "correct_answer": "Cuckoo Sandbox", "language_required": "N/A"},
    {"id": "malware_l2_q9", "field": "Malware Analysis", "question": "What is DLL sideloading in malware techniques?", "options": ["Loading a library remotely", "Hijacking a trusted process", "Forcing execution of fake DLLs", "Unloading system libraries"], "correct_answer": "Forcing execution of fake DLLs", "language_required": "N/A"},
    {"id": "malware_l2_q10", "field": "Malware Analysis", "question": "Which section of a PE file typically contains the malware payload?", "options": [".text", ".data", ".rdata", ".rsrc"], "correct_answer": ".text", "language_required": "N/A"}
]

pentest_questions_l2 = [
    {"id": "pentest_l2_q1", "field": "Penetration Testing", "question": "Which of the following tools is primarily used for buffer overflow exploits?", "options": ["Wireshark", "Metasploit", "Nmap", "John the Ripper"], "correct_answer": "Metasploit", "language_required": "N/A"},
    {"id": "pentest_l2_q2", "field": "Penetration Testing", "question": "What is the main function of the `msfvenom` tool?", "options": ["Port scanning", "Payload generation", "SQL fuzzing", "Password cracking"], "correct_answer": "Payload generation", "language_required": "N/A"},
    {"id": "pentest_l2_q3", "field": "Penetration Testing", "question": "Which of the following is NOT a type of penetration test?", "options": ["Black box", "Gray box", "White box", "Green box"], "correct_answer": "Green box", "language_required": "N/A"},
    {"id": "pentest_l2_q4", "field": "Penetration Testing", "question": "Which tool is commonly used for subdomain enumeration?", "options": ["Hydra", "Dirb", "Sublist3r", "Sqlmap"], "correct_answer": "Sublist3r", "language_required": "N/A"},
    {"id": "pentest_l2_q5", "field": "Penetration Testing", "question": "Which HTTP method can be abused to bypass authentication?", "options": ["GET", "POST", "PUT", "OPTIONS"], "correct_answer": "OPTIONS", "language_required": "N/A"},
    {"id": "pentest_l2_q6", "field": "Penetration Testing", "question": "What is the purpose of a reverse shell in penetration testing?", "options": ["Scanning ports", "Escalating privileges", "Remote code execution", "Maintaining persistence"], "correct_answer": "Remote code execution", "language_required": "N/A"},
    {"id": "pentest_l2_q7", "field": "Penetration Testing", "question": "Which of these is a web application fuzzing tool?", "options": ["Burp Suite Intruder", "Aircrack-ng", "Netcat", "Wireshark"], "correct_answer": "Burp Suite Intruder", "language_required": "N/A"},
    {"id": "pentest_l2_q8", "field": "Penetration Testing", "question": "Which port is commonly scanned for SSH brute-force attempts?", "options": ["23", "80", "21", "22"], "correct_answer": "22", "language_required": "N/A"},
    {"id": "pentest_l2_q9", "field": "Penetration Testing", "question": "Which of the following is used to manipulate HTTP requests and responses?", "options": ["Snort", "Netcat", "Burp Suite", "Ettercap"], "correct_answer": "Burp Suite", "language_required": "N/A"},
    {"id": "pentest_l2_q10", "field": "Penetration Testing", "question": "What type of attack does the `Responder` tool help simulate?", "options": ["DNS spoofing", "SQL injection", "MITM over SMB", "ARP flood"], "correct_answer": "MITM over SMB", "language_required": "N/A"}
]

forensics_questions_l2 = [
    {"id": "forensics_l2_q1", "field": "Digital Forensics", "question": "Which file system is most commonly used in Windows forensic analysis?", "options": ["EXT4", "NTFS", "FAT32", "APFS"], "correct_answer": "NTFS", "language_required": "N/A"},
    {"id": "forensics_l2_q2", "field": "Digital Forensics", "question": "What tool is widely used for memory analysis in forensics?", "options": ["Autopsy", "Ghidra", "Volatility", "Sleuth Kit"], "correct_answer": "Volatility", "language_required": "N/A"},
    {"id": "forensics_l2_q3", "field": "Digital Forensics", "question": "Which file contains information about user login activity in Windows?", "options": ["system.log", "NTUSER.DAT", "Security.evtx", "hosts"], "correct_answer": "Security.evtx", "language_required": "N/A"},
    {"id": "forensics_l2_q4", "field": "Digital Forensics", "question": "What is slack space in forensic analysis?", "options": ["Encrypted disk space", "Unallocated space", "Unused space within a cluster", "Temporary buffer space"], "correct_answer": "Unused space within a cluster", "language_required": "N/A"},
    {"id": "forensics_l2_q5", "field": "Digital Forensics", "question": "Which hashing algorithm is considered most secure for forensic image validation?", "options": ["MD5", "SHA1", "SHA256", "CRC32"], "correct_answer": "SHA256", "language_required": "N/A"},
    {"id": "forensics_l2_q6", "field": "Digital Forensics", "question": "Which Windows artifact indicates program execution?", "options": ["Prefetch files", "Hosts file", "Pagefile.sys", "Recycle Bin"], "correct_answer": "Prefetch files", "language_required": "N/A"},
    {"id": "forensics_l2_q7", "field": "Digital Forensics", "question": "Which Linux log file records login attempts?", "options": ["/var/log/messages", "/var/log/syslog", "/var/log/auth.log", "/etc/shadow"], "correct_answer": "/var/log/auth.log", "language_required": "N/A"},
    {"id": "forensics_l2_q8", "field": "Digital Forensics", "question": "What does the term 'chain of custody' mean in digital forensics?", "options": ["Backup chain method", "Timeline of user activity", "Record of evidence handling", "Network trace path"], "correct_answer": "Record of evidence handling", "language_required": "N/A"},
    {"id": "forensics_l2_q9", "field": "Digital Forensics", "question": "What type of file is a memory dump typically saved as?", "options": [".log", ".mem", ".iso", ".img"], "correct_answer": ".mem", "language_required": "N/A"},
    {"id": "forensics_l2_q10", "field": "Digital Forensics", "question": "Which tool is known for timeline analysis in digital forensics?", "options": ["Volatility", "Autopsy", "Plaso", "Ghidra"], "correct_answer": "Plaso", "language_required": "N/A"}
]

cloud_questions_l2 = [
    {"id": "cloud_l2_q1", "field": "Cloud Security", "question": "Which AWS service allows inspection of VPC traffic?", "options": ["CloudTrail", "CloudWatch", "VPC Flow Logs", "IAM"], "correct_answer": "VPC Flow Logs", "language_required": "N/A"},
    {"id": "cloud_l2_q2", "field": "Cloud Security", "question": "What does the shared responsibility model in cloud computing imply?", "options": ["Vendors manage all security", "Users are fully responsible", "Security is jointly managed", "Only networks are secured"], "correct_answer": "Security is jointly managed", "language_required": "N/A"},
    {"id": "cloud_l2_q3", "field": "Cloud Security", "question": "Which of the following is an identity federation tool in AWS?", "options": ["S3", "EC2", "IAM", "Cognito"], "correct_answer": "Cognito", "language_required": "N/A"},
    {"id": "cloud_l2_q4", "field": "Cloud Security", "question": "What is the risk of misconfigured S3 buckets?", "options": ["Service crash", "Public data leakage", "IAM error", "DDoS vulnerability"], "correct_answer": "Public data leakage", "language_required": "N/A"},
    {"id": "cloud_l2_q5", "field": "Cloud Security", "question": "Which framework provides cloud-specific security guidelines?", "options": ["NIST CSF", "OWASP Top 10", "CSA CCM", "ISO 9001"], "correct_answer": "CSA CCM", "language_required": "N/A"},
    {"id": "cloud_l2_q6", "field": "Cloud Security", "question": "What is a cloud access security broker (CASB)?", "options": ["Key management tool", "Monitoring script", "Policy enforcement point", "Cloud firewall"], "correct_answer": "Policy enforcement point", "language_required": "N/A"},
    {"id": "cloud_l2_q7", "field": "Cloud Security", "question": "Which Azure tool is used to manage security alerts?", "options": ["Azure Functions", "Security Center", "Key Vault", "Resource Groups"], "correct_answer": "Security Center", "language_required": "N/A"},
    {"id": "cloud_l2_q8", "field": "Cloud Security", "question": "Which cloud deployment model offers the least control to users?", "options": ["Private cloud", "Public cloud", "Hybrid cloud", "Community cloud"], "correct_answer": "Public cloud", "language_required": "N/A"},
    {"id": "cloud_l2_q9", "field": "Cloud Security", "question": "What is the primary purpose of IAM in cloud environments?", "options": ["Network segmentation", "Traffic monitoring", "User access control", "Data encryption"], "correct_answer": "User access control", "language_required": "N/A"},
    {"id": "cloud_l2_q10", "field": "Cloud Security", "question": "Which cloud model provides full control over OS and network configurations?", "options": ["PaaS", "SaaS", "IaaS", "FaaS"], "correct_answer": "IaaS", "language_required": "N/A"}
]

network_questions_l2 = [
    {"id": "network_l2_q1", "field": "Network Security", "question": "Which protocol is commonly targeted in ARP spoofing attacks?", "options": ["TCP", "UDP", "ICMP", "ARP"], "correct_answer": "ARP", "language_required": "N/A"},
    {"id": "network_l2_q2", "field": "Network Security", "question": "What is the primary function of a firewall?", "options": ["Encrypt data", "Detect malware", "Control incoming and outgoing traffic", "Scan for open ports"], "correct_answer": "Control incoming and outgoing traffic", "language_required": "N/A"},
    {"id": "network_l2_q3", "field": "Network Security", "question": "Which tool is used to analyze network packets?", "options": ["Metasploit", "Burp Suite", "Wireshark", "Nikto"], "correct_answer": "Wireshark", "language_required": "N/A"},
    {"id": "network_l2_q4", "field": "Network Security", "question": "Which attack involves flooding a system with SYN requests?", "options": ["SYN flood", "Ping of death", "Smurf attack", "DNS spoofing"], "correct_answer": "SYN flood", "language_required": "N/A"},
    {"id": "network_l2_q5", "field": "Network Security", "question": "What is the function of an Intrusion Detection System (IDS)?", "options": ["Encrypt data", "Block IP addresses", "Monitor and detect malicious traffic", "Balance network load"], "correct_answer": "Monitor and detect malicious traffic", "language_required": "N/A"},
    {"id": "network_l2_q6", "field": "Network Security", "question": "Which protocol is used to secure communication over the web?", "options": ["HTTP", "FTP", "SSL/TLS", "Telnet"], "correct_answer": "SSL/TLS", "language_required": "N/A"},
    {"id": "network_l2_q7", "field": "Network Security", "question": "What is port scanning?", "options": ["Flooding a server", "Searching open ports on a host", "Encrypting traffic", "Changing DNS settings"], "correct_answer": "Searching open ports on a host", "language_required": "N/A"},
    {"id": "network_l2_q8", "field": "Network Security", "question": "What type of firewall inspects both incoming and outgoing packets?", "options": ["Packet-filtering", "Application-layer", "Stateful inspection", "Proxy"], "correct_answer": "Stateful inspection", "language_required": "N/A"},
    {"id": "network_l2_q9", "field": "Network Security", "question": "Which command is used in Linux to view active network connections?", "options": ["netstat", "ping", "traceroute", "nslookup"], "correct_answer": "netstat", "language_required": "N/A"},
    {"id": "network_l2_q10", "field": "Network Security", "question": "Which DNS record type maps a domain name to an IP address?", "options": ["MX", "TXT", "A", "CNAME"], "correct_answer": "A", "language_required": "N/A"}
]

vmware_questions_l2 = [
    {"id": "vmware_l2_q1", "field": "VMware Security", "question": "What is the purpose of VMware vShield?", "options": ["Snapshot management", "Host migration", "Network security and firewalling", "Storage automation"], "correct_answer": "Network security and firewalling", "language_required": "N/A"},
    {"id": "vmware_l2_q2", "field": "VMware Security", "question": "What is VM escape in virtualization security?", "options": ["Cloning a VM", "Isolating a VM", "Running malware inside a VM", "Breaking out of VM to access host"], "correct_answer": "Breaking out of VM to access host", "language_required": "N/A"},
    {"id": "vmware_l2_q3", "field": "VMware Security", "question": "Which feature helps in encrypting VM data at rest in vSphere?", "options": ["vMotion", "vSAN", "VM Encryption", "Snapshots"], "correct_answer": "VM Encryption", "language_required": "N/A"},
    {"id": "vmware_l2_q4", "field": "VMware Security", "question": "Which VMware feature ensures secure boot of ESXi hosts?", "options": ["VMware Tools", "UEFI Secure Boot", "vApp", "NSX Firewall"], "correct_answer": "UEFI Secure Boot", "language_required": "N/A"},
    {"id": "vmware_l2_q5", "field": "VMware Security", "question": "What does the VMware NSX product primarily provide?", "options": ["Application testing", "Storage replication", "Network virtualization and security", "Snapshot management"], "correct_answer": "Network virtualization and security", "language_required": "N/A"},
    {"id": "vmware_l2_q6", "field": "VMware Security", "question": "Which of the following helps prevent unauthorized USB access in VMs?", "options": ["vSAN", "vShield", "VM Encryption", "Device Control Policy"], "correct_answer": "Device Control Policy", "language_required": "N/A"},
    {"id": "vmware_l2_q7", "field": "VMware Security", "question": "Which type of attack is specific to hypervisors in virtualization?", "options": ["VM escape", "DDoS", "ARP spoofing", "Man-in-the-middle"], "correct_answer": "VM escape", "language_required": "N/A"},
    {"id": "vmware_l2_q8", "field": "VMware Security", "question": "What is the purpose of the lockdown mode in ESXi?", "options": ["Disable firewall", "Restrict SSH", "Prevent direct host access", "Force reboot"], "correct_answer": "Prevent direct host access", "language_required": "N/A"},
    {"id": "vmware_l2_q9", "field": "VMware Security", "question": "Which security measure protects the VM BIOS/UEFI from tampering?", "options": ["vTPM", "Secure Boot", "VM Encryption", "vShield"], "correct_answer": "Secure Boot", "language_required": "N/A"},
    {"id": "vmware_l2_q10", "field": "VMware Security", "question": "Which log file helps audit changes to vCenter Server configuration?", "options": ["vpxa.log", "hostd.log", "vCenter Server events", "vmkernel.log"], "correct_answer": "vCenter Server events", "language_required": "N/A"}
]

iot_questions_l2 = [
    {"id": "iot_l2_q1", "field": "IoT Security", "question": "Which of the following best describes 'device hardening' in IoT?", "options": ["Making devices physically stronger", "Improving battery life", "Securing configurations and reducing attack surface", "Increasing processing power"], "correct_answer": "Securing configurations and reducing attack surface", "language_required": "N/A"},
    {"id": "iot_l2_q2", "field": "IoT Security", "question": "What is the common vulnerability in many consumer IoT devices related to authentication?", "options": ["Biometric failure", "Weak default credentials", "Multi-factor authentication issues", "Token expiration"], "correct_answer": "Weak default credentials", "language_required": "N/A"},
    {"id": "iot_l2_q3", "field": "IoT Security", "question": "Which network protocol is specifically designed for constrained IoT devices?", "options": ["HTTP", "FTP", "CoAP", "SSH"], "correct_answer": "CoAP", "language_required": "N/A"},
    {"id": "iot_l2_q4", "field": "IoT Security", "question": "What is the primary risk associated with 'shadow IoT'?", "options": ["Increased battery drain", "Devices operating outside IT oversight", "Improved network performance", "Reduced data storage"], "correct_answer": "Devices operating outside IT oversight", "language_required": "N/A"},
    {"id": "iot_l2_q5", "field": "IoT Security", "question": "Which security measure helps ensure the integrity of IoT device firmware?", "options": ["Regular reboots", "Signed firmware updates", "Network segmentation", "Cloud backups"], "correct_answer": "Signed firmware updates", "language_required": "N/A"},
    {"id": "iot_l2_q6", "field": "IoT Security", "question": "What does a 'zero-day exploit' mean in IoT security?", "options": ["An exploit that has been patched", "An exploit for which no patch exists yet", "An exploit that affects only one device", "An exploit from day zero of device use"], "correct_answer": "An exploit for which no patch exists yet", "language_required": "N/A"},
    {"id": "iot_l2_q7", "field": "IoT Security", "question": "Which type of attack floods IoT devices with traffic to make them unavailable?", "options": ["SQL injection", "Man-in-the-middle", "DDoS", "Phishing"], "correct_answer": "DDoS", "language_required": "N/A"},
    {"id": "iot_l2_q8", "field": "IoT Security", "question": "What is a 'security by design' principle in IoT development?", "options": ["Adding security features after launch", "Integrating security throughout the development lifecycle", "Outsourcing security to third parties", "Relying on user vigilance for security"], "correct_answer": "Integrating security throughout the development lifecycle", "language_required": "N/A"},
    {"id": "iot_l2_q9", "field": "IoT Security", "question": "Which industry standard focuses on securing IoT devices and their ecosystems?", "options": ["PCI DSS", "HIPAA", "NIST IoT Security", "GDPR"], "correct_answer": "NIST IoT Security", "language_required": "N/A"},
    {"id": "iot_l2_q10", "field": "IoT Security", "question": "What is the primary purpose of secure boot in an IoT device?", "options": ["Speed up boot time", "Ensure only trusted software loads", "Increase storage capacity", "Enable remote access"], "correct_answer": "Ensure only trusted software loads", "language_required": "N/A"}
]

appsec_questions_l2 = [
    {"id": "appsec_l2_q1", "field": "Application Security", "question": "Which type of vulnerability occurs when user input is improperly escaped in HTML?", "options": ["SQL Injection", "Buffer Overflow", "XSS", "CSRF"], "correct_answer": "XSS", "language_required": "N/A"},
    {"id": "appsec_l2_q2", "field": "Application Security", "question": "What does the 'A' in the OWASP A03:2021 stand for?", "options": ["Access Control", "Authentication Failures", "Authorization Bypass", "Injection"], "correct_answer": "Injection", "language_required": "N/A"},
    {"id": "appsec_l2_q3", "field": "Application Security", "question": "Which header is used to protect against clickjacking attacks?", "options": ["Content-Type", "X-Frame-Options", "Cache-Control", "Set-Cookie"], "correct_answer": "X-Frame-Options", "language_required": "N/A"},
    {"id": "appsec_l2_q4", "field": "Application Security", "question": "What is the purpose of a Content Security Policy (CSP)?", "options": ["Limit JavaScript execution", "Block IP addresses", "Encrypt sessions", "Prevent XSS attacks"], "correct_answer": "Prevent XSS attacks", "language_required": "N/A"},
    {"id": "appsec_l2_q5", "field": "Application Security", "question": "Which vulnerability involves tricking users into executing unwanted actions while logged in?", "options": ["SQL Injection", "XSS", "CSRF", "LFI"], "correct_answer": "CSRF", "language_required": "N/A"},
    {"id": "appsec_l2_q6", "field": "Application Security", "question": "What is the secure way to handle passwords in modern applications?", "options": ["Store in plain text", "Base64 encode them", "Use symmetric encryption", "Hash with bcrypt/scrypt"], "correct_answer": "Hash with bcrypt/scrypt", "language_required": "N/A"},
    {"id": "appsec_l2_q7", "field": "Application Security", "question": "Which testing type examines the internal logic of an application?", "options": ["Black-box", "Gray-box", "White-box", "Fuzzing"], "correct_answer": "White-box", "language_required": "N/A"},
    {"id": "appsec_l2_q8", "field": "Application Security", "question": "What is the risk of using outdated third-party libraries?", "options": ["Increased memory", "UI mismatch", "Known vulnerabilities", "Licensing issues"], "correct_answer": "Known vulnerabilities", "language_required": "N/A"},
    {"id": "appsec_l2_q9", "field": "Application Security", "question": "Which of the following tools is used for dynamic application security testing (DAST)?", "options": ["SonarQube", "ZAP", "Nessus", "Bandit"], "correct_answer": "ZAP", "language_required": "N/A"},
    {"id": "appsec_l2_q10", "field": "Application Security", "question": "What does input validation help prevent?", "options": ["Broken access control", "Command injection", "Data loss", "Timeout errors"], "correct_answer": "Command injection", "language_required": "N/A"}
]

reverse_engineering_questions_l2 = [
    {"id": "reveng_l2_q1", "field": "Reverse Engineering", "question": "Which file format is commonly used for Windows executables?", "options": ["ELF", "PE", "Mach-O", "DEX"], "correct_answer": "PE", "language_required": "N/A"},
    {"id": "reveng_l2_q2", "field": "Reverse Engineering", "question": "Which tool provides interactive disassembly and debugging for x86 binaries?", "options": ["Netcat", "GDB", "IDA Pro", "Hydra"], "correct_answer": "IDA Pro", "language_required": "N/A"},
    {"id": "reveng_l2_q3", "field": "Reverse Engineering", "question": "Which section of a PE file typically contains imported DLL names?", "options": [".text", ".rsrc", ".idata", ".reloc"], "correct_answer": ".idata", "language_required": "N/A"},
    {"id": "reveng_l2_q4", "field": "Reverse Engineering", "question": "What is the primary purpose of using a debugger in reverse engineering?", "options": ["Encrypt files", "Edit memory values", "Understand code behavior", "Obfuscate strings"], "correct_answer": "Understand code behavior", "language_required": "N/A"},
    {"id": "reveng_l2_q5", "field": "Reverse Engineering", "question": "Which tool is developed by NSA for reverse engineering purposes?", "options": ["Radare2", "OllyDbg", "Ghidra", "Frida"], "correct_answer": "Ghidra", "language_required": "N/A"},
    {"id": "reveng_l2_q6", "field": "Reverse Engineering", "question": "Which CPU architecture is NOT supported by most reverse engineering tools?", "options": ["x86", "ARM", "MIPS", "Quantum"], "correct_answer": "Quantum", "language_required": "N/A"},
    {"id": "reveng_l2_q7", "field": "Reverse Engineering", "question": "What does string obfuscation in binaries aim to prevent?", "options": ["Large binaries", "User access", "Signature-based detection", "Static analysis"], "correct_answer": "Static analysis", "language_required": "N/A"},
    {"id": "reveng_l2_q8", "field": "Reverse Engineering", "question": "Which instruction typically marks the end of a function in x86 assembly?", "options": ["NOP", "JMP", "RET", "CALL"], "correct_answer": "RET", "language_required": "N/A"},
    {"id": "reveng_l2_q9", "field": "Reverse Engineering", "question": "What is the purpose of 'anti-debugging' techniques in software?", "options": ["Optimize speed", "Confuse attackers", "Prevent analysis", "Crash the app"], "correct_answer": "Prevent analysis", "language_required": "N/A"},
    {"id": "reveng_l2_q10", "field": "Reverse Engineering", "question": "Which tool is known for mobile app reverse engineering on Android?", "options": ["IDA Free", "MobSF", "Nmap", "Metasploit"], "correct_answer": "MobSF", "language_required": "N/A"}
]

cryptography_questions_l2 = [
    {"id": "crypto_l2_q1", "field": "Cryptography", "question": "Which cryptographic algorithm is based on the difficulty of factoring large integers?", "options": ["AES", "RSA", "SHA-256", "Blowfish"], "correct_answer": "RSA", "language_required": "N/A"},
    {"id": "crypto_l2_q2", "field": "Cryptography", "question": "What is the primary purpose of a cryptographic hash function?", "options": ["Encrypt messages", "Compress files", "Verify data integrity", "Provide confidentiality"], "correct_answer": "Verify data integrity", "language_required": "N/A"},
    {"id": "crypto_l2_q3", "field": "Cryptography", "question": "Which of the following is a symmetric key algorithm?", "options": ["RSA", "ECC", "DES", "DSA"], "correct_answer": "DES", "language_required": "N/A"},
    {"id": "crypto_l2_q4", "field": "Cryptography", "question": "Which attack involves finding two inputs that produce the same hash?", "options": ["Side-channel attack", "Collision attack", "Replay attack", "Padding oracle attack"], "correct_answer": "Collision attack", "language_required": "N/A"},
    {"id": "crypto_l2_q5", "field": "Cryptography", "question": "Which protocol uses asymmetric encryption for key exchange and symmetric encryption for session data?", "options": ["TLS", "SSL", "HTTPS", "SSH"], "correct_answer": "TLS", "language_required": "N/A"},
    {"id": "crypto_l2_q6", "field": "Cryptography", "question": "What is a common key size used in AES encryption?", "options": ["56-bit", "128-bit", "160-bit", "1024-bit"], "correct_answer": "128-bit", "language_required": "N/A"},
    {"id": "crypto_l2_q7", "field": "Cryptography", "question": "Which cryptographic technique is used in Bitcoin?", "options": ["RSA", "Blowfish", "SHA-256", "3DES"], "correct_answer": "SHA-256", "language_required": "N/A"},
    {"id": "crypto_l2_q8", "field": "Cryptography", "question": "Which algorithm is primarily used for digital signatures?", "options": ["RSA", "AES", "SHA1", "MD5"], "correct_answer": "RSA", "language_required": "N/A"},
    {"id": "crypto_l2_q9", "field": "Cryptography", "question": "What is elliptic curve cryptography (ECC) known for?", "options": ["Large key sizes", "Fast hashing", "High security with smaller keys", "Slow decryption"], "correct_answer": "High security with smaller keys", "language_required": "N/A"},
    {"id": "crypto_l2_q10", "field": "Cryptography", "question": "Which of the following is a stream cipher?", "options": ["DES", "AES", "RC4", "Blowfish"], "correct_answer": "RC4", "language_required": "N/A"}
]

# Combine all questions for each level
all_questions_l1 = (
    malware_questions_l1 + pentest_questions_l1 + forensics_questions_l1 +
    cloud_questions_l1 + network_questions_l1 + vmware_questions_l1 +
    iot_questions_l1 + appsec_questions_l1 + reverse_engineering_questions_l1 +
    cryptography_questions_l1
)

all_questions_l2 = (
    malware_questions_l2 + pentest_questions_l2 + forensics_questions_l2 +
    cloud_questions_l2 + network_questions_l2 + vmware_questions_l2 +
    iot_questions_l2 + appsec_questions_l2 + reverse_engineering_questions_l2 +
    cryptography_questions_l2
)

# --- Helper Functions ---

def select_questions(questions_list, num_questions_per_field=2):
    """
    Selects a specified number of questions per field, shuffles them,
    and returns a combined list.
    """
    selected = []
    fields = {}
    for q in questions_list:
        if q["field"] not in fields:
            fields[q["field"]] = []
        fields[q["field"]].append(q)

    for field in fields:
        random.shuffle(fields[field])
        selected.extend(fields[field][:num_questions_per_field])
    random.shuffle(selected)
    return selected

def score_quiz(questions, user_answers):
    """
    Scores the quiz and calculates field-wise scores.
    """
    score = 0
    field_scores = {}
    for q in questions:
        correct = q["correct_answer"]
        user = user_answers.get(q["id"])
        if user == correct:
            score += 1
            field_scores[q["field"]] = field_scores.get(q["field"], 0) + 1
    return score, field_scores

def recommend_field(field_scores):
    """
    Recommends a field based on the highest score.
    """
    if not field_scores:
        return "No strong recommendation based on your answers."
    max_score = max(field_scores.values())
    top_fields = [field for field, score in field_scores.items() if score == max_score]
    return ", ".join(top_fields)

# --- Streamlit Application Logic ---

st.title("Cybersecurity Knowledge Quiz")

# Initialize session state variables
if 'quiz_state' not in st.session_state:
    st.session_state.quiz_state = "start" # "start", "level1_quiz", "level1_results", "level2_quiz", "level2_results"
if 'level1_questions' not in st.session_state:
    st.session_state.level1_questions = select_questions(all_questions_l1, num_questions_per_field=2)
if 'level1_current_q_index' not in st.session_state:
    st.session_state.level1_current_q_index = 0
if 'level1_user_answers' not in st.session_state:
    st.session_state.level1_user_answers = {}
if 'level1_score' not in st.session_state:
    st.session_state.level1_score = 0
if 'level1_field_scores' not in st.session_state:
    st.session_state.level1_field_scores = {}

if 'level2_questions' not in st.session_state:
    st.session_state.level2_questions = select_questions(all_questions_l2, num_questions_per_field=2)
if 'level2_current_q_index' not in st.session_state:
    st.session_state.level2_current_q_index = 0
if 'level2_user_answers' not in st.session_state:
    st.session_state.level2_user_answers = {}
if 'level2_score' not in st.session_state:
    st.session_state.level2_score = 0
if 'level2_field_scores' not in st.session_state:
    st.session_state.level2_field_scores = {}

# --- Display Logic based on quiz_state ---

if st.session_state.quiz_state == "start":
    st.write("Welcome to the Cybersecurity Knowledge Quiz! Test your expertise across various domains.")
    st.write("We'll start with Level 1 (Foundational Knowledge) and then move to Level 2 (Advanced Knowledge).")
    if st.button("Start Level 1 Quiz"):
        st.session_state.quiz_state = "level1_quiz"
        st.session_state.level1_current_q_index = 0
        st.session_state.level1_user_answers = {}
        st.experimental_rerun()

elif st.session_state.quiz_state == "level1_quiz":
    st.header("Level 1: Foundational Cybersecurity Knowledge")
    questions = st.session_state.level1_questions
    current_index = st.session_state.level1_current_q_index

    if current_index < len(questions):
        current_question = questions[current_index]
        st.subheader(f"Question {current_index + 1}/{len(questions)}")
        st.markdown(f"**{current_question['question']}**")

        # Use a form to ensure all radio buttons are submitted together
        with st.form(key=f"level1_q_form_{current_question['id']}"):
            selected_option = st.radio(
                "Select your answer:",
                current_question["options"],
                key=f"level1_radio_{current_question['id']}"
            )
            submit_button = st.form_submit_button("Submit Answer & Next")

            if submit_button:
                st.session_state.level1_user_answers[current_question["id"]] = selected_option
                st.session_state.level1_current_q_index += 1
                st.experimental_rerun()
    else:
        # All Level 1 questions answered, move to results
        st.session_state.quiz_state = "level1_results"
        st.experimental_rerun()

elif st.session_state.quiz_state == "level1_results":
    st.header("Level 1 Results")
    total_score_l1, field_scores_l1 = score_quiz(st.session_state.level1_questions, st.session_state.level1_user_answers)
    st.session_state.level1_score = total_score_l1
    st.session_state.level1_field_scores = field_scores_l1

    st.write(f"Your Total Score for Level 1: **{total_score_l1}/{len(st.session_state.level1_questions)}**")
    st.subheader("Field-wise Scores (Level 1):")
    for field, score in field_scores_l1.items():
        st.write(f" - {field}: {score} correct")

    recommended_l1 = recommend_field(field_scores_l1)
    st.markdown(f"**Based on your Level 1 answers, we recommend focusing on: {recommended_l1}**")

    if st.button("Proceed to Level 2 Quiz"):
        st.session_state.quiz_state = "level2_quiz"
        st.session_state.level2_current_q_index = 0
        st.session_state.level2_user_answers = {}
        st.experimental_rerun()

elif st.session_state.quiz_state == "level2_quiz":
    st.header("Level 2: Advanced Cybersecurity Knowledge")
    questions = st.session_state.level2_questions
    current_index = st.session_state.level2_current_q_index

    if current_index < len(questions):
        current_question = questions[current_index]
        st.subheader(f"Question {current_index + 1}/{len(questions)}")
        st.markdown(f"**{current_question['question']}**")

        with st.form(key=f"level2_q_form_{current_question['id']}"):
            selected_option = st.radio(
                "Select your answer:",
                current_question["options"],
                key=f"level2_radio_{current_question['id']}"
            )
            submit_button = st.form_submit_button("Submit Answer & Next")

            if submit_button:
                st.session_state.level2_user_answers[current_question["id"]] = selected_option
                st.session_state.level2_current_q_index += 1
                st.experimental_rerun()
    else:
        # All Level 2 questions answered, move to results
        st.session_state.quiz_state = "level2_results"
        st.experimental_rerun()

elif st.session_state.quiz_state == "level2_results":
    st.header("Level 2 Results & Overall Summary")
    total_score_l2, field_scores_l2 = score_quiz(st.session_state.level2_questions, st.session_state.level2_user_answers)
    st.session_state.level2_score = total_score_l2
    st.session_state.level2_field_scores = field_scores_l2

    st.write(f"Your Total Score for Level 2: **{total_score_l2}/{len(st.session_state.level2_questions)}**")
    st.subheader("Field-wise Scores (Level 2):")
    for field, score in field_scores_l2.items():
        st.write(f" - {field}: {score} correct")

    # Overall Summary
    st.markdown("---")
    st.subheader("Overall Quiz Performance")
    overall_total_score = st.session_state.level1_score + st.session_state.level2_score
    overall_max_score = len(st.session_state.level1_questions) + len(st.session_state.level2_questions)
    st.success(f"Your Overall Score: **{overall_total_score}/{overall_max_score}**")

    overall_field_scores = st.session_state.level1_field_scores.copy()
    for field, score in st.session_state.level2_field_scores.items():
        overall_field_scores[field] = overall_field_scores.get(field, 0) + score

    overall_recommended = recommend_field(overall_field_scores)
    st.info(f"**Overall Recommendation: {overall_recommended}**")

    if st.button("Restart Quiz"):
        # Reset all session state variables to restart from scratch
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.experimental_rerun()

