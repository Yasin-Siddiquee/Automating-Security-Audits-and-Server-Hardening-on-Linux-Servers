# Automating-Security-Audits-and-Server-Hardening-on-Linux-Servers
A Bash script that automates both the security audit and then hardening process of Linux servers. It is modular and reusable, allowing it to be easily deployed across multiple servers to ensure they meet stringent security standards. The script includes checks for common security vulnerabilities, IPv4/IPv6 configurations, public vs. private IP identification, and the implementation of hardening measures.  

### Features

- **User and Group Audits**: Lists all users and groups, checks for users with UID 0 (root privileges), and identifies users with weak or no passwords.
- **File and Directory Permissions**: Scans for world-writable files, insecure `.ssh` directories, and files with SUID/SGID bits set.
- **Service Audits**: Lists running services, checks for unnecessary or unauthorized services, and verifies that critical services are configured correctly.
- **Firewall and Network Security**: Verifies firewall status, reports open ports, and checks for insecure network configurations.
- **IP and Network Configuration**: Identifies public vs. private IP addresses and ensures sensitive services are not exposed unnecessarily.
- **Security Updates and Patching**: Checks for available security updates and ensures the server is configured to receive them regularly.
- **Log Monitoring**: Monitors logs for suspicious activity, such as failed SSH login attempts.
- **Server Hardening**: Implements hardening steps such as disabling password-based root login, configuring firewalls, disabling IPv6, securing the bootloader, and setting up automatic updates.

### Prerequisites

Before using the script, ensure you have the following:

- A Linux server with `bash` shell.
- Administrative (root) access to the server.
- `unattended-upgrades` package installed for automatic updates.
- `ufw` or `iptables` installed and configured for firewall management.
- Email configured on the server (optional, for alerting).

### Installation

1. **Clone the Repository:**

   Clone this repo to your local machine or directly onto the server you want to audit and harden.

   ```bash
   git clone https://github.com/Yasin-Siddiquee/Automating-Security-Audits-and-Server-Hardening-on-Linux-Servers.git

2. **Navigate to the Script Directory:**

   Change into the directory containing the script.

   ```bash
   cd Linux-Security-Audit-and-Hardening

3. **Make the Script Executable:**

   Ensure the script has executable permissions.

   ```bash
   chmod +x Technical_Task_Set2.sh

### Configurable

1. **Admin Email:**

   Set the admin email in the script to receive alerts. Open the script in a text editor and modify the `ADMIN_EMAIL`
   variable.

   ```bash
   ADMIN_EMAIL="admin@example.com"

3. **GRUB Password:**

   Define a password for securing the GRUB bootloader. Modify the `GRUB_PASSWORD` variable.

   ```bash
   GRUB_PASSWORD="your_grub_password"

### Usage

**Run Security Audit**  
To perform a comprehensive security audit of your server:

  ```bash
sudo ./Technical_Task_Set2.sh audit
```
This audit checks users, permissions, services, firewall settings, network configurations, logs, and updates and then generates a report at `/var/log/security_audit_report.log`.

**Run System Hardening**  
To apply security hardening measures to your server:

  ```bash
sudo ./Technical_Task_Set2.sh harden
```
Hardening disables root SSH login, disables IPv6, secures the bootloader, configures the firewall, and sets up automatic updates and also logs the hardening process at `/var/log/hardening_process.log`.

**To perform both a security audit and system hardening:**

  ```bash
sudo ./Technical_Task_Set2.sh.sh audit && sudo ./Technical_Task_Set2.sh.sh harden
```

### Extending the Script

**Configuration File for Custom Checks:**
You can also create a separate configuration file to manage custom checks and include it in the script using the source command.


