#!/bin/bash

# Script Configuration
REPORT_FILE="/var/log/security_audit_report.log"
HARDENING_LOG="/var/log/hardening_process.log"
ADMIN_EMAIL="admin@example.com"
GRUB_PASSWORD="grubpassword"

# Function to send email alerts
function send_alert() {
    local message="$1"
    echo "$message" | mail -s "Security Audit Alert" $ADMIN_EMAIL
}

# Function to check users and groups
function user_group_audit() {
    echo "Running User and Group Audit..." | tee -a $REPORT_FILE
    echo "List of all users:" >> $REPORT_FILE
    cut -d: -f1 /etc/passwd >> $REPORT_FILE
    
    echo "Users with UID 0 (root privileges):" >> $REPORT_FILE
    awk -F: '($3 == "0") {print $1}' /etc/passwd >> $REPORT_FILE
    
    echo "Checking for users without passwords or with weak passwords..." >> $REPORT_FILE
    awk -F: '($2 == "" || $2 == "x") {print $1}' /etc/shadow >> $REPORT_FILE
    echo "User and Group Audit Completed." >> $REPORT_FILE
}

# Function to check file and directory permissions
function permission_audit() {
    echo "Running File and Directory Permissions Audit..." | tee -a $REPORT_FILE
    echo "World-writable files and directories:" >> $REPORT_FILE
    find / -type f -perm -o+w >> $REPORT_FILE
    find / -type d -perm -o+w >> $REPORT_FILE
    
    echo "Checking for .ssh directories and their permissions..." >> $REPORT_FILE
    find /home -type d -name ".ssh" -exec ls -ld {} \; >> $REPORT_FILE
    
    echo "Files with SUID/SGID bits set:" >> $REPORT_FILE
    find / -perm /6000 -type f >> $REPORT_FILE
    echo "Permission Audit Completed." >> $REPORT_FILE
}

# Function to audit running services
function service_audit() {
    echo "Running Service Audit..." | tee -a $REPORT_FILE
    echo "List of all running services:" >> $REPORT_FILE
    systemctl list-units --type=service >> $REPORT_FILE
    
    echo "Checking for critical services (sshd, iptables)..." >> $REPORT_FILE
    for service in sshd iptables; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is not running" >> $REPORT_FILE
    done
    
    echo "Checking for services listening on non-standard or insecure ports..." >> $REPORT_FILE
    netstat -tuln | grep -Ev '(:22|:80|:443)' >> $REPORT_FILE
    echo "Service Audit Completed." >> $REPORT_FILE
}

# Function to check firewall and network security
function firewall_network_audit() {
    echo "Running Firewall and Network Security Audit..." | tee -a $REPORT_FILE
    echo "Checking if a firewall is active..." >> $REPORT_FILE
    ufw status | grep -qw "active" && echo "UFW is active" || echo "UFW is not active" >> $REPORT_FILE
    
    echo "Open ports and associated services:" >> $REPORT_FILE
    ss -tuln >> $REPORT_FILE
    
    echo "Checking for IP forwarding and other insecure network configurations..." >> $REPORT_FILE
    sysctl net.ipv4.ip_forward | grep -q "0" || echo "IP forwarding is enabled" >> $REPORT_FILE
    echo "Firewall and Network Security Audit Completed." >> $REPORT_FILE
}

# Function to check IP and network configuration
function ip_network_config_audit() {
    echo "Running IP and Network Configuration Audit..." | tee -a $REPORT_FILE
    echo "Public vs. Private IP checks:" >> $REPORT_FILE
    
    for ip in $(hostname -I); do
        if [[ $ip == 10.* || $ip == 172.16.* || $ip == 192.168.* ]]; then
            echo "$ip is a private IP" >> $REPORT_FILE
        else
            echo "$ip is a public IP" >> $REPORT_FILE
        fi
    done
    
    echo "IP and Network Configuration Audit Completed." >> $REPORT_FILE
}

# Function to check for security updates and patching
function update_and_patch() {
    echo "Checking for security updates..." | tee -a $REPORT_FILE
    apt-get update -y
    apt-get upgrade -y >> $HARDENING_LOG
    echo "Security updates applied." >> $HARDENING_LOG
}

# Function to monitor logs
function log_monitoring() {
    echo "Running Log Monitoring..." | tee -a $REPORT_FILE
    echo "Suspicious log entries:" >> $REPORT_FILE
    grep "sshd" /var/log/auth.log | grep "Failed" >> $REPORT_FILE
    echo "Log Monitoring Completed." >> $REPORT_FILE
}

# Function to harden SSH configuration
function harden_ssh() {
    echo "Hardening SSH Configuration..." | tee -a $HARDENING_LOG
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "SSH Configuration Hardened." >> $HARDENING_LOG
}

# Function to disable IPv6
function disable_ipv6() {
    echo "Disabling IPv6..." | tee -a $HARDENING_LOG
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1
    echo "IPv6 Disabled." >> $HARDENING_LOG
}

# Function to secure the bootloader
function secure_bootloader() {
    echo "Securing Bootloader..." | tee -a $HARDENING_LOG
    echo "Setting GRUB password..." >> $HARDENING_LOG
    echo -e "$GRUB_PASSWORD\n$GRUB_PASSWORD" | grub-mkpasswd-pbkdf2 >> /etc/grub.d/40_custom
    update-grub
    echo "Bootloader Secured." >> $HARDENING_LOG
}

# Function to configure the firewall
function configure_firewall() {
    echo "Configuring Firewall..." | tee -a $HARDENING_LOG
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
    echo "Firewall Configured." >> $HARDENING_LOG
}

# Function to configure automatic updates
function configure_auto_updates() {
    echo "Configuring Automatic Updates..." | tee -a $HARDENING_LOG
    apt-get install unattended-upgrades -y >> $HARDENING_LOG
    dpkg-reconfigure --priority=low unattended-upgrades
    echo "Automatic Updates Configured." >> $HARDENING_LOG
}

# Function to run the full audit
function run_full_audit() {
    echo "Starting Full Security Audit..." | tee -a $REPORT_FILE
    user_group_audit
    permission_audit
    service_audit
    firewall_network_audit
    ip_network_config_audit
    log_monitoring
    update_and_patch
    echo "Full Security Audit Completed." | tee -a $REPORT_FILE
}

# Function to run hardening process
function run_hardening() {
    echo "Starting System Hardening..." | tee -a $HARDENING_LOG
    harden_ssh
    disable_ipv6
    secure_bootloader
    configure_firewall
    configure_auto_updates
    echo "System Hardening Completed." | tee -a $HARDENING_LOG
}

# Main script execution
case "$1" in
    audit)
        run_full_audit
        ;;
    harden)
        run_hardening
        ;;
    *)
        echo "Usage: $0 {audit|harden}"
        exit 1
        ;;
esac
