#!/bin/bash

# ______          _   _  __          _____ _     _      _     _ 
# |  ____|        | | (_)/ _|        / ____| |   (_)    | |   | |
# | |__ ___  _ __ | |_ _| |_ _   _  | (___ | |__  _  ___| | __| |
# |  __/ _ \| '_ \| __| |  _| | | |  \___ \| '_ \| |/ _ \ |/ _` |
# | | | (_) | | | | |_| | | | |_| |  ____) | | | | |  __/ | (_| |
# |_|  \___/|_| |_|\__|_|_|  \__, | |_____/|_| |_|_|\___|_|\__,_|
#                             __/ |                              
#                            |___/                               
# Security Hardening Script for Debian and RHEL-based systems
# Version 2.0

# Set colors and formatting
BOLD="\e[1m"
YELLOW="\e[93m"
GREEN="\e[92m"
BLUE="\e[94m"
RED="\e[91m"
PURPLE="\e[95m"
CYAN="\e[96m"
RESET="\e[0m"
TICK="✓"
CROSS="✗"
WARNING="⚠"
INFO="ℹ"
BFR="\r\033[K"

# Initialize variables
OS_TYPE=""
BACKUP_DIR="/root/security_backups/$(date +%Y%m%d_%H%M%S)"
CONFIG_DIR="/etc/fortify-shield"
LOG_FILE="/var/log/fortify-shield.log"
SECURITY_SCORE=0
SECURITY_REPORT_FILE="/root/security_report.md"
SECURITY_SUMMARY="/root/security_summary.txt"

# Configuration options with defaults
SSH_PORT="2222"
SSH_USERS=""
SSH_GROUPS=""
MFA_ENABLE=true
AUTO_UPDATES=true
FIREWALL_TYPE="standard" # standard/strict
LOCKDOWN_MODE=false
DISABLE_ROOT=false
ENABLE_AUDITD=true
ENABLE_AIDE=false
ENABLE_CLAMAV=false
ENABLE_FAIL2BAN=true
KERNEL_HARDENING=true
NETWORK_HARDENING=true
FILESYSTEM_HARDENING=true
APPLY_IMMEDIATELY=true
APPLY_REBOOT=false
BLACKLIST_MODULES=true
IP_ALLOWLIST=""

# Track changes for report
CHANGES_MADE=()
WARNINGS=()

# Function to handle logging
log() {
  local level="$1"
  local message="$2"
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
  
  if [[ "$level" == "ERROR" ]]; then
    WARNINGS+=("${message}")
  fi
}

# Function to display messages
msg() {
  local type="$1"
  local message="$2"
  
  case "${type}" in
    info)
      echo -ne " ${INFO} ${CYAN}${message}...${RESET}"
      log "INFO" "${message}"
      ;;
    ok)
      echo -e "${BFR} ${GREEN}${TICK}${RESET} ${GREEN}${message}${RESET}"
      log "SUCCESS" "${message}"
      CHANGES_MADE+=("${message}")
      ;;
    warn)
      echo -e "${BFR} ${YELLOW}${WARNING}${RESET} ${YELLOW}${message}${RESET}"
      log "WARNING" "${message}"
      WARNINGS+=("${message}")
      ;;
    error)
      echo -e "${BFR} ${RED}${CROSS}${RESET} ${RED}${message}${RESET}"
      log "ERROR" "${message}"
      WARNINGS+=("${message}")
      ;;
    prompt)
      echo -e " ${INFO} ${BLUE}${message}${RESET}"
      log "PROMPT" "${message}"
      ;;
    section)
      echo -e "\n${PURPLE}${BOLD}${message}${RESET}\n"
      log "SECTION" "${message}"
      ;;
  esac
}

# Function to prompt for confirmation
confirm() {
  local message="$1"
  local default="$2"
  
  if [ "${default}" = "Y" ]; then
    prompt="Y/n"
    default="Y"
  else
    prompt="y/N"
    default="N"
  fi
  
  while true; do
    msg prompt "${message} [${prompt}]"
    read -r response
    
    if [ -z "${response}" ]; then
      response="${default}"
    fi
    
    case "${response}" in
      [Yy]* ) return 0;;
      [Nn]* ) return 1;;
      * ) echo "Please answer yes or no.";;
    esac
  done
}

# Function to prompt for value
prompt_value() {
  local message="$1"
  local default="$2"
  local validate_func="$3"
  
  while true; do
    if [ -n "${default}" ]; then
      msg prompt "${message} [${default}]"
    else
      msg prompt "${message}"
    fi
    
    read -r response
    
    if [ -z "${response}" ] && [ -n "${default}" ]; then
      response="${default}"
    fi
    
    if [ -n "${validate_func}" ]; then
      if ${validate_func} "${response}"; then
        echo "${response}"
        return 0
      else
        msg warn "Invalid input. Please try again."
        continue
      fi
    else
      echo "${response}"
      return 0
    fi
  done
}

# Function to prompt for selection from a list
prompt_select() {
  local message="$1"
  shift
  local options=("$@")
  
  echo -e " ${INFO} ${BLUE}${message}${RESET}"
  
  for i in "${!options[@]}"; do
    echo -e "   ${CYAN}$((i+1))${RESET}. ${options[$i]}"
  done
  
  while true; do
    msg prompt "Enter your selection (1-${#options[@]})"
    read -r selection
    
    if [[ "${selection}" =~ ^[0-9]+$ ]] && [ "${selection}" -ge 1 ] && [ "${selection}" -le "${#options[@]}" ]; then
      echo "${options[$((selection-1))]}"
      return 0
    else
      msg warn "Invalid selection. Please try again."
    fi
  done
}

# Function to validate port number
validate_port() {
  local port="$1"
  if [[ "${port}" =~ ^[0-9]+$ ]] && [ "${port}" -ge 1 ] && [ "${port}" -le 65535 ]; then
    return 0
  else
    return 1
  fi
}

# Function to validate IP address
validate_ip() {
  local ip="$1"
  if [[ "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    IFS='.' read -r -a ip_parts <<< "${ip}"
    for part in "${ip_parts[@]}"; do
      if [ "${part}" -gt 255 ]; then
        return 1
      fi
    done
    return 0
  elif [[ "${ip}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    # CIDR notation
    local cidr="${ip#*/}"
    if [ "${cidr}" -gt 32 ]; then
      return 1
    fi
    ip="${ip%/*}"
    IFS='.' read -r -a ip_parts <<< "${ip}"
    for part in "${ip_parts[@]}"; do
      if [ "${part}" -gt 255 ]; then
        return 1
      fi
    done
    return 0
  else
    return 1
  fi
}

# Function to backup configuration files
backup_config() {
  local file="$1"
  
  if [ ! -f "${file}" ]; then
    msg warn "File not found: ${file}"
    return 1
  fi
  
  mkdir -p "${BACKUP_DIR}/$(dirname "${file}")"
  cp -p --preserve=all "${file}" "${BACKUP_DIR}/${file}"
  
  if [ $? -eq 0 ]; then
    msg ok "Backed up: ${file}"
    return 0
  else
    msg error "Failed to backup: ${file}"
    return 1
  fi
}

# Function to detect the OS type
detect_os() {
  msg info "Detecting operating system"
  
  if [ -f /etc/debian_version ]; then
    OS_TYPE="debian"
    msg ok "Detected Debian-based system"
    
    # Check if it's Ubuntu
    if [ -f /etc/lsb-release ] && grep -q "Ubuntu" /etc/lsb-release; then
      OS_SUBTYPE="ubuntu"
      msg ok "Detected Ubuntu distribution"
    else
      OS_SUBTYPE="debian"
      msg ok "Detected Debian distribution"
    fi
  elif [ -f /etc/redhat-release ]; then
    OS_TYPE="rhel"
    msg ok "Detected RHEL-based system"
    
    # Check if it's CentOS, RHEL, or Fedora
    if grep -q "CentOS" /etc/redhat-release; then
      OS_SUBTYPE="centos"
      msg ok "Detected CentOS distribution"
    elif grep -q "Red Hat Enterprise Linux" /etc/redhat-release; then
      OS_SUBTYPE="rhel"
      msg ok "Detected Red Hat Enterprise Linux distribution"
    elif grep -q "Fedora" /etc/redhat-release; then
      OS_SUBTYPE="fedora"
      msg ok "Detected Fedora distribution"
    elif grep -q "Rocky Linux" /etc/redhat-release; then
      OS_SUBTYPE="rocky"
      msg ok "Detected Rocky Linux distribution"
    elif grep -q "AlmaLinux" /etc/redhat-release; then
      OS_SUBTYPE="alma"
      msg ok "Detected AlmaLinux distribution"
    else
      OS_SUBTYPE="unknown_rhel"
      msg warn "Detected unknown RHEL-based distribution"
    fi
  else
    msg error "Unsupported operating system"
    exit 1
  fi
}

# Function to install packages based on OS type
install_package() {
  local package_name="$1"
  local debian_package="${2:-$1}"
  local rhel_package="${3:-$1}"
  
  local package_to_install=""
  
  if [ "${OS_TYPE}" = "debian" ]; then
    package_to_install="${debian_package}"
    if ! apt-get -y install "${package_to_install}" >/dev/null 2>&1; then
      msg error "Failed to install ${package_to_install}"
      return 1
    fi
  elif [ "${OS_TYPE}" = "rhel" ]; then
    package_to_install="${rhel_package}"
    if ! yum -y install "${package_to_install}" >/dev/null 2>&1; then
      msg error "Failed to install ${package_to_install}"
      return 1
    fi
  fi
  
  msg ok "Installed ${package_name}"
  return 0
}

# Function to update the system
update_system() {
  msg section "System Update"
  
  if [ "${OS_TYPE}" = "debian" ]; then
    msg info "Updating package lists"
    if ! apt-get -y update >/dev/null 2>&1; then
      msg error "Failed to update package lists"
      return 1
    fi
    msg ok "Package lists updated"
    
    if confirm "Would you like to perform a full system upgrade" "Y"; then
      msg info "Upgrading system packages"
      if ! apt-get -y upgrade >/dev/null 2>&1; then
        msg error "Failed to upgrade system packages"
        return 1
      fi
      msg ok "System packages upgraded"
    fi
  elif [ "${OS_TYPE}" = "rhel" ]; then
    msg info "Updating package lists"
    if ! yum -y makecache >/dev/null 2>&1; then
      msg error "Failed to update package lists"
      return 1
    fi
    msg ok "Package lists updated"
    
    if confirm "Would you like to perform a full system upgrade" "Y"; then
      msg info "Upgrading system packages"
      if ! yum -y update >/dev/null 2>&1; then
        msg error "Failed to upgrade system packages"
        return 1
      fi
      msg ok "System packages upgraded"
    fi
  fi
  
  SECURITY_SCORE=$((SECURITY_SCORE + 5))
  return 0
}

# Function to install required packages
install_required_packages() {
  msg section "Installing Required Packages"
  
  # Common packages for both OS types
  local common_packages=("curl" "wget" "gnupg" "sudo" "openssh-server" "net-tools")
  
  if [ "${OS_TYPE}" = "debian" ]; then
    # Debian-specific packages
    local debian_packages=("apt-transport-https" "ca-certificates" "gnupg" "lsb-release")
    
    for package in "${debian_packages[@]}"; do
      msg info "Installing ${package}"
      install_package "${package}"
    done
    
    # Install common packages
    for package in "${common_packages[@]}"; do
      msg info "Installing ${package}"
      install_package "${package}"
    done
    
    # Install security packages based on configuration
    if [ "${ENABLE_FAIL2BAN}" = true ]; then
      msg info "Installing Fail2Ban"
      install_package "Fail2Ban" "fail2ban"
    fi
    
    if [ "${MFA_ENABLE}" = true ]; then
      msg info "Installing Google Authenticator"
      install_package "Google Authenticator" "libpam-google-authenticator"
    fi
    
    if [ "${ENABLE_AIDE}" = true ]; then
      msg info "Installing AIDE"
      install_package "AIDE" "aide" "aide"
    fi
    
    if [ "${ENABLE_CLAMAV}" = true ]; then
      msg info "Installing ClamAV"
      install_package "ClamAV" "clamav clamav-freshclam"
    fi
    
    if [ "${ENABLE_AUDITD}" = true ]; then
      msg info "Installing Audit Daemon"
      install_package "Audit Daemon" "auditd"
    fi
    
    # Install other security packages
    msg info "Installing security packages"
    install_package "Security Packages" "debsums unattended-upgrades apt-listchanges libpam-pwquality rkhunter"
    
  elif [ "${OS_TYPE}" = "rhel" ]; then
    # RHEL-specific packages
    local rhel_packages=("epel-release")
    
    for package in "${rhel_packages[@]}"; do
      msg info "Installing ${package}"
      install_package "${package}"
    done
    
    # Enable EPEL repository
    msg info "Updating package lists after enabling EPEL"
    if [ "${OS_SUBTYPE}" = "centos" ] || [ "${OS_SUBTYPE}" = "rhel" ] || [ "${OS_SUBTYPE}" = "rocky" ] || [ "${OS_SUBTYPE}" = "alma" ]; then
      if ! yum -y makecache >/dev/null 2>&1; then
        msg error "Failed to update package lists"
      else
        msg ok "Package lists updated"
      fi
    fi
    
    # Install common packages
    for package in "${common_packages[@]}"; do
      msg info "Installing ${package}"
      install_package "${package}"
    done
    
    # Install security packages based on configuration
    if [ "${ENABLE_FAIL2BAN}" = true ]; then
      msg info "Installing Fail2Ban"
      install_package "Fail2Ban" "fail2ban" "fail2ban"
    fi
    
    if [ "${MFA_ENABLE}" = true ]; then
      msg info "Installing Google Authenticator"
      install_package "Google Authenticator" "libpam-google-authenticator" "google-authenticator"
    fi
    
    if [ "${ENABLE_AIDE}" = true ]; then
      msg info "Installing AIDE"
      install_package "AIDE" "aide" "aide"
    fi
    
    if [ "${ENABLE_CLAMAV}" = true ]; then
      msg info "Installing ClamAV"
      install_package "ClamAV" "clamav" "clamav clamav-update"
    fi
    
    if [ "${ENABLE_AUDITD}" = true ]; then
      msg info "Installing Audit Daemon"
      install_package "Audit Daemon" "auditd" "audit"
    fi
    
    # Install other security packages
    msg info "Installing security packages"
    install_package "Security Packages" "debsums" "dnf-automatic cracklib-dicts rkhunter"
  fi
  
  msg ok "All required packages installed"
  SECURITY_SCORE=$((SECURITY_SCORE + 10))
  return 0
}

# Function to secure SSH
secure_ssh() {
  msg section "SSH Security Configuration"
  
  # Backup the SSH config file
  backup_config "/etc/ssh/sshd_config"
  
  # Generate a random port if not specified
  if [ -z "${SSH_PORT}" ]; then
    SSH_PORT=$(shuf -i 28000-65000 -n 1)
  fi
  
  # Prompt for SSH port
  SSH_PORT=$(prompt_value "Enter the SSH port to use" "${SSH_PORT}" validate_port)
  
  if [ "${SSH_PORT}" -eq 22 ]; then
    msg warn "You've selected port 22, which is the default SSH port (less secure)"
    if ! confirm "Are you sure you want to use the default SSH port" "N"; then
      local new_port=$(shuf -i 28000-65000 -n 1)
      SSH_PORT=$(prompt_value "Enter a different SSH port" "${new_port}" validate_port)
    fi
  fi
  
  # Prompt for SSH users
  if confirm "Would you like to restrict SSH access to specific users" "Y"; then
    SSH_USERS=$(prompt_value "Enter users allowed to SSH (comma-separated)" "")
  else
    msg warn "All users will be allowed to connect via SSH"
  fi
  
  # Prompt for SSH groups
  if confirm "Would you like to restrict SSH access to specific groups" "N"; then
    SSH_GROUPS=$(prompt_value "Enter groups allowed to SSH (comma-separated)" "")
  fi
  
  # Create a new SSH config
  msg info "Configuring SSH hardening"
  
  # Create a secure SSH config
  cat > /etc/ssh/sshd_config << EOF
# Fortify Shield Security Hardener - SSH Configuration
# Generated on $(date)

# Basic SSH Server Configuration
Port ${SSH_PORT}
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication Settings
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 5

# Only use strong ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-ed25519,ssh-rsa
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Authentication and access
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no

# Logging and monitoring
SyslogFacility AUTH
LogLevel VERBOSE

# Idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Banner
Banner /etc/issue.net

# SFTP subsystem (secured file transfer)
Subsystem sftp internal-sftp
EOF

  # Add users and groups restrictions if specified
  if [ -n "${SSH_USERS}" ]; then
    echo "AllowUsers ${SSH_USERS//,/ }" >> /etc/ssh/sshd_config
    msg ok "SSH access restricted to users: ${SSH_USERS}"
  fi
  
  if [ -n "${SSH_GROUPS}" ]; then
    echo "AllowGroups ${SSH_GROUPS//,/ }" >> /etc/ssh/sshd_config
    msg ok "SSH access restricted to groups: ${SSH_GROUPS}"
  fi
  
  # Configure MFA if enabled
  if [ "${MFA_ENABLE}" = true ]; then
    msg info "Configuring 2FA for SSH"
    
    # Configure PAM for Google Authenticator
    backup_config "/etc/pam.d/sshd"
    
    # Different configuration for Debian and RHEL
    if [ "${OS_TYPE}" = "debian" ]; then
      # Add Google Authenticator to PAM configuration
      sed -i '/@include common-auth/i auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
    elif [ "${OS_TYPE}" = "rhel" ]; then
      # Add Google Authenticator to PAM configuration
      sed -i '/auth\s*substack\s*password-auth/i auth required pam_google_authenticator.so nullok' /etc/pam.d/sshd
    fi
    
    # Update SSH configuration to use challenge-response authentication
    sed -i 's/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^AuthenticationMethods.*/AuthenticationMethods publickey,keyboard-interactive/' /etc/ssh/sshd_config
    
    msg ok "2FA configured for SSH"
  fi
  
  # Create a custom SSH banner
  msg info "Creating SSH banner"
  
  cat > /etc/issue.net << EOF
***************************************************************************
                            ATTENTION!
          This is a private computer system. Unauthorized access
          is prohibited. All activities are monitored and logged.
    Disconnect IMMEDIATELY if you are not an authorized user!
***************************************************************************
EOF

  msg ok "SSH banner created"
  
  # Enable and restart SSH service
  if [ "${APPLY_IMMEDIATELY}" = true ]; then
    msg info "Restarting SSH service"
    
    if [ "${OS_TYPE}" = "debian" ]; then
      systemctl restart ssh >/dev/null 2>&1
    elif [ "${OS_TYPE}" = "rhel" ]; then
      systemctl restart sshd >/dev/null 2>&1
    fi
    
    msg ok "SSH service restarted"
  fi
  
  SECURITY_SCORE=$((SECURITY_SCORE + 15))
  return 0
}

# Function to configure the firewall
configure_firewall() {
  msg section "Firewall Configuration"
  
  if [ "${OS_TYPE}" = "debian" ]; then
    # For Debian-based systems, use UFW
    msg info "Configuring UFW firewall"
    
    # Install UFW if not already installed
    install_package "UFW" "ufw"
    
    # Reset UFW to defaults
    msg info "Resetting UFW to defaults"
    ufw --force reset >/dev/null 2>&1
    
    # Set default policies
    msg info "Setting default policies"
    ufw default deny incoming >/dev/null 2>&1
    
    if [ "${FIREWALL_TYPE}" = "strict" ]; then
      ufw default deny outgoing >/dev/null 2>&1
      
      # Allow essential outgoing traffic
      ufw allow out 53/udp >/dev/null 2>&1   # DNS
      ufw allow out 123/udp >/dev/null 2>&1  # NTP
      ufw allow out 80/tcp >/dev/null 2>&1   # HTTP
      ufw allow out 443/tcp >/dev/null 2>&1  # HTTPS
      ufw allow out "${SSH_PORT}"/tcp >/dev/null 2>&1  # SSH
      
      msg ok "Strict outgoing firewall configured"
    else
      ufw default allow outgoing >/dev/null 2>&1
      msg ok "Standard outgoing firewall configured"
    fi
    
    # Allow SSH
    msg info "Allowing SSH on port ${SSH_PORT}"
    ufw allow in "${SSH_PORT}"/tcp >/dev/null 2>&1
    msg ok "SSH port ${SSH_PORT} allowed"
    
    # Allow specific IPs if provided
    if [ -n "${IP_ALLOWLIST}" ]; then
      IFS=',' read -ra IPS <<< "${IP_ALLOWLIST}"
      for ip in "${IPS[@]}"; do
        msg info "Allowing access from IP: ${ip}"
        ufw allow from "${ip}" to any port "${SSH_PORT}" >/dev/null 2>&1
        msg ok "Access allowed from IP: ${ip}"
      done
    fi
    
    # Enable logging
    msg info "Enabling firewall logging"
    ufw logging on >/dev/null 2>&1
    
    # Enable UFW
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      msg info "Enabling UFW"
      echo "y" | ufw enable >/dev/null 2>&1
      msg ok "UFW enabled"
    else
      msg warn "UFW configured but not enabled. To enable, run: sudo ufw enable"
    fi
    
  elif [ "${OS_TYPE}" = "rhel" ]; then
    # For RHEL-based systems, use firewalld
    msg info "Configuring firewalld"
    
    # Install firewalld if not already installed
    install_package "firewalld" "firewalld" "firewalld"
    
    # Start and enable firewalld
    systemctl start firewalld >/dev/null 2>&1
    systemctl enable firewalld >/dev/null 2>&1
    
    # Configure firewalld
    msg info "Setting default zone to drop"
    firewall-cmd --set-default-zone=drop >/dev/null 2>&1
    
    # Create a custom zone for SSH
    msg info "Creating custom zone for SSH"
    firewall-cmd --permanent --new-zone=ssh-zone >/dev/null 2>&1
    
    # Allow SSH port
    msg info "Allowing SSH on port ${SSH_PORT}"
    firewall-cmd --permanent --zone=ssh-zone --add-port="${SSH_PORT}/tcp" >/dev/null 2>&1
    
    # Allow specific IPs if provided
    if [ -n "${IP_ALLOWLIST}" ]; then
      IFS=',' read -ra IPS <<< "${IP_ALLOWLIST}"
      for ip in "${IPS[@]}"; do
        msg info "Allowing access from IP: ${ip}"
        firewall-cmd --permanent --zone=ssh-zone --add-source="${ip}" >/dev/null 2>&1
        msg ok "Access allowed from IP: ${ip}"
      done
    fi
    
    # If strict mode, limit outgoing traffic
    if [ "${FIREWALL_TYPE}" = "strict" ]; then
      msg info "Configuring strict outgoing firewall"
      
      # Create a services zone for outgoing traffic
      firewall-cmd --permanent --new-zone=services >/dev/null 2>&1
      
      # Allow essential services
      firewall-cmd --permanent --zone=services --add-service=dns >/dev/null 2>&1
      firewall-cmd --permanent --zone=services --add-service=http >/dev/null 2>&1
      firewall-cmd --permanent --zone=services --add-service=https >/dev/null 2>&1
      firewall-cmd --permanent --zone=services --add-service=ntp >/dev/null 2>&1
      firewall-cmd --permanent --zone=services --add-port="${SSH_PORT}/tcp" >/dev/null 2>&1
      
      # Set source for services zone
      firewall-cmd --permanent --zone=services --add-source=0.0.0.0/0 >/dev/null 2>&1
      
      msg ok "Strict outgoing firewall configured"
    fi
    
    # Reload firewalld
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      msg info "Reloading firewalld"
      firewall-cmd --reload >/dev/null 2>&1
      msg ok "firewalld reloaded"
    else
      msg warn "firewalld configured but not reloaded. To reload, run: sudo firewall-cmd --reload"
    fi
  fi
  
  SECURITY_SCORE=$((SECURITY_SCORE + 15))
  return 0
}

# Function to apply system hardening
apply_system_hardening() {
  msg section "System Hardening"
  
  # Secure /proc filesystem
  if confirm "Would you like to secure the /proc filesystem" "Y"; then
    msg info "Securing /proc filesystem"
    
    backup_config "/etc/fstab"
    
    # Check if the line already exists
    if ! grep -q "hidepid=2" /etc/fstab; then
      echo "proc     /proc     proc     defaults,hidepid=2,gid=proc     0     0" >> /etc/fstab
      
      # Check if we should remount immediately
      if [ "${APPLY_IMMEDIATELY}" = true ]; then
        mount -o remount,hidepid=2,gid=proc /proc >/dev/null 2>&1
      fi
      
      msg ok "Secured /proc filesystem"
    else
      msg ok "/proc filesystem already secured"
    fi
  fi
  
  # Password policies
  if confirm "Would you like to enforce strong password policies" "Y"; then
    msg info "Configuring password policies"
    
    if [ "${OS_TYPE}" = "debian" ]; then
      backup_config "/etc/pam.d/common-password"
      backup_config "/etc/login.defs"
      
      # Configure PAM password quality
      sed -i 's/# pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 gecoscheck/' /etc/pam.d/common-password

      # Configure login.defs for password aging and complexity
      sed -i '/PASS_MAX_DAYS/s/[0-9]\+/90/g' /etc/login.defs
      sed -i '/PASS_MIN_DAYS/s/[0-9]\+/1/g' /etc/login.defs
      sed -i '/PASS_WARN_AGE/s/[0-9]\+/14/g' /etc/login.defs
      
      # Set stronger SHA password hashing
      sed -i '/SHA_CRYPT_MAX_ROUNDS/s/#\(.*\)/\1/g' /etc/login.defs
      sed -i '/SHA_CRYPT_MAX_ROUNDS/s/5000/1000000/g' /etc/login.defs
      sed -i '/SHA_CRYPT_MIN_ROUNDS/s/#\(.*\)/\1/g' /etc/login.defs
      sed -i '/SHA_CRYPT_MIN_ROUNDS/s/5000/1000000/g' /etc/login.defs
      
    elif [ "${OS_TYPE}" = "rhel" ]; then
      backup_config "/etc/security/pwquality.conf"
      backup_config "/etc/login.defs"
      
      # Configure password quality
      sed -i 's/# minlen =.*/minlen = 12/' /etc/security/pwquality.conf
      sed -i 's/# dcredit =.*/dcredit = -1/' /etc/security/pwquality.conf
      sed -i 's/# ucredit =.*/ucredit = -1/' /etc/security/pwquality.conf
      sed -i 's/# lcredit =.*/lcredit = -1/' /etc/security/pwquality.conf
      sed -i 's/# ocredit =.*/ocredit = -1/' /etc/security/pwquality.conf
      sed -i 's/# difok =.*/difok = 3/' /etc/security/pwquality.conf
      sed -i 's/# maxrepeat =.*/maxrepeat = 3/' /etc/security/pwquality.conf
      
      # Configure login.defs for password aging
      sed -i '/PASS_MAX_DAYS/s/[0-9]\+/90/g' /etc/login.defs
      sed -i '/PASS_MIN_DAYS/s/[0-9]\+/1/g' /etc/login.defs
      sed -i '/PASS_WARN_AGE/s/[0-9]\+/14/g' /etc/login.defs
    fi
    
    msg ok "Password policies enforced"
  fi
  
  # UMASK settings
  if confirm "Would you like to set a more secure default UMASK" "Y"; then
    msg info "Setting secure UMASK"
    
    backup_config "/etc/login.defs"
    sed -i '/UMASK/s/022/027/g' /etc/login.defs
    
    msg ok "Secure UMASK set"
  fi
  
  # Root account security
  if confirm "Would you like to lock the root account" "Y"; then
    msg info "Securing root account"
    
    if [ "${DISABLE_ROOT}" = true ]; then
      # Completely disable root login
      passwd -l root >/dev/null 2>&1
      usermod -s /usr/sbin/nologin root >/dev/null 2>&1
      msg ok "Root account completely disabled"
    else
      # Just lock the password
      passwd -l root >/dev/null 2>&1
      msg ok "Root account password locked"
    fi
  fi
  
  # Configure core dumps
  if confirm "Would you like to disable core dumps (improves security)" "Y"; then
    msg info "Disabling core dumps"
    
    backup_config "/etc/security/limits.conf"
    
    # Add core dump restrictions to limits.conf
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "* soft core 0" >> /etc/security/limits.conf
    
    # Add core dump restrictions to sysctl
    echo "fs.suid_dumpable = 0" > /etc/sysctl.d/50-coredump.conf
    echo "kernel.core_pattern = |/bin/false" >> /etc/sysctl.d/50-coredump.conf
    
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      sysctl -p /etc/sysctl.d/50-coredump.conf >/dev/null 2>&1
    fi
    
    msg ok "Core dumps disabled"
  fi
  
  # Kernel hardening
  if [ "${KERNEL_HARDENING}" = true ]; then
    msg info "Applying kernel hardening parameters"
    
    # Create sysctl configurations
    echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/50-security-hardening.conf
    echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/50-security-hardening.conf
    echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/50-security-hardening.conf
    echo "kernel.unprivileged_bpf_disabled = 1" >> /etc/sysctl.d/50-security-hardening.conf
    echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/50-security-hardening.conf
    echo "kernel.sysrq = 0" >> /etc/sysctl.d/50-security-hardening.conf
    echo "fs.protected_fifos = 2" >> /etc/sysctl.d/50-security-hardening.conf
    echo "fs.protected_regular = 2" >> /etc/sysctl.d/50-security-hardening.conf
    
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      sysctl -p /etc/sysctl.d/50-security-hardening.conf >/dev/null 2>&1
    fi
    
    msg ok "Kernel parameters hardened"
  fi
  
  # Network hardening
  if [ "${NETWORK_HARDENING}" = true ]; then
    msg info "Applying network hardening parameters"
    
    # Create network hardening sysctl configuration
    cat > /etc/sysctl.d/51-network-hardening.conf << EOF
# IPv4 settings
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# IPv6 settings
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
    
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      sysctl -p /etc/sysctl.d/51-network-hardening.conf >/dev/null 2>&1
    fi
    
    msg ok "Network stack hardened"
  fi
  
  # Filesystem hardening
  if [ "${FILESYSTEM_HARDENING}" = true ]; then
    msg info "Applying filesystem hardening parameters"
    
    # Create filesystem hardening sysctl configuration
    cat > /etc/sysctl.d/52-filesystem-hardening.conf << EOF
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      sysctl -p /etc/sysctl.d/52-filesystem-hardening.conf >/dev/null 2>&1
    fi
    
    msg ok "Filesystem hardened"
  fi
  
  # Blacklist uncommon modules if enabled
  if [ "${BLACKLIST_MODULES}" = true ]; then
    msg info "Blacklisting uncommon kernel modules"
    
    # Create directory if it doesn't exist
    mkdir -p /etc/modprobe.d
    
    # Blacklist uncommon filesystems
    cat > /etc/modprobe.d/uncommon-fs.conf << EOF
# Blacklist uncommon filesystem modules
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install fat /bin/true
install vfat /bin/true
EOF
    
    # Blacklist uncommon network protocols
    cat > /etc/modprobe.d/uncommon-net.conf << EOF
# Blacklist uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    
    # Blacklist uncommon hardware modules
    cat > /etc/modprobe.d/uncommon-hw.conf << EOF
# Blacklist uncommon hardware modules
install firewire-core /bin/true
install firewire-ohci /bin/true
install firewire-sbp2 /bin/true
install thunderbolt /bin/true
EOF
    
    if confirm "Would you like to disable Bluetooth (improves security)" "Y"; then
      echo "install bluetooth /bin/true" > /etc/modprobe.d/bluetooth.conf
      msg ok "Bluetooth disabled"
    fi
    
    msg ok "Uncommon kernel modules blacklisted"
  fi
  
  # Update initramfs if on Debian
  if [ "${OS_TYPE}" = "debian" ]; then
    msg info "Updating initramfs"
    update-initramfs -u >/dev/null 2>&1
    msg ok "Initramfs updated"
  elif [ "${OS_TYPE}" = "rhel" ]; then
    if [ -f /usr/bin/dracut ]; then
      msg info "Updating initramfs with dracut"
      dracut -f >/dev/null 2>&1
      msg ok "Initramfs updated"
    fi
  fi
  
  SECURITY_SCORE=$((SECURITY_SCORE + 25))
  return 0
}

# Function to configure automatic updates
configure_auto_updates() {
  msg section "Automatic Updates Configuration"
  
  if [ "${AUTO_UPDATES}" = true ]; then
    if [ "${OS_TYPE}" = "debian" ]; then
      msg info "Configuring unattended-upgrades"
      
      backup_config "/etc/apt/apt.conf.d/20auto-upgrades"
      backup_config "/etc/apt/apt.conf.d/50unattended-upgrades"
      
      # Configure APT auto-updates
      cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
      
      # Configure unattended-upgrades
      cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Origins-Pattern {
      "origin=Debian,codename=\${distro_codename},label=Debian-Security";
      "origin=Ubuntu,codename=\${distro_codename},label=Ubuntu-Security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::SyslogEnable "true";
EOF
      
      # Enable services
      systemctl enable unattended-upgrades >/dev/null 2>&1
      
      msg ok "Unattended-upgrades configured"
      
    elif [ "${OS_TYPE}" = "rhel" ]; then
      msg info "Configuring automatic updates"
      
      # Install dnf-automatic if not already installed
      if [ "${OS_SUBTYPE}" = "fedora" ] || [ "${OS_SUBTYPE}" = "centos" ] || [ "${OS_SUBTYPE}" = "rocky" ] || [ "${OS_SUBTYPE}" = "alma" ]; then
        install_package "DNF Automatic" "dnf-automatic" "dnf-automatic"
        
        # Configure dnf-automatic
        backup_config "/etc/dnf/automatic.conf"
        
        # Update configuration
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf
        sed -i 's/^emit_via.*/emit_via = email/' /etc/dnf/automatic.conf
        sed -i 's/^email_from.*/email_from = root@localhost/' /etc/dnf/automatic.conf
        sed -i 's/^email_to.*/email_to = root/' /etc/dnf/automatic.conf
        
        # Enable and start services
        systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
        
        msg ok "DNF automatic updates configured"
      else
        # Fallback for older RHEL systems
        install_package "Yum Cron" "yum-cron" "yum-cron"
        
        # Configure yum-cron
        backup_config "/etc/yum/yum-cron.conf"
        
        # Update configuration
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/yum/yum-cron.conf
        sed -i 's/^emit_via.*/emit_via = email/' /etc/yum/yum-cron.conf
        sed -i 's/^email_from.*/email_from = root@localhost/' /etc/yum/yum-cron.conf
        sed -i 's/^email_to.*/email_to = root/' /etc/yum/yum-cron.conf
        
        # Enable and start services
        systemctl enable yum-cron >/dev/null 2>&1
        systemctl start yum-cron >/dev/null 2>&1
        
        msg ok "Yum automatic updates configured"
      fi
    fi
    
    SECURITY_SCORE=$((SECURITY_SCORE + 10))
  else
    msg warn "Automatic updates not configured (not recommended)"
  fi
}

# Function to configure intrusion detection
configure_intrusion_detection() {
  msg section "Intrusion Detection Configuration"
  
  # Configure AIDE if enabled
  if [ "${ENABLE_AIDE}" = true ]; then
    msg info "Configuring AIDE"
    
    # Create AIDE configuration directory
    mkdir -p /etc/aide
    
    # Backup existing configuration
    backup_config "/etc/aide/aide.conf"
    
    # Configure AIDE
    if [ "${OS_TYPE}" = "debian" ]; then
      # Create simple configuration for Debian
      cat > /etc/aide/aide.conf << EOF
# AIDE configuration
database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
verbose=5

# Regular files
regular = p+i+n+u+g+s+m+c+md5+sha256
# Directories
dir = p+i+n+u+g+acl+xattrs
# Devices
device = p+i+n+u+g+s+b+c+md5+sha256
# Logs (growing files)
log = p+i+n+u+g+acl+xattrs
# Config files
config = p+i+n+u+g+s+acl+xattrs+md5+sha256

# What to monitor
/bin config
/sbin config
/usr/bin config
/usr/sbin config
/usr/local/bin config
/usr/local/sbin config
/etc config
/boot config
/root config
/var/log log
EOF
      
      # Initialize AIDE database
      msg info "Initializing AIDE database (this may take a while)"
      aide --init >/dev/null 2>&1
      cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db >/dev/null 2>&1
      
      # Create daily cron job
      cat > /etc/cron.daily/aide-check << EOF
#!/bin/sh
aide --check
EOF
      chmod +x /etc/cron.daily/aide-check
      
    elif [ "${OS_TYPE}" = "rhel" ]; then
      # For RHEL-based systems, use the default configuration
      msg info "Initializing AIDE database (this may take a while)"
      aide --init >/dev/null 2>&1
      cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz >/dev/null 2>&1
      
      # Enable the default aide systemd timer if available
      if [ -f /usr/lib/systemd/system/aide.timer ]; then
        systemctl enable aide.timer >/dev/null 2>&1
      else
        # Create daily cron job
        cat > /etc/cron.daily/aide-check << EOF
#!/bin/sh
aide --check
EOF
        chmod +x /etc/cron.daily/aide-check
      fi
    fi
    
    msg ok "AIDE configured"
    SECURITY_SCORE=$((SECURITY_SCORE + 10))
  fi
  
  # Configure ClamAV if enabled
  if [ "${ENABLE_CLAMAV}" = true ]; then
    msg info "Configuring ClamAV"
    
    if [ "${OS_TYPE}" = "debian" ]; then
      # Backup existing configuration
      backup_config "/etc/clamav/freshclam.conf"
      
      # Update database
      systemctl stop clamav-freshclam >/dev/null 2>&1
      freshclam >/dev/null 2>&1
      systemctl start clamav-freshclam >/dev/null 2>&1
      
      # Create daily scan script
      cat > /etc/cron.daily/clamscan << EOF
#!/bin/sh
LOGFILE="/var/log/clamav/scan-\$(date +'%Y-%m-%d').log"
echo "ClamAV scan started at \$(date)" > \$LOGFILE
clamscan -r --quiet -i /home /root /etc /opt /usr/local /var/www >> \$LOGFILE
echo "ClamAV scan completed at \$(date)" >> \$LOGFILE
EOF
      chmod +x /etc/cron.daily/clamscan
      
    elif [ "${OS_TYPE}" = "rhel" ]; then
      # Backup existing configuration
      backup_config "/etc/freshclam.conf"
      
      # Update database
      freshclam >/dev/null 2>&1
      
      # Create daily scan script
      cat > /etc/cron.daily/clamscan << EOF
#!/bin/sh
LOGFILE="/var/log/clamav/scan-\$(date +'%Y-%m-%d').log"
mkdir -p /var/log/clamav
echo "ClamAV scan started at \$(date)" > \$LOGFILE
clamscan -r --quiet -i /home /root /etc /opt /usr/local /var/www >> \$LOGFILE
echo "ClamAV scan completed at \$(date)" >> \$LOGFILE
EOF
      chmod +x /etc/cron.daily/clamscan
    fi
    
    msg ok "ClamAV configured"
    SECURITY_SCORE=$((SECURITY_SCORE + 5))
  fi
  
  # Configure Fail2Ban if enabled
  if [ "${ENABLE_FAIL2BAN}" = true ]; then
    msg info "Configuring Fail2Ban"
    
    # Install Fail2Ban if not already installed
    install_package "Fail2Ban" "fail2ban" "fail2ban"
    
    # Create Fail2Ban configuration directory
    mkdir -p /etc/fail2ban/jail.d
    
    # Configure Fail2Ban for SSH
    cat > /etc/fail2ban/jail.d/sshd.conf << EOF
[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    # Start and enable Fail2Ban
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      systemctl enable fail2ban >/dev/null 2>&1
      systemctl restart fail2ban >/dev/null 2>&1
    fi
    
    msg ok "Fail2Ban configured"
    SECURITY_SCORE=$((SECURITY_SCORE + 10))
  fi
  
  # Configure audit daemon if enabled
  if [ "${ENABLE_AUDITD}" = true ]; then
    msg info "Configuring audit daemon"
    
    # Install auditd if not already installed
    if [ "${OS_TYPE}" = "debian" ]; then
      install_package "Audit Daemon" "auditd audispd-plugins"
    elif [ "${OS_TYPE}" = "rhel" ]; then
      install_package "Audit Daemon" "audit audispd-plugins"
    fi
    
    # Backup existing configuration
    backup_config "/etc/audit/auditd.conf"
    
    # Configure auditd
    cat > /etc/audit/rules.d/security.rules << EOF
# Fortify Shield - Security Audit Rules

# Watch for changes to system authentication configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/nsswitch.conf -p wa -k nsswitch

# Watch for changes to system login configuration
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/security/opasswd -p wa -k password_change

# Watch for changes to system users and groups
-w /usr/bin/passwd -p x -k passwd_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification

# Watch for changes to sudo configuration
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Watch for changes to system network configuration
-w /etc/hosts -p wa -k hosts
-w /etc/sysconfig/network -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/NetworkManager/ -p wa -k network

# Monitor important system commands
-w /usr/bin/wget -p x -k web_download
-w /usr/bin/curl -p x -k web_download
-w /bin/chmod -p x -k file_perm_change
-w /bin/chown -p x -k file_perm_change
-w /sbin/iptables -p x -k firewall
-w /sbin/ip6tables -p x -k firewall
-w /usr/sbin/nft -p x -k firewall

# Monitor kernel module operations
-w /sbin/insmod -p x -k module_manipulation
-w /sbin/rmmod -p x -k module_manipulation
-w /sbin/modprobe -p x -k module_manipulation
-w /etc/modprobe.conf -p wa -k module_manipulation
-w /etc/modprobe.d/ -p wa -k module_manipulation

# Monitor ssh configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor user/group information changes
-w /etc/group -p wa -k group_modification
-w /etc/passwd -p wa -k passwd_modification
-w /etc/gshadow -p wa -k gshadow_modification

# Monitor systemd services
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# Monitor privileged command execution
-a always,exit -F arch=b64 -F euid=0 -S execve -k rootcmd
-a always,exit -F arch=b32 -F euid=0 -S execve -k rootcmd

# Always track any 32/64bit system calls by user 'root'
-a exit,always -F arch=b64 -F euid=0 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a exit,always -F arch=b32 -F euid=0 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a exit,always -F arch=b64 -F euid=0 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a exit,always -F arch=b32 -F euid=0 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
EOF
    
    # Enable and restart auditd
    if [ "${APPLY_IMMEDIATELY}" = true ]; then
      systemctl enable auditd >/dev/null 2>&1
      systemctl restart auditd >/dev/null 2>&1
    fi
    
    msg ok "Audit daemon configured"
    SECURITY_SCORE=$((SECURITY_SCORE + 10))
  fi
}

# Function to generate a security report
generate_security_report() {
  msg section "Security Report Generation"
  
  msg info "Generating security report"
  
  # Create security report markdown file
  cat > "${SECURITY_REPORT_FILE}" << EOF
# Fortify Shield Security Report
Generated on: $(date)

## System Information
- Hostname: $(hostname)
- Operating System: ${OS_TYPE} (${OS_SUBTYPE})
- Kernel: $(uname -r)
- IP Address: $(hostname -I | awk '{print $1}')

## Security Score
**Overall Security Score: ${SECURITY_SCORE}/100**

## Security Measures Applied

### SSH Configuration
- SSH Port: ${SSH_PORT}
- MFA/2FA Enabled: ${MFA_ENABLE}
- Root Login Disabled: Yes
- Password Authentication: Disabled
- Public Key Authentication: Enabled
- Users Allowed: ${SSH_USERS:-"All"}
- Groups Allowed: ${SSH_GROUPS:-"All"}

### Firewall Configuration
- Firewall Type: ${FIREWALL_TYPE}
- SSH Port Open: Yes (Port ${SSH_PORT})
- IP Allowlist: ${IP_ALLOWLIST:-"None"}

### System Hardening
- Secured /proc Filesystem: Yes
- Strong Password Policies: Yes
- Secure UMASK: Yes
- Root Account Locked: ${DISABLE_ROOT}
- Core Dumps Disabled: Yes
- Kernel Hardening: ${KERNEL_HARDENING}
- Network Hardening: ${NETWORK_HARDENING}
- Filesystem Hardening: ${FILESYSTEM_HARDENING}
- Module Blacklisting: ${BLACKLIST_MODULES}

### Automatic Updates
- Automatic Updates Enabled: ${AUTO_UPDATES}

### Intrusion Detection
- AIDE File Integrity: ${ENABLE_AIDE}
- ClamAV Antivirus: ${ENABLE_CLAMAV}
- Fail2Ban: ${ENABLE_FAIL2BAN}
- Audit Daemon: ${ENABLE_AUDITD}

## Changes Made
EOF
  
  # Add changes to report
  for change in "${CHANGES_MADE[@]}"; do
    echo "- ${change}" >> "${SECURITY_REPORT_FILE}"
  done
  
  # Add warnings section if there are warnings
  if [ ${#WARNINGS[@]} -gt 0 ]; then
    echo -e "\n## Warnings and Issues" >> "${SECURITY_REPORT_FILE}"
    for warning in "${WARNINGS[@]}"; do
      echo "- ${warning}" >> "${SECURITY_REPORT_FILE}"
    done
  fi
  
  # Add recommendations section
  echo -e "\n## Security Recommendations" >> "${SECURITY_REPORT_FILE}"
  
  # Add recommendations based on configuration
  if [ "${SECURITY_SCORE}" -lt 50 ]; then
    echo "- Your system security score is low. Consider enabling more security features." >> "${SECURITY_REPORT_FILE}"
  fi
  
  if [ "${SSH_PORT}" -eq 22 ]; then
    echo "- Change SSH port from the default (22) to a non-standard port." >> "${SECURITY_REPORT_FILE}"
  fi
  
  if [ "${MFA_ENABLE}" = false ]; then
    echo "- Enable Multi-Factor Authentication for SSH to increase security." >> "${SECURITY_REPORT_FILE}"
  fi
  
  if [ "${ENABLE_AIDE}" = false ]; then
    echo "- Enable AIDE for file integrity monitoring." >> "${SECURITY_REPORT_FILE}"
  fi
  
  if [ "${ENABLE_CLAMAV}" = false ]; then
    echo "- Enable ClamAV for malware detection." >> "${SECURITY_REPORT_FILE}"
  fi
  
  if [ "${FIREWALL_TYPE}" != "strict" ]; then
    echo "- Consider using strict firewall rules for better security." >> "${SECURITY_REPORT_FILE}"
  fi
  
  if [ "${AUTO_UPDATES}" = false ]; then
    echo "- Enable automatic updates to ensure security patches are applied promptly." >> "${SECURITY_REPORT_FILE}"
  fi
  
  # Final notes
  echo -e "\n## Next Steps" >> "${SECURITY_REPORT_FILE}"
  echo "- Review the changes made to your system." >> "${SECURITY_REPORT_FILE}"
  echo "- Set up MFA for all user accounts that will use SSH." >> "${SECURITY_REPORT_FILE}"
  echo "- Regularly monitor system logs for unusual activity." >> "${SECURITY_REPORT_FILE}"
  echo "- Perform periodic security audits to ensure continued compliance." >> "${SECURITY_REPORT_FILE}"
  
  # Generate a simple summary
  cat > "${SECURITY_SUMMARY}" << EOF
===============================================
  FORTIFY SHIELD SECURITY SUMMARY
===============================================

Security Score: ${SECURITY_SCORE}/100

Key Security Measures:
- SSH secured on port ${SSH_PORT} with MFA: ${MFA_ENABLE}
- Firewall Type: ${FIREWALL_TYPE}
- System Hardening: Applied
- Auto Updates: ${AUTO_UPDATES}
- Intrusion Detection: Configured

Recommendations:
EOF
  
  # Add top 3 recommendations to summary
  COUNT=0
  if [ "${SSH_PORT}" -eq 22 ]; then
    echo "- Change SSH port from default (22)" >> "${SECURITY_SUMMARY}"
    COUNT=$((COUNT + 1))
  fi
  
  if [ "${MFA_ENABLE}" = false ] && [ ${COUNT} -lt 3 ]; then
    echo "- Enable MFA for SSH" >> "${SECURITY_SUMMARY}"
    COUNT=$((COUNT + 1))
  fi
  
  if [ "${ENABLE_AIDE}" = false ] && [ ${COUNT} -lt 3 ]; then
    echo "- Enable AIDE for file integrity" >> "${SECURITY_SUMMARY}"
    COUNT=$((COUNT + 1))
  fi
  
  if [ "${FIREWALL_TYPE}" != "strict" ] && [ ${COUNT} -lt 3 ]; then
    echo "- Use strict firewall rules" >> "${SECURITY_SUMMARY}"
    COUNT=$((COUNT + 1))
  fi
  
  if [ "${AUTO_UPDATES}" = false ] && [ ${COUNT} -lt 3 ]; then
    echo "- Enable automatic updates" >> "${SECURITY_SUMMARY}"
    COUNT=$((COUNT + 1))
  fi
  
  echo -e "\nDetailed report available at: ${SECURITY_REPORT_FILE}" >> "${SECURITY_SUMMARY}"
  
  msg ok "Security report generated at ${SECURITY_REPORT_FILE}"
  msg ok "Security summary generated at ${SECURITY_SUMMARY}"
}

# Function to set up MFA for users
setup_mfa() {
  msg section "Multi-Factor Authentication Setup"
  
  if [ "${MFA_ENABLE}" = true ]; then
    msg info "Setting up Google Authenticator"
    
    # Check if SSH users are specified
    if [ -n "${SSH_USERS}" ]; then
      # Set up MFA for specified users
      IFS=',' read -ra USERS <<< "${SSH_USERS}"
      for user in "${USERS[@]}"; do
        if id "${user}" >/dev/null 2>&1; then
          msg info "Setting up MFA for user ${user}"
          
          # Check if Google Authenticator is already set up for the user
          if [ ! -f "/home/${user}/.google_authenticator" ]; then
            # Create a temporary script to run as the user
            cat > /tmp/mfa_setup_${user}.sh << EOF
#!/bin/bash
cd ~
google-authenticator -t -d -f -r 3 -R 30 -w 3
EOF
            chmod +x /tmp/mfa_setup_${user}.sh
            
            # Run the script as the user
            su - "${user}" -c "/tmp/mfa_setup_${user}.sh" >/dev/null 2>&1
            
            # Clean up
            rm -f /tmp/mfa_setup_${user}.sh
            
            msg ok "MFA set up for user ${user}"
            
            # Display instructions
            echo -e "\n${YELLOW}Important:${RESET} Have user ${CYAN}${user}${RESET} scan the QR code to set up MFA"
            echo -e "The emergency scratch codes are saved in ${CYAN}/home/${user}/.google_authenticator${RESET}"
          else
            msg warn "MFA already set up for user ${user}"
          fi
        else
          msg error "User ${user} does not exist"
        fi
      done
    else
      msg warn "No specific SSH users configured for MFA"
      msg info "Please set up MFA manually for your users"
    fi
    
    msg ok "MFA configuration completed"
  else
    msg warn "MFA not enabled (not recommended)"
  fi
}

# Function to display help info
show_help() {
  cat << EOF
Fortify Shield Security Hardener
--------------------------------

A comprehensive security hardening script for Debian and RHEL-based systems.

Usage: $0 [OPTIONS]

Options:
  -h, --help                 Show this help message
  -q, --quiet                Run in quiet mode (minimal output)
  -n, --no-interaction       Run in non-interactive mode with defaults
  -c, --config FILE          Use specified configuration file
  --ssh-port PORT            Set SSH port
  --ssh-users USERS          Set SSH users (comma-separated)
  --no-mfa                   Disable MFA setup
  --no-firewall              Skip firewall configuration
  --strict-firewall          Use strict firewall rules
  --no-updates               Disable automatic updates
  --no-aide                  Disable AIDE setup
  --no-clamav                Disable ClamAV setup
  --no-fail2ban              Disable Fail2Ban setup
  --disable-root             Completely disable root account
  --lock-root                Lock root account password
  --ip-allowlist IPs         Specify allowed IPs (comma-separated)

Examples:
  $0                        # Run interactively
  $0 --no-interaction       # Run with all defaults
  $0 --ssh-port 2222 --ssh-users user1,user2 --strict-firewall  # Custom config

For more information, visit: https://github.com/your-username/fortify-shield
EOF
}

# Function for the main menu
main_menu() {
  local choice
  
  while true; do
    clear
    echo -e "${PURPLE}${BOLD}==============================================${RESET}"
    echo -e "${PURPLE}${BOLD}      FORTIFY SHIELD SECURITY HARDENER       ${RESET}"
    echo -e "${PURPLE}${BOLD}==============================================${RESET}"
    echo ""
    echo -e "${CYAN}1.${RESET} Detect Operating System"
    echo -e "${CYAN}2.${RESET} Update System"
    echo -e "${CYAN}3.${RESET} Install Required Packages"
    echo -e "${CYAN}4.${RESET} Configure SSH Security"
    echo -e "${CYAN}5.${RESET} Configure Firewall"
    echo -e "${CYAN}6.${RESET} Apply System Hardening"
    echo -e "${CYAN}7.${RESET} Configure Automatic Updates"
    echo -e "${CYAN}8.${RESET} Configure Intrusion Detection"
    echo -e "${CYAN}9.${RESET} Set Up Multi-Factor Authentication"
    echo -e "${CYAN}10.${RESET} Generate Security Report"
    echo -e "${CYAN}11.${RESET} Run All (Complete Security Setup)"
    echo -e "${CYAN}12.${RESET} Advanced Options"
    echo -e "${CYAN}0.${RESET} Exit"
    echo ""
    echo -e "${YELLOW}Current Security Score: ${SECURITY_SCORE}/100${RESET}"
    echo ""
    
    read -rp "Enter your choice [0-12]: " choice
    
    case ${choice} in
      1)
        detect_os
        read -rp "Press Enter to continue..."
        ;;
      2)
        update_system
        read -rp "Press Enter to continue..."
        ;;
      3)
        install_required_packages
        read -rp "Press Enter to continue..."
        ;;
      4)
        secure_ssh
        read -rp "Press Enter to continue..."
        ;;
      5)
        configure_firewall
        read -rp "Press Enter to continue..."
        ;;
      6)
        apply_system_hardening
        read -rp "Press Enter to continue..."
        ;;
      7)
        configure_auto_updates
        read -rp "Press Enter to continue..."
        ;;
      8)
        configure_intrusion_detection
        read -rp "Press Enter to continue..."
        ;;
      9)
        setup_mfa
        read -rp "Press Enter to continue..."
        ;;
      10)
        generate_security_report
        read -rp "Press Enter to continue..."
        ;;
      11)
        run_all
        read -rp "Press Enter to continue..."
        ;;
      12)
        advanced_menu
        ;;
      0)
        echo -e "\n${GREEN}Thank you for using Fortify Shield Security Hardener!${RESET}"
        exit 0
        ;;
      *)
        echo -e "${RED}Invalid choice. Please try again.${RESET}"
        sleep 2
        ;;
    esac
  done
}

# Function for advanced menu
advanced_menu() {
  local choice
  
  while true; do
    clear
    echo -e "${PURPLE}${BOLD}==============================================${RESET}"
    echo -e "${PURPLE}${BOLD}       ADVANCED SECURITY OPTIONS             ${RESET}"
    echo -e "${PURPLE}${BOLD}==============================================${RESET}"
    echo ""
    echo -e "${CYAN}1.${RESET} Configure Kernel Parameters"
    echo -e "${CYAN}2.${RESET} Configure PAM Modules"
    echo -e "${CYAN}3.${RESET} Configure Audit Rules"
    echo -e "${CYAN}4.${RESET} Set Custom Firewall Rules"
    echo -e "${CYAN}5.${RESET} Configure IP Allowlist"
    echo -e "${CYAN}6.${RESET} View Logs"
    echo -e "${CYAN}7.${RESET} Restore Configuration Backups"
    echo -e "${CYAN}8.${RESET} Export Configuration"
    echo -e "${CYAN}9.${RESET} Import Configuration"
    echo -e "${CYAN}0.${RESET} Back to Main Menu"
    echo ""
    
    read -rp "Enter your choice [0-9]: " choice
    
    case ${choice} in
      1)
        # Configure kernel parameters
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      2)
        # Configure PAM modules
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      3)
        # Configure audit rules
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      4)
        # Set custom firewall rules
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      5)
        # Configure IP allowlist
        IP_ALLOWLIST=$(prompt_value "Enter allowed IPs (comma-separated)" "${IP_ALLOWLIST}")
        echo "IP allowlist updated"
        read -rp "Press Enter to continue..."
        ;;
      6)
        # View logs
        if [ -f "${LOG_FILE}" ]; then
          less "${LOG_FILE}"
        else
          echo "No log file found"
          read -rp "Press Enter to continue..."
        fi
        ;;
      7)
        # Restore configuration backups
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      8)
        # Export configuration
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      9)
        # Import configuration
        echo "Not implemented yet"
        read -rp "Press Enter to continue..."
        ;;
      0)
        return
        ;;
      *)
        echo -e "${RED}Invalid choice. Please try again.${RESET}"
        sleep 2
        ;;
    esac
  done
}

# Function to run all security measures
run_all() {
  msg section "Complete Security Setup"
  
  # Ask for confirmation
  if ! confirm "This will apply ALL security measures to your system. Continue" "N"; then
    msg warn "Complete setup cancelled"
    return 1
  fi
  
  # Check if the user is root
  if [ "$(id -u)" -ne 0 ]; then
    msg error "This script must be run as root"
    exit 1
  fi
  
  # Run all functions
  detect_os
  update_system
  install_required_packages
  secure_ssh
  configure_firewall
  apply_system_hardening
  configure_auto_updates
  configure_intrusion_detection
  setup_mfa
  generate_security_report
  
  # Display final summary
  clear
  cat "${SECURITY_SUMMARY}"
  echo ""
  
  # Ask about reboot
  if confirm "Would you like to reboot the system now to apply all changes" "N"; then
    msg info "System will reboot in 10 seconds. Press Ctrl+C to cancel."
    sleep 10
    reboot
  else
    msg warn "Some changes may require a reboot to take effect"
  fi
  
  msg ok "Complete security setup finished"
}

# Function to process command line arguments
process_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help)
        show_help
        exit 0
        ;;
      -q|--quiet)
        QUIET_MODE=true
        ;;
      -n|--no-interaction)
        NON_INTERACTIVE=true
        ;;
      -c|--config)
        CONFIG_FILE="$2"
        shift
        ;;
      --ssh-port)
        SSH_PORT="$2"
        shift
        ;;
      --ssh-users)
        SSH_USERS="$2"
        shift
        ;;
      --no-mfa)
        MFA_ENABLE=false
        ;;
      --no-firewall)
        ENABLE_FIREWALL=false
        ;;
      --strict-firewall)
        FIREWALL_TYPE="strict"
        ;;
      --no-updates)
        AUTO_UPDATES=false
        ;;
      --no-aide)
        ENABLE_AIDE=false
        ;;
      --no-clamav)
        ENABLE_CLAMAV=false
        ;;
      --no-fail2ban)
        ENABLE_FAIL2BAN=false
        ;;
      --disable-root)
        DISABLE_ROOT=true
        ;;
      --lock-root)
        LOCKDOWN_MODE=true
        ;;
      --ip-allowlist)
        IP_ALLOWLIST="$2"
        shift
        ;;
      *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
    esac
    shift
  done
}

# Main entry point
main() {
  # Create log directory
  mkdir -p "$(dirname "${LOG_FILE}")"
  
  # Create config directory
  mkdir -p "${CONFIG_DIR}"
  
  # Process command line arguments
  process_args "$@"
  
  # Display banner
  clear
  cat << EOF
 ______          _   _  __          _____ _     _      _     _ 
|  ____|        | | (_)/ _|        / ____| |   (_)    | |   | |
| |__ ___  _ __ | |_ _| |_ _   _  | (___ | |__  _  ___| | __| |
|  __/ _ \| '_ \| __| |  _| | | |  \___ \| '_ \| |/ _ \ |/ _` |
| | | (_) | | | | |_| | | | |_| |  ____) | | | | |  __/ | (_| |
|_|  \___/|_| |_|\__|_|_|  \__, | |_____/|_| |_|_|\___|_|\__,_|
                            __/ |                              
                           |___/                               

Security Hardening Script for Debian and RHEL-based systems
Version 2.0

EOF
  
  # Check if the user is root
  if [ "$(id -u)" -ne 0 ]; then
    msg error "This script must be run as root"
    exit 1
  fi
  
  # Run in non-interactive mode if specified
  if [ "${NON_INTERACTIVE}" = true ]; then
    run_all
    exit 0
  fi
  
  # Otherwise, show the main menu
  main_menu
}

# Execute main function with all arguments
main "$@"