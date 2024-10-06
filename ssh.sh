#!/bin/bash

sshd_config_path="/etc/ssh/sshd_config"

if ! [[ -f "$sshd_config_path" ]]; then
    echo "***********ERROR***********"
    read -p "File $sshd_config_path not found. Ctrl+C, fix path and try again" </dev/tty
else
    echo "$sshd_config_path found, continuing"
fi

if [[ -f "~/.ssh/known_hosts" ]]; then
    sudo cat ~/.ssh/known_hosts
    echo "***********ERROR***********"
    read -p "Delete ~/.ssh/known_hosts if necessary. Press enter to continue.." </dev/tty
fi

grep -n -E 'AllowUsers|AllowGroups|DenyUsers|DenyGroups' $sshd_config_path
read -p "Check for bad config in $sshd_config_path above. Press enter to continue.." </dev/tty
echo "============================"

read -p "Check ~/.ssh/authorized_keys for bad config. Press enter to continue.." </dev/tty
echo "============================"

echo "ChallengeResponseAuthentication no" >> $sshd_config_path
echo "PermitRootLogin no" >> $sshd_config_path
echo "UsePrivilegeSeparation yes" >> $sshd_config_path
echo "Protocol 2" >> $sshd_config_path
echo "AllowTcpForwarding no" >> $sshd_config_path
echo "X11Forwarding no" >> $sshd_config_path
echo "StrictModes yes" >> $sshd_config_path
echo "IgnoreRhosts yes" >> $sshd_config_path
echo "HostbasedAuthentication no" >> $sshd_config_path
echo "RhostsRSAAuthentication no" >> $sshd_config_path
echo "RSAAuthentication yes" >> $sshd_config_path
echo "PermitEmptyPasswords no" >> $sshd_config_path
echo "PermitUserEnvironment no" >> $sshd_config_path
echo "PrintLastLog yes" >> $sshd_config_path
echo "PasswordAuthentication no" >> $sshd_config_path
echo "UseDNS no" >> $sshd_config_path
echo "ClientAliveInterval 300" >> $sshd_config_path
echo "ClientAliveCountMax 1" >> $sshd_config_path
echo "LoginGraceTime 300" >> $sshd_config_path
echo "MaxStartups 2" >> $sshd_config_path
echo "LogLevel VERBOSE" >> $sshd_config_path
echo "PermitRootLogin no" >> $sshd_config_path
echo "HostBasedAuthentication no" >> $sshd_config_path
echo "PermitEmptyPasswords no" >> $sshd_config_path
echo "IgnoreRhosts yes" >> $sshd_config_path
echo "Protocol 2" >> $sshd_config_path
echo "MaxAuthTries 3" >> $sshd_config_path
echo "PermitUserEnvironment no" >> $sshd_config_path
echo "HashKnownHosts yes" >> $sshd_config_path
echo "UsePAM yes" >> $sshd_config_path
echo "AllowTcpForwarding no" >> $sshd_config_path
echo "MaxSessions 4" >> $sshd_config_path
echo "LogLevel VERBOSE" >> $sshd_config_path
echo "IgnoreRhosts yes" >> $sshd_config_path
echo "Port 2345" >> $sshd_config_path
#New: 7th Sept 2024
echo "X11UseLocalhost yes" >> $sshd_config_path
echo "PubkeyAuthentication yes" >> $sshd_config_path

sudo service sshd restart
sudo systemctl restart sshd.service
sshd -T

