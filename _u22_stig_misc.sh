#!/bin/bash

sudo apt install -y ssh
sudo apt install -y aide
sudo aideinit
sudo dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | sudo tar -x ./usr/share/aide/config/cron.daily/aide -C /
sudo cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide
sudo apt-get install -y libpam-pwquality
sudo apt-get install -y rsyslog
sudo systemctl enable rsyslog.service --now
sudo apt-get install -y apparmor
sudo apt-get install -y vlock
sudo apt-get install -y chrony
sudo systemctl enable auditd.service --now
sudo systemctl enable apparmor.service --now
sudo systemctl enable ssh.service --now
sudo apt-get install -y  opensc-pkcs11
sudo apt-get install -y libpam-pkcs11

#gsettings config
sudo gsettings set org.gnome.settings-daemon.plugins.media-keys logout []
sudo gsettings set org.gnome.desktop.screensaver lock-enabled true
sudo gsettings set org.gnome.desktop.screensaver lock-delay 0
sudo gsettings set org.gnome.desktop.session idle-delay 900
sudo gsettings set org.gnome.desktop.screensaver lock-enabled true
sudo dconf update
echo "applied gsettings"
echo "=============="

#SSH config
sshd_config_path="/etc/ssh/sshd_config"

if ! [[ -f "$sshd_config_path" ]]; then
    echo "***********ERROR***********"
    read -p "File $sshd_config_path not found. Press enter to continue.." </dev/tty
else
    sudo grep -E 'KexAlgorithms|MACs|Ciphers' $sshd_config_path
    echo "Add or set following good values in $sshd_config_path, remove insecure ones"
    echo "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"
    echo "MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com"
    echo "Ciphers aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com"
fi

sudo service sshd restart
sudo systemctl restart sshd.service
sshd -T
echo "SSH settings done"
echo "=============="
