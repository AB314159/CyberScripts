#!/bin/bash
echo "Changing /etc/passwd perms to 644"
sudo chmod 644 /etc/passwd
sudo ls -l /etc/passwd
echo "Changing /etc/shadow perms to 0000"
sudo chmod 0000 /etc/shadow
sudo ls -l /etc/shadow
echo "Changing /boot/grub/grub.cfg perms to 600"
sudo chmod 600 /boot/grub/grub.cfg
sudo ls -l /boot/grub/grub.cfg
echo "Changing /etc/group perms to 644"
sudo chmod 644 /etc/group
sudo ls -l /etc/group
echo "Changing /etc/sysctl.conf perms to 644"
sudo chmod 644 /etc/sysctl.conf
sudo ls -l /etc/sysctl.conf
echo "Changing /etc/ssh/sshd_config perms to 644"
sudo chmod 644 /etc/ssh/sshd_config
echo "Changing various other permissions, if file is present"
sudo chmod 644 /etc/samba/smb.conf
sudo chmod 644 /srv/ftp
sudo chmod 644 /etc/vsftpd.conf
sudo chmod 640 /etc/ssl/private/ssl-cert-snakeoil.key
sudo chmod 644 /etc/samba/smb.conf
sudo chmod 644 /etc/vsftpd.conf
sudo chmod 700 /etc/apparmor
sudo chmod 644 /usr/lib/python3.10/turtle.py
sudo chmod 644 /etc/ssh/sshd_config
sudo chmod 755 /usr/bin/chmod
sudo chmod 755 /bin/mawk
sudo chmod 000 /bin/su
sudo chmod 000 /usr/bin/ldd
sudo chmod 644 /etc/sshd_config
sudo chgrp root /etc/vsftpd.conf
sudo chown root:root /etc/vsftpd.conf
sudo chown root:root /etc/default/grub
sudo chown root:root /etc/samba/smb.conf
sudo chmod 640 /etc/ssh/*.pub
echo "Do chmod 640 for public, and 600 for private keys"
sudo ls -l /etc/ssh/*
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "review the sshd_config above"
sudo ls -l /etc/ssh/sshd_config
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "Changing /etc/ssh/sshd_config owner:group to root:root"
sudo chown root:root /etc/ssh/sshd_config 2> /dev/null
sudo ls -l /etc/ssh/sshd_config
echo "Changing /etc/passwd owner:group to root:root"
sudo chown root:root /etc/passwd
sudo ls -l /etc/passwd
echo "Changing /etc/group owner:group to root:root"
sudo chown root:root /etc/group
sudo ls -l /etc/group
echo "Changing /etc/shadow owner:group to root:shadow"
sudo chown root:shadow /etc/shadow
sudo ls -l /etc/shadow
echo "Changing /etc/sysctl.conf owner:group to root:root"
sudo chown root:root /etc/sysctl.conf
sudo ls -l /etc/sysctl.conf
echo "Changing /boot/grub/grub.cfg owner:group to root:root"
sudo chown root:root /boot/grub/grub.cfg
sudo ls -l /boot/grub/grub.cfg
read -p "Press Enter to continue" </dev/tty
echo "Suspicious: Files in /bin /sbin /usr/bin /usr/sbin /usr/local/sbin not owned by root"
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "Suspicious: Files in /bin /sbin /usr/bin /usr/sbin /usr/local/sbin with >755 permissions"
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "Suspicious: Files in /lib /lib64 /usr/lib with >755 permissions"
sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \;
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "Suspicious: Files in /bin /sbin /usr/bin /usr/sbin /usr/local/sbin not group owned by root"
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "Suspicious: Log files in /var/log with >640 permissions"
sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;
read -p "Press Enter to continue" </dev/tty
echo "============================"
echo "Check: Directory perms must be <= 750 and log file <= 600"
sudo stat -c "%n %a" /var/log/audit /var/log/audit/* 
read -p "Press Enter to continue" </dev/tty