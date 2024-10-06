#!/bin/bash

sudo apt install -y auditd
auditd_path="/etc/audit/rules.d/stig.rules"
echo $auditd_path

if ! [[ -f "$auditd_path" ]]; then
    echo "***********ERROR***********"
    read -p "File $auditd_path not found. Ctrl+C, fix path and try again" </dev/tty
else
    echo "$auditd_path found, continuing"
fi

sudo echo "-w /var/log/sudo.log -p wa -k maintenance" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv" >> $auditd_path
sudo echo "-w /var/log/btmp -p wa -k logins" >> $auditd_path
sudo echo "-w /var/log/journal -p wa -k systemd_journal" >> $auditd_path
sudo echo "-w /var/run/utmp -p wa -k logins" >> $auditd_path
sudo echo "-w /var/log/wtmp -p wa -k logins" >> $auditd_path
sudo echo "-w /var/log/lastlog -p wa -k logins" >> $auditd_path
sudo echo "-w /var/log/faillog -p wa -k logins" >> $auditd_path
sudo echo "-w /etc/sudoers.d -p wa -k privilege_modification" >> $auditd_path
sudo echo "-w /etc/sudoers -p wa -k privilege_modification" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k module_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k module_chng" >> $auditd_path
sudo echo "-w /etc/security/opasswd -p wa -k usergroup_modification" >> $auditd_path
sudo echo "-w /etc/passwd -p wa -k usergroup_modification" >> $auditd_path
sudo echo "-w /etc/gshadow -p wa -k usergroup_modification" >> $auditd_path
sudo echo "-w /etc/group -p wa -k usergroup_modification" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod" >> $auditd_path
sudo echo "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-umount" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd" >> $auditd_path
sudo echo "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd" >> $auditd_path
sudo echo "-w /bin/kmod -p x -k modules" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab" >> $auditd_path
sudo echo "-w /usr/sbin/fdisk -p x -k fdisk" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check" >> $auditd_path
sudo echo "-w /sbin/modprobe -p x -k modules" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd" >> $auditd_path
sudo echo "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chfn" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=unset -k perm_mod" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete" >> $auditd_path
sudo echo "-w /etc/shadow -p wa -k usergroup_modification" >> $auditd_path
sudo echo "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path
sudo echo "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_chng" >> $auditd_path

sudo augenrules --load
sudo cat $auditd_path
echo "Settings above applied"

