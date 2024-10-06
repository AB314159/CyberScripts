Arya - Ubuntu Checklist


VM Setup	2
Sequence	2
Shells	2
Users/Groups/Passwords	3
File permissions	10
Services	13
Programs	30
Sudo & Sudoers config	30
Firewall	31
Audit	33
APT	34
Packages	36
Grub	39
Networking	40
/etc/fstab	40
Password policies	40
Kernel config	42
Browser	45
Firefox STIGS	47
Crontab	50
Backdoors	52
Bad files	53
Policies	56
Start-up check	56
File size	57
Display Managers	57
Kernel modules	60
Miscellaneous	60
FQ info - temp	61
Useful commands - temp	62
File Structure	64
Local Policies	65
Scripting	65
Tips	73
More	75

VM Setup
Processors * cores = 4 * 2
RAM: 8GB
Space: 50GB

Sequence
Study the readme
Don’t miss any clues or points
Write Readme notes in notepad
If ReadMe or Scoring report are unable to open in firefox type in terminal:
sudo apt install firefox
Download plain image backup, do meld, study the system for vulns, take detailed notes
Do FQs first. Don’t miss any clues for getting related (free) points in vulns (e.g disable bad ports or IP addresses, delete bad files etc.)
Complete forensics that don’t require image material
More info on tools, techniques in the FQ document
Do vulns.
Keep taking screenshot of scores after each point, if available

Shells
Meld with plain image
Diff /etc/shells with same file from plain image
Ubuntu 22.04.4
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/usr/bin/sh
/bin/dash
/usr/bin/dash
Remove bad ones
Bad shells:
/usr/sbin/nologin
/bin/false
Users/Groups/Passwords
Meld with plain image
Add/Remove users based on a list of authorized users
https://linuxize.com/post/how-to-add-and-delete-users-on-ubuntu-18-04/
Make sure only specific users have administrator permissions
https://phoenixnap.com/kb/how-to-create-sudo-user-on-ubuntu
Give all users secure passwords
https://www.cyberciti.biz/faq/linux-set-change-password-how-to/
Run: passwd -l root
$TODO:
Need to add chage -M 90 -W 14 -m 7 for all users in the script
Check no local users have ID less than 1000
Check that system users have IDs either less than 1000 or more than 1010 or so. Just print all IDs for system users and manually check
Check no system users have no valid login shell
Make sure to check passwd for good shells only, and no interactive shells for system users, and no non-interactive shells for local users
UID>1000, shell false or nologin
UID <1000, but interactive shell?
Check for duplicate ID
Ask before deleting root imposter/root group
Group script: Add syslog in adm group only
Disable default/guest account login: LightDM
Cat gecosfields of all users for manual checking
usermod -u randomUser # Unlock any users that are authorized and are currently locked
Check for groups that shouldn’t have users
sudo apt install libpam-pwquality
SYS_UID_MAX = 999
SYS_UID_MIN = 0
UID_MAX = 65534
UID_MIN = 1000
LOG_OK_LOGINS yes
add/remove users, duplicate ID, <1000> ID, wrong home directory, missing password, change all user passwords, delete root imposters
Lock root account, set root password
add/delete group members from adm and sudo groups, delete root groups
Confirm if all above stuff is part of the script created. Make sure the script prints the passwd and group files for manual double checking after doing all work
passwd randomUser # Make sure all users have secure passwords
passwd -S randomUser # Read the user's password status
usermod -L randomUser # Lock out any users the readme wants
usermod -u randomUser # Unlock any users that are authorized and are currently locked
chage -m 7 -M 90 -I 10 -W 14 randomUser # Enforce the aging policies on all users
sudo deluser <uid>
sudo adduser <uid> (or useradd?)
set complex password
Check existing password settings (expiry, min/max etc)
Set right admin permissions
Admin users: set the list in adm, sudo lines
delgroup <group_name>
If using CenOS, this group should be removed from the file.
sudo nano /etc/passwd 
grep x /etc/passwd -v : Check for blank passwords
grep 0 /etc/passwd : Check for root imposters
Make sure users login to their own home directory and not someone else’s
If readme says users aren’t unauthorized but aren’t authorized either
sudo passwd -l <user>
passwd randomUser # Make sure all users have secure passwords
passwd -S randomUser # Read the user's password status
usermod -L randomUser # Lock out any users the readme wants
usermod -u randomUser # Unlock any users that are authorized and are currently locked
chage -m 7 -M 90 -I 10 -W 14 randomUser # Enforce the aging policies on all users
/etc/passwd
check for bad shells based on clean image
Check for blank or incorrect shells (root:x:0:0:root:/root:/usr/sbin/nologin)
/etc/group
Check for groups that shouldn’t have users
I.e. Bluetooth
Find if any users or groups have duplicate IDs
Check passwd for logon shells not within /etc/shells
Prints users with IDs less than 1000 and with interactive login shells
Ensure all users login to their own home directories
Check for geckos fields in /etc/passwd
Make sure to configure password policies. (more)


Warning: This may lead to your account getting locked out.


Important packages:


libpam-cracklib
libpam-pwquality
Note: Libpam-pwquality is newer and should be installed instead of libpam-cracklib.
Important files:


/etc/login.defs
/etc/pam.d/common-auth
/etc/pam.d/common-password
/etc/pam.d/common-account
Bellow is an example PAM configuration:
File: /etc/pam.d/common-password


# here are the per-package modules (the "Primary" block)
password   requisite                   pam_pwquality.so retry=3 minlen=15 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password   requisite                   pam_pwhistory.so retry=3 minlen=15 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password   requisite                   pam_unix.so retry=3 minlen=15 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password   [success=1 default=ignore]  pam_unix.so obscure use_authtok sha512 shadow
Another module you should know is gecoscheck, it can ensure that passwords do not use fields from the gecosfields (name, phone number, etc.) It is also a good idea to check for gecosfields that contain malicious/sus things:


gecoscheck
This is just a basic setting for the /etc/pam.d/common-password file. You should of course find more settings on your own. Remember, this is generally how pam works:


setting-type control module.so arguments


Where setting-type can be things like "password" or "account", control can be "requisite" or "required", module.so can be modules like "unix.so" or "pwquality.so", and arguments can be things like "minlen=x" or "retry=x" where x is a value. You can find more information about PAM at the link below.
Click Here for More PAM Stuff


Password Commands:


passwd randomUser # Make sure all users have secure passwords
passwd -S randomUser # Read the user's password status
usermod -L randomUser # Lock out any users the readme wants
usermod -u randomUser # Unlock any users that are authorized and are currently locked
chage -m 7 -M 90 -I 10 -W 14 randomUser # Enforce the aging policies on all users
Check existing password settings (expiry, min/max etc)
Limit consecutive repeating characters in passwords
$ sudo nano /etc/security/pwquality.conf
Add line:
maxrepeat=3
/etc/login.defs: PASS_MIN_DAYS 7 Default min password age
Dictionary based password strength checks enabled
sudo apt install libpam-pwquality
A minimum password length requirement:
/etc/pam.d/common-password: 
password required pam_pwquality.so
minlen=10
dcredit=-1
ucredit=-1
lcredit=-1
ocredit=-1
retry=3
difok=3 
maxrepeat=3 
reject_username
minclass=3
Users should not have null passwords: 
Remove nullok from the common-auth file or replace with nullok_secure
chage -l is to list password min, max, and warn ages of a user
chage -M 90 -m 7 -W 14 <username>
sudo nano /etc/passwd 
grep x /etc/passwd -v : Check for blank passwords
grep 0 /etc/passwd : Check for root imposters
Check for suspicious gecos fields
Make sure users login to their own home directory and not someone else’s
Groups:
Check for GID 0
Auth:
/etc/pam.d/common-session (check for good settings, below ones might be bad ones)
Session [default=1]  pam_permit.so
Session requisite  pam_permit.so
In /etc/pam.d/common-auth:
auth	required 	pam_faillock.so deny = 3


Password Policies:
Make sure to configure password policies. (more)
Warning: This may lead to your account getting locked out.
Important packages:
libpam-cracklib
libpam-pwqaulity
Note: Libpam-pwquality is newer and should be installed instead of libpam-cracklib.
Important files:
/etc/login.defs


/etc/pam.d/common-auth
#at least 4 second delay between logon attempts
auth    required    pam_faildelay.so    delay=4000000 


/etc/pam.d/common-password
/etc/pam.d/common-account
Bellow is an example PAM configuration:
File: /etc/pam.d/common-password
# here are the per-package modules (the "Primary" block)
password   requisite                   pam_cracklib.so retry=3 minlen=15 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password   requisite                   pam_pwhistory.so retry=3 minlen=15 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password   requisite                   pam_unix.so retry=3 minlen=15 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
password   [success=1 default=ignore]  pam_unix.so obscure use_authtok sha512 shadow
Another module you should know is gecoscheck, it can ensure that passwords do not use fields from the gecosfields (name, phone number, etc.) It is also a good idea to check for gecosfields that contain malicious/sus things:
gecoscheck
This is just a basic setting for the /etc/pam.d/common-password file. You should of course find more settings on your own. Remember, this is generally how pam works:
setting-type control module.so arguments
Where setting-type can be things like "password" or "account", control can be "requisite" or "required", module.so can be modules like "unix.so" or "cracklib.so", and arguments can be things like "minlen=x" or "retry=x" where x is a value. You can find more information about PAM at the link below.
Click Here for More PAM Stuff
Important login.defs configurations
PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_WARN_AGE 14
ENCRYPT_METHOD YESCRYPT
passwd randomUser # Make sure all users have secure passwords
passwd -S randomUser # Read the user's password status
usermod -L randomUser # Lock out any users the readme wants
usermod -u randomUser # Unlock any users that are authorized and are currently locked
chage -m 7 -M 90 -I 10 -W 14 randomUser # Enforce the aging policies on all users
Password Commands:
passwd randomUser # Make sure all users have secure passwords
passwd -S randomUser # Read the user's password status
usermod -L randomUser # Lock out any users the readme wants
usermod -u randomUser # Unlock any users that are authorized and are currently locked
chage -m 7 -M 90 -I 10 -W 14 randomUser # Enforce the aging policies on all users
/etc/pam.d/common-password: rounds=5000 gecoscheck minlen=14 remember=24
set min/max/expiry password info for users


/etc/login.defs:
SYS_UID_MAX = 999
LOG_OK_LOGINS yes
In /etc/login.defs do the following:
	Set ENCRYPT_METHOD to YESCRYPT (or SHA512 if you don’t get points)
	Set PASS_MAX_DAYS to 90
	Set PASS_MIN_DAYS to 7
	Set PASS_WARN_AGE to 14
Important login.defs configurations
PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_WARN_AGE 14
ENCRYPT_METHOD YESCRYPT
Enforce secure password policies
Make sure users are required to comply with secure password guidelines. 
https://www.poftut.com/linux-etc-login-defs-configuration-examples/
Our Recommendations:
PASS_MAX_DAYS	90
PASS_MIN_DAYS	7
PASS_WARN_AGE	14
ENCRYPT_METHOD 	YESCRYPT
https://www.2daygeek.com/how-to-set-password-complexity-policy-on-linux/
Users must not be able to use the same password forever
https://www.systutorials.com/docs/linux/man/8-pam_pwhistory/
User passwords should be hashed with a secure hashing algorithm
/etc/passwd
Backup before changing: sudo cp /etc/passwd ~/passwd-backup
Delete: non-root users with ID 0
Delete: unauthorized users
System users are users with ID less than 1000
sudo chmod 644 /etc/passwd
Scroll end of the file to find hidden lines
/etc/group
Backup before changing: sudo cp /etc/group ~/group-backup
Update: sudo and admin lists to authorized ones
sudo chmod 644 /etc/passwd
Scroll end of the file to find hidden lines
Set complex password: 
passwd <user>
Users
	To access the system and use it, you use users. 
	There are human users and system users. Human users are for humans, (UID > 1000) and system users are used by the system to maintain functionality for different applications and critical system 
		A group of users is called a group!
	Users and groups can each be assigned different privileges
	Example: The pulse user in linux is used by pulse audio, however the audio sound server only needs to be use device and hardware files, and thus canonical uses a separate user to make sure it doesn't have more 		privileges then required.
	They're also used to manage access to who can see certain files and directories and run certain commands
	Different users and groups have different privileges
		As the root user (or how the system sees it: anyone with the UID 0) has all privileges, you can quite literally do anything
		Make sure no users have UID 0 because they would have root permissions
			Sudo allows any user to run commands as the root user, so we want to make sure only authorized administrators can do that
		We also want to make sure there are no unauthorized normal users that aren't in mentioned in the README
			This is because these unauthorized users may be able to elevate to root users, obviously not good


	System accounts are stored in /etc/passwd
	Groups are stored in /etc/group
	Make sure only authorized admins are in the adm and the sudo groups in /etc/group
	Password hashes are stored in /etc/shadow
	In linux, the system identifies users and groups through a number called the "UID" (User Identifier), a number ID from 0-65534
	Some important commands 
	adduser <username> (add a user)
	adduser <username> <group_name> (add user to group)
	deluser <username> (delete a user)
	deluser	 <username> <group_name>  (delete user from group)
	groupadd <group_name> (add group)
	delgroup <group_name> (delete group)
	All of these files edit /etc/group or /etc/passwd, and you can see that real time!
Guidelines for secure passwords are as follows:
	10 characters
	1 uppercase character
	1 lower case character
	1 number
	1 symbol (i.e. #, $, %, &, etc.)
	Most common example: CyberPatriot1!
	passwd <username> (new password)
	echo “<username>:<newpassword>” | chpasswd  
		To execute the command above you need to be root
Remove suspicious groups in /etc/group
Change all user passwords to CyberPatriot1!
Restrict direct login access for system/shared accounts:
sudo nano /etc/security/access.conf
Add: “ALL EXCEPT users :ALL”
sudo nano /etc/pam.d/login
Add: account required pam_access.so
Users:
If readme says users aren’t unauthorized but aren’t authorized either
sudo passwd -l <user>
good commands to run:
$ grep ":x:0" /etc/passwd | grep -v "^root:"
ensure no output
Here's a command to list all non system users:
files to change:


/etc/passwd
check for bad shells based on clean image
Check for blank or incorrect shells (root:x:0:0:root:/root:/usr/sbin/nologin)


/etc/group
	Check for groups that shouldn’t have users
		I.e. Bluetooth








File permissions
must diff with plain image, sticky/suid/guid etc, r/w/x perms
File Permissions:
use ls -l to view file permissions
l means it's a link
d means it's a link
r means read permissions
w means writing permissions
x means executing permissions
+ means has a file access control list so use getfacl
getfacl shows file access control list - when ls -l has a + it has a FACL. Too see all Extended ACLS use getfacl -Rs /
for octal permissions uses binary:
---  :  0
--x  :  1
-w-  :  2
-wx  :  3
r--  :  4
r-x  :  5
rw-  :  6
rwx  :  7
e.g. for a directory everyone could access the file permission would be drwxrwxrwx-
change octal permissions using chmod
File permissions:
sudo chmod 600 /boot/grub/grub.cfg
chown [-R] {user}:{group} /path/to/file # To change the owner/group of a file
chgrp [-R] {group} /path/to/file # To change the group of a file
stat -c “%a” /path/to/file # Get octal permissions
/etc/passwd # 644 root:root
/etc/group # 644 root:root
/etc/sysctl.conf # 644 root:root
/etc/shadow # 0000 root:root
Find files with suid & guid bits set
sudo find / -type f \( -perm -u=s -o -perm -g=s \) -ls 2> /dev/null
sudo find . -perm /1000 -ls 2> /dev/null
sudo getfacl -Rs / 2>/dev/null (once found, setfacl -b or -bR as needed to remove)
sudo nano /etc/fstab # Add security settings for /tmp
Make sure specific directories/memory (i.e. /dev/shm) spaces are mounted with correct permissions (nosuid, noexec, nodev)
Add your mounting settings through /etc/fstab.
mount -o remount {directory} # Let the settnigs take affect
chmod 0000 /etc/shadow
chmod 644 /etc/samba/smb.conf
Insecure permissions on samba configuration file fixed
Setting secure permissions (644) on the Samba configuration file ensures that it can be read by authorized users but not modified by unauthorized users. This helps prevent unauthorized changes to Samba settings.
chmod 644 /etc/samba/smb.conf
VSFTPD ftp root is not world writable
Baseline permissions
chmod 644 /srv/ftp
Vsftpd configuration permission is fixed
chmod 644 /etc/vsftpd.conf
Baseline permissions
VSFTPD private key for TLS no longer world readable
chmod 640 /etc/ssl/private/ssl-cert-snakeoil.key
In general not everyone needs to read every file, a key file is critical in this comprised environment as it is used on this company’s FTP server. Only people with high level permissions should be able to read this file.
(system.sh was setting 646 permissions on auth.log)
chown [-R] {user}:{group} /path/to/file # To change the owner/group of a file
chgrp [-R] {group} /path/to/file # To change the group of a file
stat -c “%a” /path/to/file # Get octal permissions
/etc/passwd # 644 root:root
/etc/group # 644 root:root
/etc/sysctl.conf # 644 root:root
/etc/shadow # 0000 root:root
getcap -r / 2>/dev/null
$ sudo chown root:root /etc/samba/smb.conf
$ sudo chmod 644 /etc/samba/smb.conf
$ sudo chmod 644 /etc/vsftpd.conf
$ sudo chown root:root /etc/vsftpd.conf
$ sudo chgrp root /etc/vsftpd.conf
sudo chmod 700 /etc/apparmor
sudo chmod 644 /usr/lib/python3.10/turtle.py
sudo chmod 640 </etc/ssh/ssh_host_xxx_keys>
sudo chmod 600 <private keys>
sudo chmod 644 /etc/ssh/sshd_config
chmod SUID binary removed
Any user on the system could change the permission of a file without requiring authentication
There was also a crontab under a normal user changing the permissions of /etc/shadow, which was possible using this SUID bit
chmod 755 /usr/bin/chmod
Remove SUID bit from python: sudo chmod u-s /usr/bin/python3
sudo getcap /usr/bin/perl
getcap -r / 2>/dev/null (or, also route to local file like ~/getcap.txt)
Remove bad service capabilities from service files in /etc/systemd/system
sshd.service: remove AmbientCapabilities=CAP_SYS_ADMIN
Removed SUID permission bit from mawk - (/srv/e.sh, bleh, link)
chmod 755 /bin/mawk
rm -rf /srv/e.sh
This script was opening a bash shell
Secure Su:
chmod 000 /bin/su
Secure ldd:
chmod 000 /usr/bin/ldd
chmod SSH SystemD service to ensure it's not world-writable
Auditd monitors changes to SSH configuration
Grub is owned by root
chown root:root /etc/default/grub
Make sure "AmbientCapabilities=CAP_SYS_ADMIN" is not in any file under /etc/systemd/system/*
Capabilities: getcap command
SSH
Chmod of config file for no world writable
sudo chmod 644 /etc/sshd_config
/etc/shadow permissions fixed
check for SUID bits on the system
Services
Location /etc/systemd
Syntax of service file:
[Unit]
Description=System Logging Service
Requires=syslog.socket
Documentation=man:rsyslogd(8)
Documentation=https://www.rsyslog.com/doc/


[Service]
Type=notify
ExecStart=/usr/sbin/rsyslogd -n -iNONE
StandardOutput=null
Restart=on-failure
# Increase the default a bit in order to allow many simultaneous
# files to be monitored, we might need a lot of fds.
LimitNOFILE=16384

[Install]
WantedBy=multi-user.target
Alias=syslog.service
Start Services: # systemctl start <service_name>
Stop Services: # systemctl stop <service_name>
Enable Services: # systemctl enable <service_name>
Disable Services: # systemctl disable <service_name>
List Services: # systemctl list-units --type=service
You can also use service --status-all to list all running services under systemd.


Setting up ProFTPD, Pure-FTPD, and VSFTPD - Google Docs
disable bad services (e.g. update-rc.d avahi-daemon disable [disables at start-up];or sudo systemctl disable apache2 [completely disables apache2])
enable good services like ufw, auditd, etc
install aide
check config under system.d and other 2 locations, delete bad exec command line
SSH: Critical service config, if allowed by the README file
https://linuxhint.com/secure-ssh-server-ubuntu/
/etc/ssh/sshd_config
ChallengeResponseAuthentication no
PermitRootLogin no
UsePrivilegeSeparation yes
Protocol 2
AllowTcpForwarding no
X11Forwarding no
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
RhostsRSAAuthentication no
RSAAuthentication yes
PermitEmptyPasswords no
PermitUserEnvironment no
PrintLastLog yes
PasswordAuthentication no
UseDNS no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 300
MaxStartups 2
LogLevel VERBOSE
ssh-keygen
SSH (/etc/ssh/sshd_config):
Check Banner message
Check Message of the day
remove insecure ciphers like 3des-cbc (good ones are aecXXX, openssh)
PubkeyAuthentication → enable
Strict mode → enable 
Set banner to /etc/issue
good commands to run:


$ ssh-keygen (used when a user needs to connect to a remote system without supplying a password)
$ service ssh status


files to change: 
~/.ssh ~ check authorized_keys that have been installed


/etc/ssh/sshd_config
 ChallengeResponseAuthentication no
 PermitRootLogin no
 UsePrivilegeSeparation yes
 Protocol 2
 AllowTcpForwarding no
 X11Forwarding no
 StrictModes yes
 IgnoreRhosts yes
 HostbasedAuthentication no
 RhostsRSAAuthentication no
 RSAAuthentication yes
 PermitEmptyPasswords no
 PermitUserEnvironment no
 PrintLastLog yes
 PasswordAuthentication no
 UseDNS no
 ClientAliveInterval 300
 ClientAliveCountMax 0
 LoginGraceTime 300
 MaxStartups 2
 LogLevel VERBOSE
 Banner /etc/issue
 Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
 UsePAM no
 HostKeyAlgorithms  ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,ssh-dss
 KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1
SSH 
AddressFamily inet
ChrootDirectory %h
Protocol 2 #This is better than 1
Review types of SSH ciphers used in sshd_config, and remove insecure ones
/etc/pam.d/sshd: make sure pam_authchk.so is not "auth optional"


Apache: Critical service config, if allowed by the README file
Apache Directory:
/etc/apache2/
apache2.conf 	
main config file, global config settings		
ports.conf
used to specify ports that virtual hosts listen on
conf.d/				
define SSL config + default security
sites-available/
virtual host files that define different web sites (available)
sites-enabled/
defines virtual host files that are being used
mods-[enabled, available]/
define modules that can be loaded
Global Configs:
Timeout: how long server has to fulfill a client request
KeepAlive: Allow/deny each connection to handle multiple requests from the same client
MaxKeepAliveRequests: Number of separate requests each connection will handle before dying
KeepAliveTimeout: How long to wait for a new request before dying
ServerSignature: Do/don’t display server version on error (or any) pages
ServerTokens: Do/don’t only return Apache in Server header
Directory Configs:
<Directory />
    Order Deny,Allow
    Deny from all
    Deny from [user]
    Options None
    AllowOverride None
    Require all denied
</Directory>
Modules
Apache has modules you can plug in to perform additional functions
mod-security
mod-evasive
Each module has its own installation (apt) and configurations in files
Highly recommend researching Apache security modules, especially those two
Disable all unnecessary modules
apt purge <module>
Apache security:
/etc/apache2/conf-enabled/security.conf:
ServerSignature off
/etc/apache2/conf-enabled/httpd.conf
TraceEnable off
User apache
Group apache
ServerSignature Off
ServerTokens Prod
/etc/apache2/conf-enabled/httpd-ssl.conf
SSLCipherSuite ALL:!aNULL:!ADH:!eNULL:!LOW:!EXP:RC4+RSA:+HIGH:+MEDIUM


VSFTPD: Critical service config, if allowed by the README file
check PR4 & Google drive settings/xls
Change these lines in /etc/vsftpd.conf:
	accept_timeout=60
allow_anon_ssl=NO
allow_writeable_chroot=YES
VSFTPD Critical service configuration:
sudo chmod 600 /etc/ssl/private/vsftpd.key
VSFTPD upload/download logging enabled
xferlog_enable = YES
Generally logging is a good thing and comes in handy when dealing with perpetrators 
VSFTPD TLS security-layer has been added
ssl_enable = YES
VSFTPD anonymous login has been enabled
anonymous_enable = YES
VSFTPD anonymous user is not root
ftp_username ≠ root 
Anonymous users should not log into the ftp server as root, this poses a security concern
Baseline /etc/vsftpd.conf
VSFTPD anonymous ftp root is set
anon_root = /srv/ftp
VSFTPD PASV security checks enabled
pasv_promiscuous = NO
Allows for only the controlled connections to the FTP server and makes sure that clients only use the     original IP that was used in the connection request to connect the FTP server
Prevents threat actors from spoofing their IP during data transfer
VSFTPD Critical service configuration:
VSFTPD upload/download logging enabled
xferlog_enable = YES
Generally logging is a good thing and comes in handy when dealing with perpetrators 
VSFTPD TLS security-layer has been added
ssl_enable = YES
VSFTPD anonymous login has been enabled
anonymous_enable = YES
VSFTPD anonymous user is not root
ftp_username ≠ root 
Anonymous users should not log into the ftp server as root, this poses a security concern
Baseline /etc/vsftpd.conf
VSFTPD anonymous ftp root is set
anon_root = /srv/ftp
VSFTPD PASV security checks enabled
pasv_promiscuous = NO
Allows for only the controlled connections to the FTP server and makes sure that clients only use the     original IP that was used in the connection request to connect the FTP server
Prevents threat actors from spoofing their IP during data transfer
VSFTPD
Very Secure FTP Daemon
An FTP server for linux, old but still good
To install: apt install vsftpd
Config: /etc/vsftlpd.conf
Enable active:
connect_from_port_20=YES
Enable Passive:
pasv_enable=YES
pasv_max_port=<port>
pasv_min_port=<port>
Connecting
ftp <ip_addr/Domain_name>
Upload using put command
Download using get command
Directives
Anonymous
Not always bad, may want public files to be available
Just make sure that if it is enabled, that access is restricted to only the files (or directory) you want to share
Guest
If allowed, non-anonymous connections get remapped to a local user (still needs a username/password)
Local
Allows local users on the machine to use FTP
If local is disabled anonymous must be allowed
Users
If you want local users to have access to their home directory user enable local user chroot
SSL
FTP is a clear text protocol, so encrypting FTP using the latest SSL is good
Block anonymous privileges:
Upload
Write
Look at stigs
good commands to run:


Search for the existence of '.netrc' files:
$ sudo find /root /home -iname “.netrc”


files to change:
/etc/vsftpd.conf
Add or change lines: 
ssl_ciphers = high
banner_file= /etc/issue
anonymous_enable=NO
chroot_local_user=YES
xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES
force_dot_files=NO
write_enable=YES
ssl_enable=YES
Remove lines:
chown_username=root
ascii_download_enable=YES
after changing the files run sudo service vsftpd restart to apply changes
Add locked users to /etc/ftpusers to prevent ftp access
TCP Wrapper + Firewall:
echo "vsftpd: ALL" >> /etc/hosts.allow
iptables -I INPUT -p tcp --dport 64000:65535 -j ACCEPT
ufw allow 21/tcp
Samba: Critical service config, if allowed by the README file
SMB server for linux
To install server: apt install samba
To install client: apt install smbclient
Server config file location: /etc/samba/smb.conf
Samba Shares:
[games] # Share Name
comment = My video games
path = /etc/games
read only = yes 
printable = yes # Files can be sent to spool for printing
guest ok = yes
Using Samba Client
Accessing a Specific Share
smbclient //ipaddress/sharename

Listing a Servers Share
smbclient -L <ip_address>

Full Samba Client Commands:
https://www.samba.org/samba/docs/current/man-html/smbclient.1.html 
Samba Server Security
Global configurations set under the [global] section
[global]
client signing = mandatory # Makes it mandatory for SMB to sign each packet
guest ok = no
encrypt passwords = yes
force create mode = 0755 # Sets permissions on newly created files in share
Link to full settings documentation
Highly recommend going through that link and researching anything related to security, and implementing that
More Security:
Samba has a lot of vulnerabilities because it’s older versions do not use encryption
https://www.cvedetails.com/vulnerability-list/vendor_id-102/Samba.html 
Research more
chmod 755 all samba shares
Remove line containing:
client min protocol = NT1
/etc/samba/smb.conf
Add line:
null passwords = no
/etc/samba/smb.conf
check PR4 & Google drive settings/xls
Insecure permissions on samba configuration file fixed
Samba uses Encrypted Password
Samba minimum protocol set to SMB3
Samba never maps logins to guest
Unauthorized samba share removed
Samba restricts anonymous
Samba enables tls
Samba requires signing
Samba does not accept null passwords
Samba does not allow insecure wide links
Samba tls certificate verification enabled
Samba does not enable ntlm
Samba create mask for company share secured
Samba uses Encrypted Password
Enabling password encryption in Samba ensures that user passwords are stored securely. This prevents password cracking and enhances authentication security.
[/etc/samba/smb.conf] encrypt passwords = yes
Samba minimum protocol set to SMB3
Setting the minimum protocol to SMB3 improves security by using a more modern and secure version of the Samba server. Older SMB versions have vulnerabilities that could be exploited.
[/etc/samba/smb.conf] server min protocol = SMB3
Samba never maps logins to guest
Disabling the mapping of logins to guest access enhances security by ensuring that unauthorized users cannot access shared directories.
[/etc/samba/smb.conf] map to guest = never
Unauthorized samba share removed
Remove IPCS share, unauthorized share sharing ‘/’ in the conf file.
[IPCS]
   comment = IPC Public Share
   path = /
   browseable = yes
   read only = no
   writeable = yes
   guest ok = yes
   public = yes




Samba restricts anonymous
Restricting anonymous access in Samba limits the information that anonymous users can access.
[/etc/samba/smb.conf] restrict anonymous = 2
Samba enables tls
Enabling TLS for Samba enhances data encryption and security during communication between clients and the server.
[/etc/samba/smb.conf] tls enabled = yes
Samba requires signing
Requiring client and server signing ensures that data is not tampered with during transmission.
[/etc/samba/smb.conf] client signing = mandatory
[/etc/samba/smb.conf] server signing = mandatory
Samba does not accept null passwords
Disallowing null passwords in Samba ensures that users must set strong passwords. Empty passwords can be exploited by attackers to gain unauthorized access.
[/etc/samba/smb.conf] null passwords = no
Samba does not allow insecure wide links
[/etc/samba/smb.conf] allow insecure wide links = no
Samba tls certificate verification enabled
Enabling TLS certificate verification in Samba enhances security by ensuring that the server's TLS certificate is valid and trusted.
[/etc/samba/smb.conf] tls verify peer = as_strict_as_possible
Samba does not enable ntlm
Disabling NTLM (NT LAN Manager) authentication in Samba improves security by using more secure authentication methods.
[/etc/samba/smb.conf] client ntlmv2 auth = no
[/etc/samba/smb.conf] ntlm auth = no
Samba create mask for company share secured
README stated that the share had to be secured. 
[/etc/samba/smb.conf] create mask 0777
Samba share read and write list configured
[/etc/samba/smb.conf] read list = jyp
[/etc/samba/smb.conf] write list = @misamo

Samba uses Encrypted Password
Enabling password encryption in Samba ensures that user passwords are stored securely. This prevents password cracking and enhances authentication security.
[/etc/samba/smb.conf] encrypt passwords = yes
Samba minimum protocol set to SMB3
Setting the minimum protocol to SMB3 improves security by using a more modern and secure version of the Samba server. Older SMB versions have vulnerabilities that could be exploited.
[/etc/samba/smb.conf] server min protocol = SMB3
Samba never maps logins to guest
Disabling the mapping of logins to guest access enhances security by ensuring that unauthorized users cannot access shared directories.
[/etc/samba/smb.conf] map to guest = never
Unauthorized samba share removed
Remove IPCS share, unauthorized share sharing ‘/’ in the conf file.
[IPCS]
   comment = IPC Public Share
   path = /
   browseable = yes
   read only = no
   writeable = yes
   guest ok = yes
   public = yes


Samba restricts anonymous
Restricting anonymous access in Samba limits the information that anonymous users can access.
[/etc/samba/smb.conf] restrict anonymous = 2
Samba enables tls
Enabling TLS for Samba enhances data encryption and security during communication between clients and the server.
[/etc/samba/smb.conf] tls enabled = yes
Samba requires signing
Requiring client and server signing ensures that data is not tampered with during transmission.
[/etc/samba/smb.conf] client signing = mandatory
[/etc/samba/smb.conf] server signing = mandatory
Samba does not accept null passwords
Disallowing null passwords in Samba ensures that users must set strong passwords. Empty passwords can be exploited by attackers to gain unauthorized access.
[/etc/samba/smb.conf] null passwords = no
Samba does not allow insecure wide links
[/etc/samba/smb.conf] allow insecure wide links = no
Samba tls certificate verification enabled
Enabling TLS certificate verification in Samba enhances security by ensuring that the server's TLS certificate is valid and trusted.
[/etc/samba/smb.conf] tls verify peer = as_strict_as_possible
Samba does not enable ntlm
Disabling NTLM (NT LAN Manager) authentication in Samba improves security by using more secure authentication methods.
[/etc/samba/smb.conf] client ntlmv2 auth = no
[/etc/samba/smb.conf] ntlm auth = no
Samba create mask for company share secured
README stated that the share had to be secured. 
[/etc/samba/smb.conf] create mask 0777
Samba share read and write list configured
[/etc/samba/smb.conf] read list = jyp
[/etc/samba/smb.conf] write list = @misamo
good commands to run:
files to change:
/etc/samba/smb.conf :
In [global], add:
client signing = mandatory
encrypt passwords = yes
tls enabled = yes
allow dcerpc auth level connect = no
restrict anonymous = true
tls verify peer = as_strict_as_possible
unicode = yes
unix charset = ASCII
unix extensions = yes
unix password sync = no
update encrypted = yes
username level = 5
In [share], add:
create mask = 644

XRDP: Critical service config, if allowed by the README file
XRDP Critical service configuration:
XRDP logs at the highest level
LogLevel = TRACE
Logging at the highest level helps with troubleshooting and security
XRDP requires credentials
require_credentials = true
The readme said the bleh was somehow able to gain initial access onto the system using XRDP, that hinted that XRDP was comprised.
XRDP is running on port 3306
port 3306
Instructed in readme
XRDP encryption has been enabled
crypt_level = fips/high
Obvious vulnerability, you want the highest amount of encryption especially in this environment
MYSQL: Critical service config, if allowed by the README file
JBOSS: Critical service config, if allowed by the README file
Apache: Critical service config, if allowed by the README file
PHP: Critical service config, if allowed by the README file
In /etc/php5/apache2
In /etc/php5/cli
Error handling
expose_php = Off			Disables web server sending back PHP version info
error_reporting = E_ALL		Report all errors
display_errors = Off			Suppresses displaying errors
display_startup_errors = Off		Suppresses displaying startup errors
log_errors = On			Logs errors. This is so only you can view errors, not hackers!
error_log = [/path/to/log]		Sets the path to the log file
ignore_repeated_errors		Log repeating messages, even if they’re from the same use
General Settings:
doc_root = [/path/DocRoot/PHP_Scripts]		Sets PHP’s root directory
open_basedir = [/path/Docroot/PHP_Scripts]		Limits files that can be accessed, like chroot in FTP
include-path = [/path/PHP-Pear]			Limits directories that can be queried by certain
							commands
extension-dir = [/path/to/dir]				Sets directory that PHP looks for extensions in
mime_magic.magicfile = [/path/to/file]		Self-explanatory
allow_url_fopen = Off					Turns off access of URL object-like files
allow_url_include = Off				Turns of use of URL-aware fopen wrappers
variables_order = “GPSE”				Creates $GET $POST $SERVER and $ENV variables
allow_webdav_methods = Off				Allow handling of WebDav HTTP requests within PHP script
File Upload Handling
file_uploads = On			Enables file uploads on the PHP enabled servers
upload_tmp_dir = [/path/to/dir]	Sets the temporary directory for upload storage
max_file_uploads = 2			Sets maximum amount of files that can be uploaded at a time
PHP Executable Handling
enable_dl = Off			Disables dynamic loading of PHP modules in Apache, deprecated
disable_functions = system, exec, shell_exec, passthru, phpinfo, show_source, popen, proc_open
disable_functions = fopen_with_path, dbmopen, dbase_open, putenv, move_uploaded_file
disable_functions = chdir, mkdir, rmdir, chmod, rename
disable_functions = filepro, filepro_rowcount, filepro_retrieve, posix_mkfi
Session Handling
session.auto_start = Off					States whether session module begins on startup
session.save_path = /path/PHP-session/			States where your session files will be saved
session.name = myPHPSESSID				Session name
session.hash_function = 1					Use SHA-1 hashing
session.hash_bits_per_character = 6				Self-explanatory
session.use_trans_sid = 0					Enables transparent session ID is enabled or not
session.cookie_domain = full.qualified.domain.name		Domain name
session.cookie_lifetime = 0					Lifetime of cookies after they are sent to the browser
session.cookie_secure = On					Whether cookies should be sent over secure connections
session.cookie_httponly = 1					Cookies only accessible through HTTP
session.use_only_cookies = 1					Only use cookies to store SID on client side
session.cache_expire = 30					Lifetime of cached content
default_socket_timeout = 60					Default timeout in seconds for socket-based data streams
Checks and limits for the paranoid. 
session.referer_check = /application/path	Substring to be checked when looking at the HTTP referer
memory_limit = 32M				Max memory in MB allowed to be allocated by a script
post_max_size = 32M				
max_execution_time = 60			Maximum execution time of a script in seconds
report_memleaks = On			Report memory leaks
track_errors = Off				Enables/disables storing last error in $php_errormsg
html_errors = Off				Suppress HTML errors
Reference:
https://www.owasp.org/index.php/PHP_Configuration_Cheat_Sheet
iptables: Critical service config, if allowed by the README file
Nginx: Critical service config, if allowed by the README file
Nginx HTTP & Reverse Proxy Server
Open-source HTTP server for Windows and Linux
More popular than Apache
To install: apt install nginx
NGINX directory:
/etc/nginx/
conf.d/
modules-[available/enabled]
nginx.conf
site-[available/enabled]
Very similar to Apache
Configs
Similar to Apache
Configurations are the same except for a few unique ones
Syntax is different though:
“ServerTokens Off” (Apache)
“server_tokens off;” (Nginx)
https://www.stigviewer.com 
https://www.stigviewer.com/stig/apache_server_2.4_unix_server/ 
https://www.stigviewer.com/stig/red_hat_ansible_automation_controller_web_server/2023-03-15/ 


NGINX disable etag
Disabling ETag response headers helps improve security by preventing browsers from tracking files and versions. Attackers can potentially use this information for fingerprinting or identifying vulnerabilities in web applications.
[/etc/nginx/nginx.conf] etag off;
NGINX protects against cross site scripting attacks
This configuration adds an additional layer of protection against cross-site scripting (XSS) attacks. The "X-XSS-Protection" header instructs browsers to block pages if they detect suspected XSS attacks, in turn, enhancing web application security.
[/etc/nginx/nginx.conf] add_header X-XSS-Protection "1; mode=block" always; 
NGINX ssl protocols set to TLSv1.3
Enforcing the use of TLSv1.3 for SSL/TLS connections enhances security by using the latest and most secure encryption protocols. Older protocols like TLSv1.0 and TLSv1.1 have known vulnerabilities and should be disabled.
[/etc/nginx/nginx.conf] ssl_protocols TLSv1.3;
ProFTPD: Critical service config, if allowed by the README file
/etc/proftpd/tls.conf
Create self-signed ssl certificate
Enable TLSEngine
Set appropriate TLS Protocols (TLSv1 TLSv1.1 TLSv1.2)
/etc/proftpd/proftpd.conf
UseIPv6	off
ServerIdent	off
DefaultRoot	~
Umask		077
UseLastlog	on
Include /etc/proftpd/tls.confcd 
User 		non-root
/etc/proftpd/sftp.conf
SFTPEngine on
Port 2222
SFTPAuthMethods publickey
sudo mkdir /etc/proftpd/authorized_keys
sudo ssh-keygen -e -f ~username/.ssh/authorized_keys | sudo tee /etc/proftpd/authorized_keys/username
In the /etc/proftpd/conf.d directory check to make sure there aren’t any rogue config files. If there are, delete them.
FTP: Critical service config, if allowed by the README file
File servers: remove unauthorized file shares & have right group ownership & chmod for shared folders (check Google on how to set group/ownership permissions for shared folders/files correctly)
systemctl shows what services are running (eg. FTP)
You could also use service --status-all for a view all services (use dpkg -la | grep <service> to see what all services do)
install critical services (and keep them on!!!)
ssh commands:
sudo apt install openssh-server
sudo apt install openssh-client
systemctl (start | stop | restart | enable | disable | status) ssh


SSH:
Basicaly remote desktop but linux
To install type sudo apt install openssh-server
And type sudo apt install ssh
use systemctl (start|stop|restart|enable|disable|status) ssh to start or stop SSH
service ssh (start|stop|status) works too
for configuration of ssh go to /etc/ssh/sshd_config:
Port 22
LogLevel VERBOSE
You don't want people to have access to sudo so type: PermitRootLogin no
You want to know what people have been doing so type: LogLevel VERBOSE
You have a public key and a private key so it will only let you in if you have both: PubkeyAuthentication yes
PermitEmptyPasswords no: pretty self explanatory
X11Fowarding no
PrintLastLog Yes: prints data and time of user's last login
StrictMode Yes: Checks file permissions of users files on login
AllowTcpForwarding no: prevents TCP packets to be forwarding unnecessarily
If something is hashed it doesn't run
SSH:
Disable remote root login
Server uses privilege separation
Server shows last login
Server uses verbose logging
/etc/ssh/sshd_config
ClientAliveCountMax 0
rsh-server service has been removed
pure-ftpd service has been removed
postgresql service has been removed
Service: 
Remove CUPS (printing daemon)
Check the services on the system and remove any unnecessary ones.
service --status-all will return a list of running services, make sure to look through these and stop/uninstall/disable unneeded services.
Finding more info on what command the service runs:
Find service list using service –status-all
Run systemctl –user status <service_name) (e.g. systemctl –user status quarantine-threat)
Loaded will provide location of the .service file, which contains the command info
Non-critical services (ex: Apache2) may be scored during the AFA Rounds as unwanted software. Remove any servers that are not needed
systemctl start rsyslog




Programs
Do not track header for programs:
Disable Thunderbird (or, do sudo grep -r donottrackheader /etc) do not track header
privacy.donottrackheader.enabled = true → change to false
Set in /etc/thunderbird/* or ~/.thunderbird/*
VS code extensions:
Remove Malicious VScode extension
Remove the extension from inside vscode
Or rm -rf ~/.vscode/extensions/siliconhills.pass-0.0.1





Sudo & Sudoers config
check all sudo files, diff with plain image
tty not required for sudo?
In /etc/sudoers.d remove the line with "default !authenticate"
Look for bad stuff inside /etc/sudoers.d/*** files
Sudoers config (/etc/sudoers)
Change NOPASSWD:ALL to PASSWD:ALL
Change Defaults !authenticate to Defaults authenticate
Change Defaults !tty_tickets to Defaults tty_tickets
Change Defaults !use_pty to Defaults use_pty
Remove Defaults env_keep+=LD_PRELOAD
Make sure no bad service gets to run with NOPASSWD
Sudo:
Disable developer mode: /etc/sudo.conf (Set developer_mode false)
Remove Defaults env_keep+=LD_PRELOAD in /etc/sudoers
Remove “!” from Defaults !use_pty in /etc/sudoers
Remove Defaults !authenticate in /etc/sudoers
Users in the sudo group are not allowed to sudo without a password
“sudo gedit /etc/sudoers”  
- Change NOPASSWD: ALL ➜ PASSWD: ALL



Firewall
If not already installed:
sudo apt install ufw
sudo nano /etc/ufw/before.rules
:ufw-http-logdrop - [0:0]
enable & set full logs
check blocking/host rules & settings in /etc/ufw/ufw.conf (e.g. LOGLEVEL=high)
netstat -tulpna for open ports
enable firewall by : sudo ufw enable
iptables service keeps track of firewall options
Iptables:
apt install iptables
Commands:
iptables
command to manipulate the iptables firewall (for IPv4)
iptables6
the command to manipulate the iptables firewall (for IPv6)
ufw
the command to manipulate the Uncomplicated FireWall
gufw
 launches the GUI for the ufw 
iptables/ip6tables command options:
-A chain rule-specification : append the rule to the specified chain
-j, --jump target : This specifies the target of the rule; i.e., what to do if the packet matches it.
man iptables or  man ip6tables for more command options (there’s a lot more)
iptables/ip6tables target actions:
ACCEPT - Accept the packet and stop processing rules in this chain.
REJECT - Reject the packet and notify the sender that we did so, and stop processing rules in this chain.
DROP - Silently ignore the packet, and stop processing rules in this chain.
LOG - Log the packet, and continue processing more rules in this chain. Allows the use of the --log-prefix and --log-level options.
iptables/ip6tables commands:
Adding Rules (-A):
sudo iptables -A INPUT -j LOG
sudo iptables -A FORWARD -j LOG
sudo ip6tables -A INPUT -j LOG
sudo ip6tables -A FORWARD -j LOG
Adding Policies (-P):
sudo iptables -P INPUT DROP
sudo ip6tables -P INPUT DROP
Save iptables rules after restarting:
touch /etc/iptables.rules
iptables-save > /etc/iptables.rules
iptables-restore < /etc/iptables.rules
$ netstat -plaunt
$ systemctl --status-all



UFW:
sudo ufw enable
Host configuration security:
sudo nano /etc/host.conf
nospoof on
sudo nano /etc/hosts.deny
ALL: ALL
Or, do “sudo apt install gufw” and set via UI of “gufw”
sudo ufw logging high
In /etc/default/ufw:
IPV6=no
To allow a port through firewall, use “ufw allow <port>” *(or, gufw for GUI based config)
Any additional configurations??
/etc/ufw/before.rules: ufw-http-logdrop [0:0] --> UFW protects against DOS attacks
iptables-persistent installed and started 
netfilter-persistent service started

Audit 
install/enable, check if running, 
add stig configs in audit rules
/var/tradesecret monitoring enabled?
Audit Rule Configuration:nano 
sudo apt install auditd
Log successful logins???????????????????
Update /etc/audit/rules.d/audit.rules and then run “sudo auditd restart”
-w {}
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete
-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng
-w /var/log/tallylog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k priv_cmd
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -k perm_chng
-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-passwd 
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix-update 
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng 
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-pam_timestamp_check 
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-crontab 
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-usermod 
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-chage
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-gpasswd
-w /etc/passwd -p wa -k usergroup_modification
-w /etc/group -p wa -k usergroup_modification 
/etc/audit/auditd.conf:
action_mail_acct = root



APT
Software:
Package management, to install software and programs, we use package managers. In Ubuntu, the package manager is APT. Package managers allow us to install, remove, and upgrade different softwares that we want!
Ok let's talk about some of the advantages
In linux we take all of our common softwares and centralize them by putting them on servers. The packages that are stored on those servers are called "repositories," these packages are commonly used and approved by the community. Package managers simply pull from these servers and their repositories in order to maintain installed softwares and new software.
Because softwares often require other packages on linux or what's called "dependencies," package managers are made to find dependencies for you.
And guess what? Having everything in one place makes it extremely easy to install these dependencies, because packages are kept in a centralized place. 
Apt also automatically does security updates for your packages, so you don't have to go manually update all of your applications one by one.
Other package managers:
pip
yum
npm
snap
We want to make sure that there are no unauthorized softwares that are bad, because people could potentially use the packages on a system to exploit the system. 
You can mainly use common sense, and you'll develop a security mindset when you do more practice
APT commands:
Update repositories with `apt update`
Upgrade all packages with `apt upgrade`
Install a package with `apt install <package_name>`
Remove a package with `apt remove <package_name>`
Remove a package the cool way with `apt --purge autoremove <package_name>`
Just removes unneeded packages and any configuration files associated with the specified package. 
Be careful not to confirm unless you’ve made sure that you’re not accidentally autoremoving an important package
If you’re unsure what a package does, Google it!
clean cache / update / upgrade
check sources and diff with clean image to make sure source list is complete & good
add rules and right configs and then update/upgrade
check packages on hold (apt-mark showhold) and remove the hold (apt-mark unhold <name>)
Other
Change /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "14"
APT using certificate verification
Ensure that all packages installed are digitally signed using a certificate that is recognized and approved. This basically means that packages are verified, and if set to true, could compromise the system with unauthorized packages (malware) getting installed.
APT::Get::AllowUnauthenticated "false";

The system automatically checks for updates daily
APT::Periodic::Update-Package-Lists “1” in/etc/apt/apt.conf.d/20auto-upgrades
/etc/sources.list
Remove unauthorized sources
/etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "14"
Lock Issue: killall dpkg or remove lock file -> rm /var/lib/dpkg/lock*
Files to change:
/etc/apt/sources.list
/etc/apt/sources.list.d/*
Copy default lines for these files and overwrite competition images (we know that every year, especially on Debian, they mess with these files)
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades
/etc/apt/apt.conf.d/50unattended-upgrades:
Acquire::AllowInsecureRepositories "false"
Acquire::AllowDowngradeToInsecureRepositories "false"; #APT is not permitted to downgrade to insecure repositories
Unattended-Upgrade::Mail "root" (should not have any other user listed here)
APT::Periodic::Update-Package-Lists \"1\";"
APT::Periodic::Unattended-Upgrade \"1\";"
/etc/apt/apt.conf.d/20auto-upgrades:
Other:
grep AllowUnauthenticated /etc/apt/apt.conf.d/*, and make sure APT::Get::AllowUnauthenticated "false"
Script command example, to append value in a file:
echo "APT::Periodic::Update-Package-Lists \"1\";" >> /etc/apt/apt.conf.d/50unattended-upgrades 
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades

Packages
install good ones (all antivirus, and run them, clamav, linis, debsums, others), iptables/persistent etc
Updates
apt get update
Update check settings: Subscribe to “All updates” -> “Daily”
remove bad ones.. make sure the script is updated based on info from PR4 (Nginx, SMTP, p0f, minetest, torsocks) and older PRs
remove bad snaps, check "grep -v canonical" to see extra ones which might be bad
bad snaps: games, cncra, spotify etc from canonical might be unnecessary too, remove them
Bad packages
reaver, pixfrogger, featherpad, cowsay, apache2, kollision, packit, unbound, dnsrecon, cups, nginx, nmap, yersinia, ruby, rails, xinetd
Non-needed packages:
VScode, spotify, kollision
Bad packages to remove: rsh-server, pure-ftpd, PostgreSQL, finger, nikto, moon-buggy, tmnationsforever
Nikto: web server scanner
Finger: Potentially useful for finding user information on a remote system
Moon-buggy: video game
tmnationsforever: video game
Manage software and applications [Refer to Safin’s Tutorial]
Remove unauthorized applications such as password cracking utilities, exploitation frameworks, or video games.
Install required software such as office work utilities.
Run software-properties-gtk
sudo apt update
sudo apt upgrade
Lock Issue: killall dpkg or remove lock file -> rm /var/lib/dpkg/lock*
Remove bad packages
dpkg:
dpkg -l | more
Use the command dpkg --list | grep -Ei 'freeciv|telnet|wireshark|binwalk|weevely|goldeneye|john|medusa|hydra|dsniff|cain|ophcrack|p0f|hping3|minetest|moon-buggy|netcat-*|nikto|deluge|yersinia|transmission|ruby-net-telnet|sl|pyrit|sendmail|aircrack-ng|aiseriot|nsnake|httpry|nmap|poll|vulner|t50|dirb|crack|’sniff’|password|intrusion|server|postgresql|reaver|apache2|cups|reaver|pixfrogger|featherpad|cowsay|apache2|kollision|packit|unbound|dnsrecon|cups|nginx|nmap|yersinia|spotify|vscode|popularity-contest'
sudo apt autoremove --purge reaver pixfrogger cowsay apache2 featherpad kollision packit unbound dnsrecon cups nginx nmap yersinia ruby rails xinetd freeciv telnet wireshark binwalk weevely goldeneye john medusa hydra dsniff ophcrack p0f hping3 minetest moon-buggy netcat nikto deluge yersinia transmission ruby-net-telnet sl sendmail aircrack-ng nsnake httpry nmap t50 dirb crack postgresql reaver apache2 cups reaver cain aisleriot
Remove all bad packages in this using “sudo apt –purge autoremove <package>” 
use dpkg -l | grep -iE 'hack|crack|pass|swiss|stealth|dos|game|credit|secret|backdoor'
apt purge vsftpd tcpdump recon-ng binwalk dnsenum minetest ncrack postgresql
snap:
snap list
snap remove <name> (Don’t remove Linux packages - canonical)
remove games: sudo apt --purge autoremove <package_name>

Packages: 
Install: debsums, debsecan, libpam-google-authenticator (only if 2-factor authentication is needed per the readme)
Run debsecan for clues
sudo apt autoremove --purge aircrack-ng nikto john hydra medusa wireshark netcat-traditional httpry nginx dsniff finger moon-buggy tmnationsforever
sudo apt autoremove --purge geoclue-2.0 net-tools rhythmbox tnftp totem transmission-gtk transmission-common
apt-mark showmanual to show manually installed packages
Description:
Nginx (web server)
httpry (sniffing tool)
dsniff (sniffing tool)
Package managers:
sudo yum remove a b c
apt autoremove –purge a b c
rpm (CentOS is based on RedHat, it uses rpm instead of dpkg)
Check installed: run rpm -qa --last
Dpkg
Install Fail2Ban
Install zbar_tools to batch process qrcode images 
Script to use:

AIDE:
sudo apt install aide
Unauthorized software freeciv / slowhttptest / mdk3 removed
Each of these packages are hacking tools and should be removed accordingly with `apt purge freeciv slowhttptest mdk3`.
List packages
$ dpkg -l | awk '{print $2}'
Filter packages for certain things
$ dpkg -l | grep -i crack
$ dpkg -l | grep 'sniff'
$ dpkg -l | grep password
$ dpkg -l | grep intrusion
$ dpkg -l | grep server


Remove known bad packages (black list)
$ apt-get purge -y freeciv telnet wireshark binwalk john john-data medusa hydra dsniff wireshark cain ophcrack p0f hping3 minetest moon-buggy netcat-* nikto deluge yersinia transmission ruby-net-telnet sl pyrit sendmail aircrack-ng aiseriot nsnake httpry nmap
$ apt-get autoremove --purge zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist xserver-xorg* xserver-xorg-core*
$ apt-get autoremove --purge xinetd ettercap-common ettercap-dbg ettercap-graphical ettercap-text-only
You can also use either meld or diff to compare the packages installed on a round's image with a default image:
$ dpkg -l | awk '{print $2}' > default # do on clean image once
$ dpkg -l | awk '{print $2}' > current # do on normal round image
$ diff default current | grep ">" # finds the packages only in current file
Remove critical services from this list
$ apt-get purge apache2 samba postgresql vsftpd bind9*
sudo apt autoremove --purge apport
sudo apt autoremove --purge slapd
sudo apt autoremove --purge xonotic
sudo apt autoremove --purge pacman4console
sudo apt autoremove --purge lighttpd


Grub
Add password for GRUB:
grub-mkpasswd-pbkdf2
Script (test to make sure it doesn’t break the bootloader):
Copy the password hash, and put it along with the following configurations into [/etc/grub.d/00_header]
cat << EOF
set superusers=root
password_pbkdf2 root <Copied Hash>
EOF     
set .conf rules and config for default_cmd_line and cmd_line for audit, slab_nomerge, etc
/etc/default/grub
GRUB_CMDLINE_LINUX_DEFAULT="quiet page_alloc.shuffle=1"
sudo update-grub → to apply changes
GRUB_CMDLINE_LINUX_DEFAULT="apparmor=1 security=apparmor slab_nomerge slub_debug=FZP init_on_alloc=1 init_on_free=1 mce=0 pti=on mds=full,nosmt module.sig_enforce=1 oops=panic vsyscall=none page_alloc.shuffle=1 randomize_kstack_offset=on spec_store_bypass_disable=on page_poison=1 iommu.passthrough=0 iommu.strict=1 mitigations=auto,nosmt kfence.sample_interval=100 vdso32=0 cfi=kcfi quiet loglevel=0 splash debugfs=off lockdown=confidentiality ipv6.disable=1 amd_iommu=on efi=disable_early_pci_dma"
Do this after making any grub changes.
sudo grub-mkconfig /boot/grub/grub.cfg
sudo grub-mkconfig -o /boot/grub/grub.cfg
sudo Update-grub
Edit the files in /etc/grub.d/* or /etc/default/grub after you run update-grub, /boot/grub/grub.cfg will contain all configurations in /etc/grub.d/* or /etc/default/grub
There are variety of things you can do for grub:
Password Encryption
Restrict Single User Mode
Grub disables slab merging
/etc/default/grub: in the GRUB_CMDLINE_LINUX_DEFAULT line:
GRUB_CMDLINE_LINUX_DEFAULT=”quiet splash slab_nomerge”
Add following at end of GRUB_CMDLINE_LINUX: 
module.sig_enforce=1
debugfs = off
audit = 1

Networking
Check for bad stuff running from under /etc/network/if-up.d/ethtool or similar files
Research on how to config /etc/network/interfaces for proper security settings (e.g. iface eth0 inet static to disable DHCP)

/etc/fstab
Add in /etc/fstab:
tmpfs                   /tmp                tmpfs   defaults,nosuid,noexec,nodev,rw 0 0
Password policies
Install pam_pwquality
/etc/pam.d/common-password
password	requisite			pam_pwquality.so retry=3 minlen=15 difok=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 dictcheck=1 gecoscheck minclass=3 reject_username
password	requisite			pam_pwhistory.so retry=3 minlen=15 difok=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 gecoscheck minclass=3 reject_username
password	requisite			pam_unix.so retry=3 minlen=15 difok=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 gecoscheck minclass=3 reject_username
password	[success=1 default=ignore]	pam_unix.so obscure use_authtok try_first_pass yescrypt shadow
diff the folder of pam.d and login.def file with plain image, make sure nullok_secure (or none), pam_deny, password complexity etc settings are made in right files
research to make sure all secure settings are added in right files, from past PRs and from Google research for what all secure/hardening settings must go in those files
even though pam.d enabled, there will be some changes needed in /etc/security/pwquality.conf (e.g. maxrepeat=3 etc)
Run:
apt-get install libpam-pwquality
nano /etc/pam.d/common-password
password	required	pam_unix.so obscure sha512 remember=12 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 maxrepeat=3
password	required	pam_pwquality.so retry=3 remember=24
KEEP ABOVE AFTER REQUISITE
STIG vulnerability ID V-4346
Remove any references to pam_console.so module from files:
grep pam_console.so /etc/pam.d/*
grep -r /pam/console.so /
Remove all references to this file
Delete below file:
sudo find / -iname "console.perms"
sudo rm /etc/security/console.perms
PAM setting: local_users_only
/etc/pam.d/common-auth: 
deny = 3


auth requisite pam_deny.so -> /etc/pam.d/common-auth (DON'T PUT PAM_ALLOW.SO)


use pam_faillock (new) in common-auth as compared to pam_tally (old)
KEEP AFTER REQUISITE OR ELSE WON’T WORK
set min/max/expiry password info for users



Kernel config
Things like net.ipv4.ip_forward = 0
Set in /proc/sys/net/ipv4/ip_forward
make full list for all parameters on website
Configuring secure kernel parameters
https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/
add config for extra stuff like yama etc.. check PR4 /proc/sys & Google for more info on such configs
Other config (see PR4 for some clue) in /etc/sysctl.d/*.conf files: Check what is 10-, 50-, 99- etc priority vs /etc/sysctl.conf and where must the latest config be placed..
10-console-messages.conf
10-kernel-hardening.conf
10-network-security.conf
10-zeropage.conf
10-ipv6-privacy.conf
10-magic-sysrq.conf
10-ptrace.conf
99-sysctl.conf
/etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
kernel.exec-shield = 1
kernel.randomize_va_space = 2
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv4.ip_forward=0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.lo.disable_xfrm = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
vm.swappiness = 10
net.ipv4.tcp_timestamps = 0
kernel.ctrl-alt-del = 0
fs.protected_symlinks = 1
#Prevent malicious FIFO writes
fs.protected_fifos = 2
vm.unprivileged_userfaultfd = 0
kernel.sysrq=1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.send_redirects = 0
kernel.perf_event_paranoid = 2
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0
kernel.watchdog = 1
net.ipv4.tcp_sack = 0
vm.memory_failure_early_kill = 1
dev.tty.ldisc_autoload = 0
fs.protected_hardlinks  =1
fs.suid_dumpable = 0
kernel.yama.ptrace_scope = 3
sysctl -p → Do after changing the file to apply changes
PAM
Authentication is required for using the 'su' command
Authentication is required for using the 'sudo' command
sudo nano /etc/pam.d/login:
Add: account required pam_access.so
IPv4 source route verification enabled
Protected hardlinks enabled
SUID core dumps disabled
Minimum virtual memory address mapping set to non-zero value
IPv4 source route verification enabled
net.ipv4.conf.all.rp_filter = 1

Why?
This setting helps protect against IP address spoofing attacks. When enabled, it verifies the source of incoming packets, ensuring that they come from the expected route and preventing attackers from forging packet sources.
Protected hardlinks enabled
fs.protected_hardlinks = 1

Why?
Protecting hard links helps prevent privilege escalation attacks. When enabled, it restricts the creation of hard links for files owned by other users, reducing the risk of malicious exploitation.
SUID core dumps disabled
fs.suid_dumpable = 0

Why?
Disabling SUID (Set User ID) core dumps enhances security by preventing privileged programs that have crashed from creating core dump files. This reduces the potential for sensitive information leakage.
Minimum virtual memory address mapping set to non-zero value
vm.mmap_min_addr = [4000-9999]

Why?
Setting a non-zero value for the minimum virtual memory address mapping helps mitigate attacks that rely on accessing low-level memory addresses. This prevents malicious processes from manipulating system memory in dangerous ways.
Note: It may seem that /bin/true enables the modules, it disables them as it holds the value of 0 which is false in binary
Disable USB Storage detection
Important files
/etc/modprobe.d/usb-storage.conf
/etc/modprobe.d/modprobe.conf
/etc/modprobe.conf
Add
install usb-storage /bin/true
Disable Bluetooth Module
Important files
/etc/modprobe.d/bluetooth.conf
/etc/modprobe.d/modprobe.conf
/etc/modprobe.conf # You want to put most of your settings here
Add
install net-pf-31 /bin/true
install bluetooth /bin/true
Other Kernel Modules that are insecure/unnecessary
install freevxfs /bin/true
install appletalk /bin/true
install gfs2 /bin/true
install udf /bin/true
install ceph /bin/true


Browser
update to latest version, make sure on their website that it’s indeed the latest version
set all UI options, remove extensions
Firefox Hardening Guide 2024 (brainfucksec.github.io) → Very detailed. See if these can be scripted.
Firefox about:config setting: geo.enabled = false
implement stigs for different browsers, they have instructions on how to update the conf/policy files. many settings will probably work from only the config files, see stigs xls for instructions. Also, conf changes are easy to script
UI also has config:policies etc, look at that too
to upgrade firefox: first sudo apt update, then sudo apt install firefox. You can also do it from help > about Firefox
Firefox blocks pop-up windows
Firefox blocks pop-up windows
Blocking pop-up windows in the Firefox web browser enhances security by preventing potentially malicious or intrusive pop-up advertisements and scripts.
Firefox settings > Privacy & Security > Permissions > Block Pop Up Windows


Firefox
A profile can be imported by importing it into .mozilla and changing the default profile in profiles.ini
Set min TLS version to 1.3 or greater 
Enable ‘safe browsing’
Check (about:config, Preferences) → enter “about:config” in address bar
Example Configurations:
Firefox pop-up blocker enabled
Menu > Options > Security > Block pop-up windows
Firefox warns you when websites try to install add-ons
Menu > Options > Security > Warn you when websites try to install add-ons
Firefox blocks 3rd party cookies
Menu > Options > Security > Content Blocking > Third-party Cookies; All third-party cookies (may cause websites to break)
Firefox blocks dangerous and deceptive content
Menu > Options > Privacy & Security > Security > Deceptive Content and Dangerous Software Protection
Firefox Does not send your data to firefox	
Menu > Options > Security > (scroll down to “firefox data collection and use”)
uncheck all boxes



Hit checkboxes with good stuff in about:preferences


Firefox pop-up blocker enabled
Menu > Options > Security > Block pop-up windows 


Firefox warns you when websites try to install add-ons
Menu > Options > Security > Warn you when websites try to install add-ons


Firefox blocks 3rd party cookies
Menu > Options > Security > Content Blocking > Third-party Cookies; All third-party cookies (may cause websites to break) 


Firefox blocks dangerous and deceptive content
Block Dangerous Downloads
Warn you about unwanted and uncommon software
Menu > Options > Privacy & Security > Security > Deceptive Content and Dangerous Software Protection
Firefox Does not send your data to firefox
Menu > Options > Security > (scroll down to “firefox data collection and use”) uncheck all boxes


“files” to change:


about:config 
about:support 
about:preferences


/etc/firefox/syspref.js
Add settings from this github, change user_pref to pref
https://github.com/pyllyukko/user.js/blob/master/user.js


stigs: 
https://www.stigviewer.com/stig/mozilla_firefox/


user.js configure settings for about:config
Format:
user_pref("setting", value);
Firefox: (about:config, Preferences):
geolocation service disabled
Firefox minimum TLS version set to 1.3
Firefox safe browsing enabled
Firefox: try "custom" instead of "strict":
privacy.trackingprotection.fingerprinting.enabled “true”
browser.safebrowsing.malware.enabled "true"
If firefox can't be upgraded to latest automatically, check .sources file for any issues finding the update from Ubuntu. Or, install only the Firefox update from its Personal Package Archive (PPA) as follows. PPA is for users to install third party software not published in Ubuntu package repo, and are generally used to test pre-release/beta software.
sudo add-apt-repository ppa:mozillateam/ppa
apt install --only-upgrade firefox


Firefox STIGS
Add the following in the policies section of "policies.json" file:

-----------------------------------------------------
"DisableDeveloperTools": true"
"DisableFeedbackCommands": true"
"DisableFirefoxAccounts": true"
"DisableFirefoxStudies": true"
"DisableForgetButton": true"
"DisableFormHistory": true"
"DisablePocket": true"
"DisablePrivateBrowsing": true"
"DisableTelemetry": true"
"DNSOverHTTPS": {"Enabled": false}
"ExtensionUpdate": false"
"NetworkPrediction": false"
"PasswordManagerEnabled": false"
"SearchSuggestEnabled": false"
"SSLVersionMin": "tls1.3"

"EnableTrackingProtection": {
  "Fingerprinting": true
}

"EnableTrackingProtection": {
  "Cryptomining": true
}

"SanitizeOnShutdown": {
  "Cache": false,
  "Cookies": false,
  "Downloads": false,
  "FormData": false,
  "History": false,
  "Sessions": false,
  "SiteSettings": false,
  "OfflineApps": false,
  "Locked": true 
}

"FirefoxHome": {
  "Search": false,
  "TopSites": false,
  "SponsoredTopSites": false,
  "Pocket": false,
  "SponsoredPocket": false,
  "Highlights": false,
  "Snippets": false,
  "locked": true
}

"InstallAddonsPermission": {
      "Default": false
}

"PopupBlocking": {
      "Allow": ["http://example.mil/",
                "http://example.gov/"],
      "Default": true,
      "Locked": true
}

"UserMessaging": {
  "ExtensionRecommendations": false
}

"DisabledCiphers": {
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA": true
}

"EncryptedMediaExtensions": {
  "Enabled": false,
  "Locked": true
}

"Permissions": {
  "Autoplay": {
    "Default": "block-audio-video"
  }
}

"Preferences": {
  "security.default_personal_cert": {
    "Value": "Ask Every Time",
    "Status": "locked"
  }
}

"Preferences": {
  "browser.contentblocking.category": {
    "Value": "strict",
    "Status": "locked"
  }
}


"Preferences": {
  "dom.disable_window_flip": {
    "Value": true,
    "Status": "locked"
  }
}

"Preferences": {
  "dom.disable_window_move_resize": {
    "Value": true,
    "Status": "locked"
  }
}

"Preferences": {
  "browser.search.update": {
    "Value": false,
    "Status": "locked"
  }
}

"Preferences": {
"extensions.htmlaboutaddons.recommendations.enabled": {
"Value": false,
"Status": "locked"
},”


Crontab
Diff with plain image, scroll till end of the file, don't ignore simple stuff
ps -aux & top check for bad stuff
/etc/crontab - for scheduled jobs
Scroll end of the file to find hidden lines
Netcat
Bad command: nc -lvn 4343 &
Hacker can change binary name (nc to cn)
PS - process information
Find a running process: ps -aux | grep <name>
Kill: kill -9 <pid>
Init process: PID 0
Cron locations
/etc/crontab
/etc/cron.d/*
/etc/cron.hourly/*
/etc/cron/daily/*
/etc/cron.weekly/*
/etc/cron/monthly/*
/var/spool/cron/crontabs/*
find cron jobs by using crontab -e or by going to /etc/crontab
crontab isn't malicious by itself
Cron:
Check /etc/cron.d/<folder> for bad stuff and remove

files to change:


Check for unauthorized cronjobs or default cronjobs that run unauthorized tasks
/etc/cron.d/* - anacron, debsecan, .placeholder
/etc/cron.daily/* - 0anacron, aide, apache2, apport, apt, bsdmainutils, chkrootkit, cracklib-runtime, debsums, dpkg, logrotate, man-db, mlocate, passwd, popularity-contest, update-notifier-common, upstart, .placeholder
/etc/cron.monthly/* - 0anacron, debsums, .placeholder
/etc/cron.weekly/* - 0anacron, apt-xapian-index, debsums, fstrim, man-db, update-notifier-common, .placeholder
/etc/cron.hourly/* - .placeholder
/etc/crontab - contains scoring engine, plus commands running all the other cron folders/files
/var/spool/cron/crontabs/*
Make sure to check for hidden files in each crontab directory (ls -a)
Look in each file in the crontab directories to find potentially bad files
	$cat <file>


Sometimes in the bottom of the file may have a hidden cronjob


Search for crontabs based on date modified, running processes (ps -aux, netstat -plunt)
cronjob locations: 
/etc/crontab
/etc/cron.d/*
/etc/cron.hourly/*
/etc/cron/daily/*
/etc/cron.weekly/*
/etc/cron/monthly/*
/var/spool/cron/crontabs/*


/etc/crontab: remove last line
/var/spool/cron/crontabs/root: remove line which is emailing /etc/passwd
/etc/bash_completion.d/system.sh
/lib/systemd/system/modify-system.service


Backdoors
Diff /etc and look for files under /opt, /etc/gdm3/PreSession etc. Check for .sh or.py running under /etc
Check for bad services
Steps to find bad files and get points:
netstat -plantu > Check bad things running (e.g. perl or python script)
Check ps -aux for more details of above bad program
Now, search common places for scripts to be run from. Use [grep -rnw “[common directories]” -e “perl -e”]
Now you would get the script [/usr/bin/sysmond] containing the one-liner, but the script can’t be running itself so next thing you should search for common places scripts are run from [cron, services, init (/etc/systemd/system), etc]
Through some grepping you find /etc/systemd/system/sysmond.service which was periodically running /usr/bin/sysmond
To get points, kill the process using kill -9 [PID], delete script, and delete the lines from any files/places where the script is called from. If no points, delete the bad file from where the bad script is called. Delete the service that runs the script.
See service status compared to plain image
systemctl list-unit-files --type=service
systemctl list-unit-files --type=service | grep generated
Ps tree display
ps axjf
ps auxfww
Network activity monitoring:
netstat -plaunt (p/program, l/listening, a/all, u/udp, n/numeric, t/tcp. Add v/verbose, c/continuous)
lsof -p <pid>
ss -atp (a/all, t/tcp, p/processes)
Any of the above commands can be put to execute every 1 seconds with command:
watch n 1 “command”
Check for unauthorized keys under ~/.ssh/
Check for file permissions (suid, guid etc)
Check files with special capabilities
Check bad commands under services (cat /etc/system.d/system/*.service | grep -i exec)
E.g. from under /etc/apt/apt.conf.d/ folder
Check for Pre-Invoke, nohup etc keywords in file system to see processes bring forked

Bad files
media, txt, scripts
apt install mlocate
sudo locate *.mp3 (or any file type)
File/folder can’t be deleted by sudo/root if it’s immutable. Check via lsattr, and remove the attribute via “chattr -i” command for that file/folder to enable deletion via root.
Use ls -alR /home to find weird media files in home
Check based on names: crack, pwd, pass, bank, hack etc..
Check based on type: zip, rar, bz2, tar, gz, gzip etc
Typically under /home, but could be elsewhere in / too
Files with name .bak ??? (e.g. /etc/issue.bak ??)
Unauthorized media:
Images: jpg, bmp, png, jpeg
Audio: wav, mp3, aud
Video: mp4, wmv, avi
Remove malware and unauthorized multimedia
Multimedia files such as MP3s, MP4s, PNGs, etc. should be removed from the system if they are not necessary.
Backdoors and persistence mechanisms should also be removed from the system.
Remove bad files (media, sensitive information)
cd /home → ls -al *
ls /etc (File with - at end of file name is system generated backup, but others are not. Example: passwd- is ok, but paswd- is not and need to delete)
To rename the file (rm will delete, not good) : mv <filename> (or sudo rm)
sudo find / -type f -name "*.aif" -o -name "*.iff" -o -name "*.m3u" -o -name "*.m4a" -o -name "*.mid" -o -name "*.mp3" -o -name "*.mpa" -o -name "*.ra" -o -name "*.wav" -o -name "*.wma" -o -name "*.3g2" -o -name "*.3gp" -o -name "*.asf" -o -name "*.asx" -o -name "*.avi" -o -name "*.flv" -o -name "*.m4v" -o -name "*.mov" -o -name "*.mp4" -o -name "*.mpg" -o -name "*.rm" -o -name "*.srt" -o -name "*.swf" -o -name "*.vob" -o -name "*.wmv" -o -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.bmp"
tree -fa | grep -v <user>
sudo apt --purge autoremove netcat-openbsd (TCP/IP swiss army knife)		
Forbidden Files:
Media Files:
.mp3, .mp4, .avi, .wav, .png, .jpg, .wma, .ogg
Hacking Tools or archives:
.tar, .zip, .gz
Backdoors
.sh, .php, .py, .c
Private Info
Misc (Anything not necessary on systems)
cat the files to see if calling other files
If backdoor found or anything suspicious, rename the file because it might be system essential.

Bad files:
Find
sudo find / -iname "*secret*"
sudo tree -a 
Media files: *.ogg, *.aac, *.opus, *.mp3
Other files: anything under home directory.. Esp password info etc.
Check for bad shell (.sh) or python (.py) files in /etc, /opt, /home /srv or /.
Check for bad or corrupted binary files in /bin or /usr/sbin or /usr/bin/


You can find corrupted packages using apt list –installed | grep <keywords> | grep <other> |...
Google package location for example /usr/lib/python3/dist-packages/apt for python3-apt package.
Check out .py files within the packages to look for any suspicious code. 
Binaries:
Remove fake binaries
good commands to run:
Search for media file of a certain type: $ sudo locate *.(type of file)
Search for media file of a certain type: $ sudo find / -iname "*.FILE_EXTENSION1" -o -name "*.FILE_EXTENSION2"
Search by file type: $ sudo find /etc /home /root | xargs file --mime-type {} \; 2> /dev/null | grep "image/\|video/\|audio/"


files to change:


.mp3 files and .mp4 files
The following are all media file extensions: "*.m3u"  "*.M3U"   "*.m4a"  "*.M4A"  "*.mid"  "*.MID"  "*.mp3"  "*.MP3"  "*.mpa"  "*.MPA"  "*.wav"  "*.WAV"  "*.wma"  "*.WMA"  "*.3g2"  "*.3G2"  "*.3gp"  "*.3PG"  "*.asf"  "*.ASF"  "*.avi"  "*.AVI"  "*.flv"  "*.FLV"  "*.m4v"  "*.M4V"  "*.mov"  "*.MOV"  "*.mp4"  "*.MP4"  "*.mpg"  "*.MPG"  "*.rm"  "*.RM"  "*.srt"  "*.SRT"  "*.swf"  "*.SWF"  "*.vob"  "*.VOB"  "*.wmv"  "*.WMV" 


Dangerous command, try not do do: files with passwords or passwd/shadow copies
passwdmd5 = $(md5sum /etc/passwd)
shadowmd5 = $(md5sum /etc/shadow)
sudo find / -type f -exec md5sum {} + | grep -E '^$passwdmd5|^$shadowmd5' 2>/dev/null




Remove files with keywords such as “password”, “hack”, “virus”, etc.


"*.aif" -o -name "*.iff" -o -name "*.m3u" -o -name "*.m4a" -o -name "*.mid" -o -name "*.mp3" -o -name "*.mpa" -o -name "*.ra" -o -name "*.wav" -o -name "*.wma" -o -name "*.3g2" -o -name "*.3gp" -o -name "*.asf" -o -name "*.asx" -o -name "*.avi" -o -name "*.flv" -o -name "*.m4v" -o -name "*.mov" -o -name "*.mp4" -o -name "*.mpg" -o -name "*.rm" -o -name "*.srt" -o -name "*.swf" -o -name "*.vob" -o -name "*.wmv"


 "*.webm" -o -iname "*.mkv" -o -iname "*.flv" -o -iname "*.vob" -o -iname "*.ogv" -o -iname "*.ogg" -o -iname "*.drc" -o -iname "*.gif" -o -iname "*.gifv" -o -iname "*.mng" -o -iname "*.avi" -o -iname "*.mov" -o -iname "*.qt" -o -iname "*.wmv" -o -iname "*.yuv" -o -iname "*.rm" -o -iname "*.rmvb" -o -iname "*.asf" -o -iname "*.amv" -o -iname "*.mp4" -o -iname "*.m4p" -o -iname "*.m4v" -o -iname "*.mpg" -o -iname "*.mp2" -o -iname "*.mpeg" -o -iname "*.mpe" -o -iname "*.mpv" -o -iname "*.svi" -o -iname "*.3gp" -o -iname "*.3g2" -o -iname "*.mxf" -o -iname "*.roq" -o -iname "*.nsf" -o -iname "*.flv" -o -iname "*.f4v" -o -iname "*.f4p" -o -iname "*.f4a" -o -iname "*.f4b" -o -iname "*.aa" -o -iname "*.aac" -o -iname "*.aax" -o -iname "*.act" -o -iname "*.aiff" -o -iname "*.amr" -o -iname "*.ape" -o -iname "*.au" -o -iname "*.awb" -o -iname "*.dct" -o -iname "*.dss" -o -iname "*.dvf" -o -iname "*.flac" -o -iname "*.gsm" -o -iname "*.iklax," -o -iname "*.ivs" -o -iname "*.m4a" -o -iname "*.m4b" -o -iname "*.mmf" -o -iname "*.mpc" -o -iname "*.msv" -o -iname "*.oga" -o -iname "*.opus" -o -iname "*.ra" -o -iname "*.raw" -o -iname "*.sln" -o -iname "*.tta" -o -iname "*.vox" -o -iname "*.wav" -o -iname "*.wma" -o -iname "*.wv" -o -iname "*.jpeg" -o -iname "*.jpg" -o -iname "*.tif" -o -iname "*.tiff" -o -iname "*.gif" -o -iname "*.bmp" -o -iname "*.png" -o -iname "*.pbm" -o -iname "*.pgm" -o -iname "*.ppm" -o -iname "*.pnm" -o -iname "*.webp" -o -iname "*.hdr" -o -iname "*.bpg" -o -iname "*.ico" -o -iname "*.img" -o -iname "*.aup" -o -iname "*.dmg"


Find prohibited text files:
sudo find / -iname '*.txt'


Common bad files:
/etc/password
creditcards.txt
passwords.txt
*.mp? (CP Rounds: /home/{USERDIR}/Music/*.mp?)
search bad files using keywords: rootkit|swiss|password|secret|credit|bank|backdoor|hack|ddos|terror|violen
bad file *.pdf, *.deb (under downloads)
/usr/lib/passwords
file search by bad file name (not extension)




Policies
If users other than logged in users have more than the default files, then something is wrong about them.
Remove bad policies
/etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf]
Also look at /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
Remove bad rule from /usr/share/polkit-1/rules.d:



Start-up check
In profile, login etc files at different locations
/etc/skel/.bashrc: This is root’s bashrc
umask 077
Bum - for start-up programs
/etc/profile
set “umask 077”
Disable avahi at boot-up:
sudo bum & uncheck avahi-daemon
Or, run “update-rc.d avahi-daemon disable”
Start-up programs check (these get loaded at system start or at login):
Files to check: 
~/.bashrc , /etc/profile, /etc/bash.bashrc , ~/.login , ~/.profile /etc/skel/bashrc /etc/profile.d
Locations to check:
/etc/systemd/system
Other stuff:
Services
Cron
Check for and remove:
Suspicious commands and actions
Bad alias (e.g. alias sudo “ls” → maps sudo to ls). Run unalias <command> to remove the alias, and remove the alias command from the file
Check logs at /var/log (dmesg is for kernel log, check for start-up issues.. There are other logs too that can be checked for issues)


File size
Comparison of important file sizes & versions with the plain image file sizes (e.g. repo, bash etc) to see something is compromised


Display Managers
gdm3/lightdm
Disable guest
Disable display of users on login screen
LightDM
/usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf for Ubuntu 14.04 and newer versions or /etc/lightdm/lightdm.conf for Ubuntu 12.04 or older
allow-guest=false
greeter-hide-users=true
To remove remote login:
greeter-show-remote-login=false
Force Allow manual login:
greeter-show-manual-login=true
Disable display of all users list on login screen in CentOS:
sudo mkdir -p /etc/dconf/db/gdm.d
sudo nano /etc/dconf/db/gdm.d/00-login-screen
Add: disable-user-list=true
Disable guest account:
sudo nano /etc/lightdm/lightdm.conf
Add: allow-guest=false
gdm3	
GDM greeter root login disabled
GDM Remote Autologin Disabled
GDM greeter root login disabled
In general, don’t allow root to login in. This is just another piece of the many different steps and ways to locking out the root account. Basically this setting disallows the root user to log in through GNOME Display Manager.
[/etc/gdm3/custom.conf] AllowRoot = false

GDM Remote Autologin Disabled
Disabling remote auto-login through GDM further secures the system by preventing automatic logins over the network, which could be exploited by attackers.
[/etc/gdm3/custom.conf] AllowRemoteAutoLogin = false

GDM
Verbosely log auth requests (how?)
Disallow sessions over network (how?)
Remove PreSession backdoor: Check /etc/gdm3/PreSession/Default 
Disable login user list gdm3:
sudo nano /etc/gdm3/greeter.dconf-defaults
Uncomment
[org/gnome/login-screen]
disable-user-list=true
good commands to run:
-----------------------------------------------------------------------------
|SCREEN SAVER|
sudo gsettings get org.gnome.desktop.screensaver lock-enabled
to check is screensaver is turned on
gsettings set org.gnome.desktop.screensaver lock-enabled true
to turn screen saver on
-----------------------------------------------------------------------------
|LIGHTDM|
sudo apt-get install lightdm
at the beginning of /usr/share/lightdm/lightdm.conf.d/* add (if not already there) before 15.10
[SeatDefaults]
after 15.10
[Seat:*]
-----------------------------------------------------------------------------
|USERS|
Following configs are in: /usr/share/lightdm/lightdm.conf.d/50-unity-greeter.conf for Ubuntu 14.04 and newer versions or /etc/lightdm/lightdm.conf for Ubuntu 12.04 or older
To disable guest:
allow-guest=false
To hide user list:
greeter-hide-users=true
To remove remote login:
greeter-show-remote-login=false
Force Allow manual login:
greeter-show-manual-login=true
-----------------------------------------------------------------------------


files to change:
*remember lightdm is different in different versions of Ubuntu*
---------------------------------------------------------------------------------
Change files in this dir: /etc/lightdm/lightdm.conf (Ubuntu 14)
OR  
/usr/share/lightdm/lightdm.conf.d (Ubuntu 16 and up)
Disable remote desktop
Disable guest login
Disable users shown at login page
/etc/lightdm/users.conf
---------------------------------------------------------------------------------


Websites with info and types of display manager:
https://www.makeuseof.com/tag/choose-switch-linux-display-managers/
/etc/gdm3/custom.conf:
echo "WaylandEnabled = true"


Kernel modules
Lsmod, check stuff under /etc/modprobe.d/ etc check and config/settings
Disable USB detection & media
Disable bluetooth
Disable plug and play, autoplay?
Other Kernel Modules that are insecure/unnecessary

Miscellaneous
active=yes in /etc/audisp/plugins.d/syslog.conf
Rotate audit logs once they reach max file size (do if asked)
$ sudo nano /etc/audit/auditd.conf
Set max_log_file_action = ROTATE
Activate audispd plugin
$ sudo nano /etc/audisp/plugins.d/syslog.conf
Set active = yes
System PATH
Edit /etc/environment to remove temp and bad locations that might contain bad binaries
DHCP client disabled:
sudo nano /etc/network/interfaces
iface eth0 inet static (find the right interface using command “ip a”, e.g. eth0)
Enable screen saver with lock
Limits configuration securing:
/etc/security/limits.conf:
* hard core 0
* hard maxlogins 10
/etc/default/useradd
INACTIVE=35
/etc/default/apport
enabled=0
Whoopsie Configuration
/etc/default/whoopie
report_crashes=false
Check what else goes into /etc/security files like limits.conf and others
/etc/security/access.conf ALL EXCEPT users :ALL
See what is this is for, and which other things like this under /etc need to be enabled similarly
Disable bash shell history
Research on how to harden /etc/default/useradd, /etc/default/apport, /etc/default/whoopsie
software-properties-gtk
Go to Software & Updates > Updates and set Automatically check for updates to Daily
MySQL:
/etc/mysql.conf.d/mysqld.cnf
[mysql]
local-infile=0
Vulnerability scan
Lynis is a security auditing tool for linux. However, if it is on your computer, someone could find vulnerabilities on your system using it. So, remove it after you run it.
Install lynis
apt-get install lynis
Run lynis
lynis -c -Q # -c is checking everything -Q is quick check
Change settings for updates
$ update-manager
review /etc/modprobe.d/custom.conf to see what's in it
/etc/fail2ban/jail.local:
enabled=true
Disabled mounting of appletalk module - 3pts
install appletalk /bin/true >> /etc/modprobe.d/modprobe.conf
Disabled mounting of vfat modules - 3 pts
install vfat /bin/true >> /etc/modprobe.d/modprobe.conf
software update setting UI:
Under "Ubuntu Software", check all boxes for "Downloadable from internet"


FQ info - temp
Transfer these to FQ doc later
Audacity
Spectogram -> Settings/Scale/Max Frequency (24000) → Google CVE ID
Ciphers
rot13.com
https://www.dcode.fr/en
https://cryptii.com
Google: Cipher identifier




Useful commands - temp
Locate a binary:
locate <name>
sudo -s makes you root for the terminal session
touch <file> Creates a file
rm <file> removes a file
nautilus <file> is to view media
nano/vim/gedit <file> edits file
use unzip to unzip an archive
ls (lists the contents in a directory)
cat (outputs file text to system/concatenate)
cd (traverses directories)
pwd (outputs path)
touch (makes it looks like file has been edited)
nano (text editor)
gedit (text editor)
man (manuel)
rm (remove)
run ./path/to/file to run a binary file
dpkg -s <package name>: it provides more verbose info about the package
fcrackzip is a password brute forcer that guesses passwords for zip files
Check current network connections with netstat -tuapn to inspect current network connections. Check for unauthorized programs with an ESTABLISHED or LISTENING socket status.
You can check current processes with ps -aux. Anything in brackets are kernel threads, don't spend time hunting kernel threads.
To get a tree of processes you can use ps -auxf.
You can also use ss -plunt which is basically netstat -tuapn but more information such as the user, uid, and state of the connection.
Delete any unauthorized services that mgiht be listening. You might even find a netcat backdoor listening which will prove that there is a netcat backdoor on your system. Disable or remove any services that are not needed.
Make sure to use the grep -r command to see if there is any suspicious service file in /etc/systemd/system that may be running anything suspicious.
To check everything in every port use:
sudo apt install net-tools
netstat -tulpn
Check malicious program starting arguments using ps -aux
GDB
Use for debugging binaries
gdb <binary>
info functions
info args
Put breakpoint and then run


When trying to read something from encrypted file system
Commands:
ls - This command 'lists' the contents of your present working directory.
pwd - Shows you what your present working directory is.
cd - Lets you change directories. (home)
rm - Removes one or more files.
rmdir - Remove an empty directory.
mkdir - Make a directory.
ps - Provides a list of currently running processes.
cp - Copy a file.
mv - Move a file (this is also used to rename a file. "Moving" it from one file name to another.)
grep - The global regular expression print program lets you search through a file or output of another program.
find - Find a file on the filesystem (100% accurate, but not fast).
locate - Find a file on the filesystem from a cached list of files (Fast, but not 100% accurate).
man - Displays the manual for most commands (including 'man').
clear - clear the screen
sudo - execute a command as another user (default as root)
su - switch user (default to root)
view - Start in read-only mode. You will be protected from writing the files. Can also be done with the "-R" argument.
touch (name of file) - creates file (not necessary)
#(directory) - hides it/sorta recycles it 
ifconfig -a - displays all network ports and ip addresses 
ping host - sends echo required to test connection
w - shows the list of currently logged in users.
whoami - who you are logged in as
exit - Use this to quit the command line shell on a linux system.
uname - shows important information about your system such as kernel name, host name, kernel release number, processor type and various others.
less - view the contents of a file
File Editors:
pico
pico is nano when pico is not installed
nano
An fork of pico, it is easy to use and is copyleft
vi / vim
Try to use this editor when you can, it is found on all* Linux systems by default. Has a learning curve. Has graphical support (gvim)
gedit
A graphical editor. Try to not use this; you may not always have access to a graphical display
emacs
A powerful, extensible editor with both graphical and console support, but has a steep learning curve
Terminal Shortcuts:
Ctrl+C – halts the current command
Ctrl+Z – stops the current command, resume with fg in the foreground or bg in the background
Ctrl+D – log out of current session, similar to exit
Ctrl+W – erases one word in the current line
Ctrl+U – erases the whole line
Ctrl+R – type to bring up a recent command
!! - repeats the last command
exit – log out of current session
Media Files:
sudo apt install tree
sudo tree
Secure Root:
sudo passwd -l root



File Structure
Understanding how to navigate Linux
Everything in linux is a file
To organize those files and have them in a collection, you can have folders! (In linux they are called directories)
The path to a file or directory is where it's located on the system (example: /home/will/cat.mp3)
Every filename in one directory is unique
You can't have two filenames in the same directory
There are two parts to a file name, the name and extension
For example: (e.mp3)
Some important directories that you should know:
"/" - All your files and directories go underneath here, this is your "root" directory (not that actual /root, that's different), generally we use the term root to describe the highest level or privilege
Important subdirectories underneath the root directory
/home - User's home directories, personalized things
/etc - Main configurations for the system and sometimes also the applications
/bin - Binaries and executables (this is how you and your system can run commands to interact with the system)
/tmp - Temporary files
/usr - User related applications, libraries, binaries, and some documentations for 
Local Policies
Local Policies:
This includes patching vulnerabilities in lightDM, GDM, and Sysctl. (more)
Important files:
/etc/sysctl.conf
/etc/lightdm/lightdm.conf
/etc/gdm/custom.conf
Remember to run sysctl -p after configuring your sysctl.conf
Scripting


Bash scripting cheatsheet (devhints.io)
The Complete Guide to Regular Expressions (Regex) - CoderPad
Scripting:
Run These commands to make sure your script will work
Checking for immutable and append only files
lsattr -R / 2>/dev/null | grep -- "-i-"
lsattr -R / 2>/dev/null | grep -- "-a-"
Checking for apt misconfigurations:
/etc/apt/sources.list # Make sure all the default apt repositories are here, this way your updates can actually update properly and you can install things
/etc/apt/sources.list.d
apt-mark showhold # Some packages may be put on hold, this means that certain packages will not be upgraded, this command will list all packages put on hold
Checking for aliases (in both your account and root's account):
Alias
Have script to list whatever shouldn’t be there in standard image
> Files
> File permissions
> Packages
> Cron job config
> Password file configs in pam.d
* Find a way to show the changed items based on timestamp
Have script that takes user IDs as arguments, and sets following for them:
Complex password CyberPatriot1!
Password expiry (min/max days etc.)


Create files with dumps of following from clean image, for use for making scripts:
Kernel config
lsmod
Important directory/file permissions & attributes (will need to create script to dump the info in proper format)
Installed packages
Installed services
Default user accounts info
Default groups info
Default Cron jobs
List of typical files inside the home directories


DON’T BE A SKID
SCRIPTING
What is a script?
Something that uses sequences of instructions or “commands”
Interpreted through a shell (bash, zsh, python3)
Use cases of scripts:
Dependency/software installation
Automation of repetitive tasks
Creation of command-line utilities
Organizing files and filesystems
Setting up environments for software to run on
System wide configs
Why is this important for CyberPatriot?
Often times, we can see ourselves facing challenges such as doing repetitive tasks over and over again. Scripting can aid us in these tasks.
You could theoretically full score instantly
Clown on the farm leaguers pr1 of next year to make it seem like you are hacking
Before scripting, know
The capabilities of your script can only be matched to your knowledge
DO NOT SKID
Using scripts without knowledge on their functionality can lead to problems you can’t even fix
Other important stuff to know
We script in bash
Bash is a scripting language, not a programming language
Make sure to always polish your script before competition
Find balance between what you want to automate and what to do manually
Always start your scripts with the she-bang (#!/path/to/bin) to specify the interpreter. For bash, this is #!/bin/bash.
Automation vs. consistency
Automation
Pros:
Gets stuff done fast
Minimizes human error
Cons
Could lead to undetected problems
Might not catch everything
Consistency
Pros
More supervised
Safer
More likely to catch everything
Cons
Slower
Do not script everything, only what you can do consistently.
BASH
Variables
Declaration:
VariableName=value
Using:
$VariableName
$(command output)
E.g.
echo $VariableOne
echo $(date)
Operators
Logic
&& And
-o/|| OR
! NOT
Comparison
-eq/== EQUAL TO
!= NOT EQUAL TO
-le IS LESS THAN OR EQUAL TO
-ge IS GREATER THAN OR EQUAL TO
-lt LESS THAN
-gt IS GREATER THAN
Math
+, -, /, *, % SELF EXPLANATORY
If, Else, Elif
If statement:
IF <condition>; then
command
ELIF <condition>; then
command
ELSE <condition>;then
command
fi to end the if statements
E.g.
if 1+1==2; then
echo “1+1=2”
elif 1+1==3; then
echo “1+1=3”
else; then
echo “1+1!=2 and 1+1!=3”
fi
Loops
For loop
E.g.	
for i in {1..5}; do
Echo $i
done


While loop
E.g.
while true; do
echo “hi”
done
Until loop
E.g.
until false; do
echo “hi”
Done
Cases
Functions
E.g.
function echoSomething() {
something=$1
echo $something
}
What is baselining?
Baselining or defaulting is basically the process of comparing files and file system of the vulnerable machine to the files and file systems of a default or secured version
Comparing with defaults can help us find out if anything has been changed
Hash comparison
Hash comparison - comparing hashes on files
Hashing algorithms are used to converts strings into fixed-size, unreadable, and irreversible text representations called hashes
E.g. 
sha1sum <file>
Meld
Meld is a powerful tool which can compare separate files or even entire filesystems. It has a user-friendly GUI and is able to show differences between files and filesystems.
Can be useful in the context of CyberPatriot when used to compare a system file with a default configuration or secure configuration


Have script that updates following, and makes comparison with clean image config as necessary. Name scripts 1_xxx, 2_xxx etc based on what needs to be run when during an image. 
Kernel config update (make sure to have full list created by studying https://sysctl-explorer.net/ and security haderning resources/search on internet for all these parameters). Other (more readable?) documentation is at:
Documentation for /proc/sys/abi/
Documentation for /proc/sys/fs/
Documentation for /proc/sys/kernel/
Documentation for /proc/sys/net/
Documentation for /proc/sys/sunrpc/
Documentation for /proc/sys/user/
Documentation for /proc/sys/vm/
Checking for installed kernel modules using lsmod, compare with clean image output and print the diff
APT config update
Package automatic update configuration
Cronjob files comparison with clean image and output diff in a file
/etc/crontab
/etc/cron.d/*
/etc/cron.hourly/*
/etc/cron.daily/*
/etc/cron.weekly/*
/etc/cron.monthly/*
/var/spool/cron/crontabs/*
Pam.d related configuration
Find root imposters in /etc/passwd: awk -F: '$3 == 0' /etc/passwd
Find if any users or groups have duplicate IDs
Diff /etc/apt/sources.list from the clean image and show delta
Show packages that can’t be upgraded: apt-mark showhold
sudo apt update, sudo apt upgrade, sudo apt dist-upgrade, reboot
Install good packages, remove bad packages & games / unnecessary packages based on clean image, reboot, search for suspicious keywords in remaining packages and output in a file
Search for media files and output in a file
Search for suspicious (name & extension) files and output in a file
Checks /etc/shells for bad shells (e.g. /usr/sbin/nologin, /bin/false) by comparing with good shell info (from clean image, /bin/bash, /bin/sh etc.)
Check passwd for logon shells not within /etc/shells
Prints users with IDs less than 1000 and with interactive login shells
Ensure all users login to their own home directories
Check for geckos fields in /etc/passwd
Any other configurations for users (what else?)


dpkg --get-selections # Get all packages
dpkg -s <package name> # Check status of package
dpkg -l # list all packages with a description
apt-mark showmanual # list packages marked manually installed


Commands to edit crontab:
crontab -e # edit your own crontab
sudo crontab -e # edit the root user's crontab
sudo crontab -u [user] -e # edit a random user's crontab




Sudo config from clean image: /etc/sudoers:


#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults  env_reset
Defaults  mail_badpass
Defaults  secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"


# Host alias specification


# User alias specification


# Cmnd alias specification


# User privilege specification
root  ALL=(ALL:ALL) ALL


# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL


# Allow members of group sudo to execute any command
%sudo  ALL=(ALL:ALL) ALL


# See sudoers(5) for more information on "#include" directives:


#includedir /etc/sudoers.d
To get suid:




See and remove hold from packages from being upgraded:
apt-mark showhold
echo "<package-name> install" | sudo dpkg --set-selections




Scan-1:
echo “Install clamav”
sudo apt install -y debsecan
debsecan grep \(


Scan-2:
echo “Install clamav”
sudo apt install -y clamav
echo “Update virus definitions”
sudo service clamav-freshclam stop
sudo freshclam
sudo service clamav-freshclam start
echo “Scan all files and display infected ones only. Ignore errors”
clamscan -r -i / 2>/dev/null


Scan-3:
echo “Install debsums”
sudo apt install -y debsums
echo “Scan all files and display infected ones only. Ignore errors”
echo “Ignore if shows error on lightdm config for default user autologin”
debsums 2>/dev/null | egrep 'FAILED|REPLACED'



Tips
Do:
Read the ReadME!!!
Use grep or find for wide searching
Use tools like ls and tree(use apt-get install tree) on small directories
Research!
Practice!
more practice = more time = more familiarity with the system = more speed & points
Don't:
Mass delete by extension
Delete before checking file
CentOS is based on RedHat. Review RedHat help at https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Desktop_Migration_and_Administration_Guide/customizing-login-screen.html
Look at stigs for security options.
Go Through this: here (hacktricks.xyz)
Execution paths
How does linux acutally know where to look for all the binaries? Why don't we need to type the full path of the binary whenever we call them? For example, the ls binary is located in /bin/ls, but we're able to use the command without even mentioning the full path. But with other binaries if we put in /tmp, to use them we need to specify their full path. So what's happening?
Well linux has an environmental variable. In short they are variables that are dynamically set (so they can change) that services or applications may use. One of those environmental variables is the PATH variable. The PATH variable can allow you to execute binaries such as ls without using the full path, it also determines the order in which the system searches for binaries in linux. You can check out the current paths that your current system is checking for through:
echo $PATH # Will list out the PATH variable


Point Scrounging
Still no perfect score huh? You've come to the right place! Here's a small mini checklist on what to do now.
Look around the filesystem for anything that looks out of place.
Check the filesystem for any files with world writable permissions.
Look back through each package installed on the system carefully.
Last resort
DO THIS WHOLE CHECKLIST AGAIN!!!! 
It's very possible that you might be missing a simple vulnerability that you overlooked. Don't just sit there eating pizza and call it a day. You got this!
IMPORTANT LINKS
Linux Checklist Critical Services
Linux Resources Tools/Utilities
Red Hat Ubuntu Linux Die Net
If any vuls found in FQs, see how you can get points by using the info.
E.g. if bad IP found, use iptables to block it.
iptables -A INPUT -p tcp -s 178.18.25.16 --dport 2222 -j DROP (adding rule to drop packets for TCP connection from certain IP, going to certain port)






More
Go through past year FQs
Go through steg tools presentation and solve the samples give there. Also, know more on how to check more details of getattr with option -n
script: check for bad groups in various files like sudoers
script: gid 0
script hash check for shadow, passwd, group based on file size
suid diff
setup hashcat for host pc
/etc/proftpd/proftpd.conf: Make sure all items included: ServerIdent off,  RequireValidShell on
/etc/postfix/main.cf: smtp_sasl_security_options = noanonymous, disable_vrfy_command = yes, smtpd_data_restrictions = reject_unauth_pipelining
ufw script: high logs, /etc/ufw/before.rules --> ufw-http-logdrop - [0:0]
/etc/sysctl.conf: kernel.unprivileged_userns_clone=2, net.core.bpf_jit_harden=2
/etc/default/grub: randomize_kstack_offset=on
packages: cewl, gnuboy-x, icmpinfo <Add grep check for word intercept>
bad folder grep: intel, intercept
/etc/gdm3/PreSession/Default: invoke check for this and others
firefox: privacy.resistFingerprinting/true; privacy.trackingprotection.lower_network_priority/true

APT: /etc/apt/apt.conf.d/20auto-upgrades:
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "14";
APT::Get::AllowUnauthenticated "false";

Notes from Linux 24 presentations:
----------------------------------

Prep:
- ICC theme: Ubuntu 22.04.4 LTS... prepare all clean image info files from this page and upload on server before ICC
- setup host password cracking & steg tools.. verify hashcat setup
update checklist with any new info found during research
Know how to add a new service
create scripts for Ubuntu 22.04.4 LTS stig, cis benchmark
create script for browser hardening
research all kernel hardening config
find out how injects work (trivial, damaging, critical).. save work
prepare hardening config info for services taught in class, and for other services from last 2 years
practice all 5 steg images and tools from steg presentation
review PR answers/FQs of last 2/3 years, update script/checklist, make note if need more research, confirm if checklist/scripts cover all scenarios
improve package delete script to present keyword based views.. and offer to delete some?
improve bad file search script to create output based on file extension; and maybe for key directories?
know how to make iptables/firewall rules and create script to protect ports by port number (See firewall presentation.
learn how to use ps, top, netstat, lsof, ss, pgrep, pstree, TCPView etc for finding vults and bad ports / processes
learn syntax of how to add cron jobs for min/hour/week etc (contab -e; 1/min, 2/hour, 3/day, 4/month, 5/week etc)??
learn "Systemd Timers" for vul checking.. slide 18 of "Processes and system services II [2024]". Times can start bad service, just like what cron can do
https://docs.google.com/presentation/d/1LXEyfY_Zdr1KkAJsVivS9o4L_lXGhG_4M7eoNivqKkw/edit#slide=id.g13e18a1cdc9_0_25
learn how D-Bus works and how to check for vulns
learn how to create new service, and new timer that launches a service
try installing https://github.com/f0rb1dd3n/Reptile and then learn how to uninstall it
services: vsftpd, proftpd
learn how to Create a vsftpd server, Connect from another computer/VM, log in locally or anonymously, upload/edit a file, try chmod a files after changing server setting
read https://akshayrohatgi.com/blog/posts/How-To-Win-CyberPatriot/ blog from Akshay R




Confirm for scripts:
-------------------

hash comparison of important files like passwd, shadow based on file size


kernel:
kernel.unprivileged_bpf_disabled 
research all vulns and hardening settings under these: Check https://sysctl-explorer.net/
https://theprivacyguide1.github.io/linux_hardening_guide
https://tails.net/contribute/design/kernel_hardening/
https://wiki.archlinux.org/title/Security


abi | execution domains + personalities 
crypto | cryptographic interfaces
debug | kernel debugging interfaces
dev | device specific information
fs | global and specific file system parameters
kernel | global kernel parameters
net | network parameters 
sunrpc | NFS
user | user namespace limits
vm | tuning/management of memory, buffer, and cache 
yama...
<< at the competition check in /proc/sys/ and /proc/sys/kernel for any other module that needs settings.. e.g. yama >>.. add in script

group:
check for IDs <1000

tool:
sudo apt -y install libimage-exiftool-perl
rkhunter, verify on PR image (https://docs.rockylinux.org/guides/web/apache_hardened_webserver/rkhunter/)
ssh-audit


cron script:
make sure cron script also looks for user level cron jobs in /var/spool/cron/crontabs/* as well in addition to system level jobs in /etc/crontab, /etc/cron.*/*
add in script: service cron reload, service cron restart

ssh script:
#check if bad banner.. Banner [banner-file]: /etc/ssh/sshd_config
X11Forwarding no: /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes: /etc/ssh/sshd_config
  cd ~/.ssh/ (create the folder if not present)
  ssh-keygen -t rsa -b 4096
  Chose a name for the file, for example I chose “id_rsa”
  Use the command: cp id_rsa.pub ~/.ssh/authorized_keys to copy the id_rsa.pub file into the authorized_keys file
  chown root:wheel ~/.ssh/id_rsa
  chown root:wheel ~/.ssh/id_rsa.pub
  chown root:wheel ~/.ssh/authorized_keys
  chmod 640 ~/.ssh/id_rsa
  chmod 640 ~/.ssh/id_rsa.pub
  chmod 640 ~/.ssh/authorized_keys

PermitRootLogin no
HostBasedAuthentication no
PermitEmptyPasswords no
IgnoreRHosts yes
Protocol 2
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
PermitUserEnvironment no
HashKnownHosts yes
UsePAM yes
AllowTcpForwarding no
maxsessions 4
LogLevel VERBOSE
IgnoreRhosts yes
UseDNS yes
Port 2345 (changing to port other than 22 to make it hard to discover)
#delete ~/.ssh/known_hosts file if already present?
#grep for AllowUsers, AllowGroups, DenyUsers, DenyGroups for bad stuff
#check if any allowed commands in ~/.ssh/authorized_keys file
sudo service sshd restart
sshd -T

SSH client config: 
Files: ~/.ssh/config, /etc/ssh/ssh_config
ssh -G hostname
Config file example: https://linux-audit.com/audit-and-harden-your-ssh-configuration/



/etc/vsftpd.conf:
pasv_enable=YES
pasv_max_port=<PORT_NUMBER> #start of port range
pasv_min_port=<PORT_NUMBER> #end of port range
Anonymous no
Guest no
Local yes
Allow/deny users to use chmod command (recommended to disable)
Allow/deny users to use commands to change the file system
Allow/deny users to download files from the FTP server
If you want local users to have access to their home directory (but not directories above), enable local user chroot (“change root”)
FTP is a clear text protocol, so encrypting FTP using the most secure SSL/TLS is recommended
Block anonymous privileges: Upload, Write (changing the file system)
Limit: Login fails, Clients
https://linux.die.net/man/5/vsftpd.conf




first things to do in an image:
------------ -----------------
- Check README and make notes
check suid info
- check for copy of password/shadow files using hash comparison & optimized based on file size
- make list of bad files
- download Ubuntu 22.04.4 LTS backup
- install and do meld, make notes. see bad files
- DO FQs
- review & sanitize apt config

apt autoremove (doesn't remove dependencies.. e.g. gdm3, python?) better than apt purge --autoremove?

locate -ci Bin
grep -lri “netcat” /etc:

media files: .mp3, .mp4, .avi, .wav, .png, .jpg, .wma, .ogg
tools: extension less (bad name), .elf, .tar., .zip. .bz2
backdoors: .go, .sh, .py. .php, .c
bad files: extension less (bad name), .txt, .pdf


Good to know:
------------

Info found under /proc/<pid>, for FQ or vuls:
cmdline: Command line arguments used for the process
cpu: Current and last cpu in which it was executed
cwd: Current working directory of process
environ: Values of environment variables
exe: Symbolic link to executable
fd: file descriptors
maps: all memory maps
status: Process status (human readable)

other info in /proc:
/proc/mounts: displays all current mounts configured on the system
/proc/filesystems: displays all current configured or loaded filesystems
/proc/cpuinfo: cpu information

if can't update apt packages:
sudo killall dpkg
sudo killall apt-get
sudo killall apt
sudo rm /var/lib/dpkg/lock*


mount -o nodev,noexec,nosuid /tmp
Or, in /etc/fstab, add this line:
tmpfs                   /dev/shm                tmpfs   defaults        0 0

chown (new user owner):(new group owner) (file)

setfacl -m u:<username>:r <file_name>: Assign read permissions for a user for the file_name
setcap [-r] “CAP_STRING+ep” file



nautilus <file> to view media file


kernel.modules_disabled = 1
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
user.max_user_namespaces = 0
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
kernel.warn_limit = 1
kernel.oops_limit = 1
vm.unprivileged_userfaultfd = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
kernel.yama.ptrace_scope=2
kernel.kexec_load_disabled=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv6.icmp.echo_ignore_all = 1
kernel.ctrl-alt-del = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.log_martians = 1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
kernel.sysrq=0
kernel.unprivileged_userns_clone=0
net.ipv4.tcp_sack=0
kernel.deny_new_usb=1
kernel.core_pattern=|/bin/false
fs.suid_dumpable=0




run "ip a", and then replace eth0 / wlan0 with your network interfaces
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.eth0.use_tempaddr = 2
net.ipv6.conf.wlan0.use_tempaddr = 2





Run this tool to check for kernel hardening:
https://github.com/a13xp0p0v/kernel-hardening-checker/ 


/etc/fstab (to hide process information from other users except those in the proc group):
proc	/proc	proc	nosuid,nodev,noexec,hidepid=2,gid=proc	0	0
/etc/systemd/system/systemd-logind.service.d/hidepid.conf:
[Service]
SupplementaryGroups=proc


/etc/systemd/system/systemd-logind.service.d/hidepid.conf
[Service]
SupplementaryGroups=proc


create /etc/modprobe.d/no-conntrack-helper.conf and add
options nf_conntrack nf_conntrack_helper=0


/etc/securetty must be empty, so nobody can login as root from a tty.



edit /etc/pam.d/su and /etc/pam.d/su-l and uncomment
auth required pam_wheel.so use_uid

passwd -l root

password required pam_unix.so sha512 shadow nullok rounds=65536 >> more rounds will make login slower though.. remove nullok?


Create /etc/X11/Xwrapper.config and add
needs_root_rights = no



rfkill block all

create /etc/modprobe.d/blacklist-bluetooth.conf and add:
install btusb /bin/true
install bluetooth /bin/true



Edit /etc/profile and change the umask to 0077



create "/etc/modprobe.d/blacklist-dma.conf". To blacklist these modules from loading add
install firewire-core /bin/true
install thunderbolt /bin/true

Create /etc/systemd/coredump.conf.d/custom.conf and add
[Coredump]
Storage=none


/etc/security/limits.conf, add
* hard core 0


run: 
timedatectl set-ntp 0
systemctl disable systemd-timesyncd.service


Add these lines to /etc/NetworkManager/NetworkManager.conf:
[connection]
ipv6.ip6-privacy=2


Create /etc/systemd/network/ipv6.conf and add:
[Network]
IPv6PrivacyExtensions=kernel




edit /boot/syslinux/syslinux.cfg and add:
MENU MASTER PASSWD (password)
MENU PASSWD (password)


edit /etc/pam.d/system-login and add:
auth required pam_tally2.so deny=3 unlock_time=600 onerr=succeed file=/var/log/tallylog


Create /etc/modprobe.d/uncommon-network-protocols.conf and add:
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install n-hdlc /bin/true
install ax25 /bin/true
install netrom /bin/true
install x25 /bin/true
install rose /bin/true
install decnet /bin/true
install econet /bin/true
install af_802154 /bin/true
install ipx /bin/true
install appletalk /bin/true
install psnap /bin/true
install p8023 /bin/true
install llc /bin/true
install p8022 /bin/true


Create /etc/modprobe.d/uncommon-filesystems.conf and add
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true

Start at 26: https://theprivacyguide1.github.io/linux_hardening_guide


Create /etc/modprobe.d/blacklist-webcam.conf and add:
install uvcvideo /bin/true


Danger:
The kernel module for the microphone is the same as the one for the speaker. This means disabling the microphone in this method will also disable any speakers. To find the name of the module, look in /proc/asound/modules. Create /etc/modprobe.d/blacklist-mic.conf and add
install (module) /bin/true
Replace "(module)" with whatever you found in /proc/asound/modules. For example, if you found "snd_hda_intel", you would add
install snd_hda_intel /bin/true


Edit the /etc/pam.d/passwd file to read as:
#%PAM-1.0
password required pam_pwquality.so retry=2 minlen=10 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 [badwords=myservice mydomain] enforce_for_root
password required pam_unix.so use_authtok sha512 shadow


sudo aptitude install rkhunter
sudo rkhunter --update
sudo rkhunter --check

sudo aptitude -y install tiger
sudo tiger

UFW useful commands:
sudo ufw status verbose

sudo ufw deny PORT#
sudo ufw deny PORT#/tcp
sufo ufw deny PORT#/udp

sudo ufw allow PORT#
sudo ufw allow PORT#/tcp
sudo ufw allow PORT#/udp

sudo ufw deny from xxx.xxx.xxx.xxx
sufo ufw deny from 192.168.1.0/24 #blocks entire subnet
sudo ufw deny ssh #blocks service
sudo ufw allow ssh #allows service
sudo ufw delete deny ssh #delete the 'deny ssh' rule

—---------------

Create /etc/systemd/coredump.conf.d/disable.conf and add:

[Coredump]
Storage=none
------------
To enable privacy extensions for NetworkManager, edit /etc/NetworkManager/NetworkManager.conf and add:

[connection]
ipv6.ip6-privacy=2

-------------
 enable privacy extensions for systemd-networkd, create /etc/systemd/network/ipv6-privacy.conf and add:

[Network]
IPv6PrivacyExtensions=kernel


----------------------------

Sysctrl.conf settings to check:
# TCP and memory optimization 
# increase TCP max buffer size setable using setsockopt()
#net.ipv4.tcp_rmem = 4096 87380 8388608
#net.ipv4.tcp_wmem = 4096 87380 8388608
 
# increase Linux auto tuning TCP buffer limits
#net.core.rmem_max = 8388608
#net.core.wmem_max = 8388608
#net.core.netdev_max_backlog = 5000
#net.ipv4.tcp_window_scaling = 1
# increase system file descriptor limit    
fs.file-max = 65535
 
#Allow for more PIDs 
kernel.pid_max = 65536
 
#Increase system IP port limits
net.ipv4.ip_local_port_range = 2000 65000






------------------------------



modprobe blacklist:
#unnecessary kernel modules
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false

#Obscure networking protocols
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false

#rare filesystems.
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install ksmbd /bin/true
install gfs2 /bin/true

#network filesystem
install vivid /bin/false

#bluetooth
install bluetooth /bin/false
install btusb /bin/false

#camera
install uvcvideo /bin/false



#???
install firewire-core /bin/false
install thunderbolt /bin/false


rfkill block all
rfkill unblock wifi #to unblock wifi







This is an example of a basic iptables configuration that disallows all incoming network traffic:
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:TCP - [0:0]
:UDP - [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -p udp -m conntrack --ctstate NEW -j UDP
-A INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j TCP
-A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -j REJECT --reject-with tcp-reset
-A INPUT -j REJECT --reject-with icmp-proto-unreachable
COMMIT


To randomize MAC address on each boot:
1. find network interface (e.g. eth0) by running "ip a"
2. create systemd script like this:
[Unit]
Description=macchanger on eth0
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-eth0.device
After=sys-subsystem-net-devices-eth0.device

[Service]
ExecStart=/usr/bin/macchanger -e eth0
Type=oneshot

[Install]
WantedBy=multi-user.target
