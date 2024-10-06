mkdir current
ps -aux | awk {'print $11 " " $12 " " $13 " " $14'} > current/ps.txt
du -sh /* 2>/dev/null > current/root_folder_sizes.txt
dpkg -l > current/dpkg.txt
getfacl -Rs / 2>/dev/null > current/getfacl.txt
lsmod > current/lsmod.txt
service --status-all > current/services.txt
find / -perm /4000 -ls > current/suid.txt
find / -perm /2000 -ls > current/sgid.txt
find / -perm /1000 -ls > current/stickybits.txt
ls -al / > current/ls_root.txt
ls -al /usr/bin > current/ls_usr_bin.txt
ls -al /usr/local/bin > current/ls_usr_local_bin.txt
ls -al /usr/local/sbin > current/ls_usr_local_sbin.txt
ls -al /usr/sbin > current/ls_usr_sbin.txt
sudo getcap -r / 2> /dev/null > current/getcap.txt
sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \; > current/var_log_gt_640.txt
sudo apt install attr -y
getfattr -R / > current/getfattr.txt
stat -c "%n %a" /bin /boot /cdrom /dev /etc /home /lib /lib32 /lib64 /libx32 /lost+found /media /mnt /opt /proc /root /run /sbin /snap /srv /swapfile /sys /tmp /usr /var /usr/bin /usr/games /usr/include /usr/lib /usr/lib32 /usr/lib64 /usr/libexec /usr/libx32 /usr/local /usr/sbin /usr/share /usr/src /var/backups /var/cache /var/crash /var/lib /var/local /var/lock /var/log /var/mail /var/metrics /var/opt /var/run /var/snap /var/spool /var/tmp /var/log/alternatives.log /var/log/apt /var/log/auth.log /var/log/boot.log /var/log/bootstrap.log /var/log/btmp /var/log/cups /var/log/dist-upgrade /var/log/dmesg /var/log/dpkg.log /var/log/faillog /var/log/fontconfig.log /var/log/gdm3 /var/log/gpu-manager.log /var/log/hp /var/log/installer /var/log/journal /var/log/kern.log /var/log/lastlog /var/log/openvpn /var/log/private /var/log/speech-dispatcher /var/log/syslog /var/log/ubuntu-advantage.log /var/log/unattended-upgrades /var/log/vmware-vmsvc-root.log /var/log/vmware-vmtoolsd-a.log /var/log/vmware-vmtoolsd-root.log /var/log/vmware-vmusr-a.log /var/log > current/stat_key_folders.txt
stat -c "%n %a" /usr/bin/* > current/stat_usr_bin.txt
stat -c "%n %a" /usr/local/sbin/* > current/stat_usr_local_sbin.txt
stat -c "%n %a" /usr/sbin/* > current/stat_usr_sbin.txt
mkdir ../Desktop/plain_backup
mkdir backups
tar -xf ubuntu-22.04.4-plain-backup.tar.gz -C ../Desktop/plain_backup
mv ../Desktop/plain_backup/*.txt backups
echo "Immutable Files:"
sudo lsattr -a -R 2>/dev/null / | grep -P "(?<=-)i(?=-).* "
read -p "Press Enter to continue" </dev/tty
sudo lsattr -a -R 2>/dev/null / | grep -P "(?<=-)a(?=-).* "
read -p "Press Enter to continue" </dev/tty



#  root@a:/home/a/Downloads# ls -al
#  total 496
#  drwxr-xr-x   8 a    a      4096 Sep  2 22:56 .
#  drwxr-x---  16 a    a      4096 Sep  2 22:26 ..
#  drwxr-xr-x   3 root root   4096 Sep  2 22:46 boot
#  -rw-r--r--   1 root root 237547 Sep  2 22:16 dpkg.txt
#  drwxr-xr-x 130 root root  12288 Sep  2 21:36 etc
#  -rw-r--r--   1 root root    216 Sep  2 22:52 getcap.txt
#  -rw-r--r--   1 root root   2862 Sep  2 23:00 getfacl.txt
#  -rw-r--r--   1 root root   1273 Sep  2 23:01 getfattr.txt
#  drwxr-xr-x   3 root root   4096 Sep  2 21:31 home
#  drwxr-xr-x  72 root root   4096 Sep  2 22:11 lib
#  -rw-r--r--   1 root root   2721 Sep  2 22:19 lsmod.txt
#  -rw-r--r--   1 root root   1545 Sep  2 22:18 ls_root
#  -rw-r--r--   1 root root  84384 Sep  2 22:18 ls_usr_bin
#  -rw-r--r--   1 root root     97 Sep  2 22:18 ls_usr_local_bin
#  -rw-r--r--   1 root root     97 Sep  2 22:18 ls_usr_local_sbin
#  -rw-r--r--   1 root root  23466 Sep  2 22:19 ls_usr_sbin
#  -rw-r--r--   1 root root   9560 Sep  2 22:32 ps.txt
#  drwx------   4 root root   4096 Sep  2 21:37 root
#  -rw-r--r--   1 root root    247 Sep  2 22:15 root_folder_sizes.txt
#  drwxr-xr-x  35 root root   4096 Sep  2 21:37 run
#  -rw-r--r--   1 root root    640 Sep  2 22:19 services.txt
#  -rw-r--r--   1 root root   2877 Sep  2 22:20 sgid.txt
#  -rw-r--r--   1 root root   1378 Sep  2 22:43 stat_key_folders.txt
#  -rw-r--r--   1 root root  31413 Sep  2 22:43 stat_usr_bin.txt
#  -rw-r--r--   1 root root      0 Sep  2 22:43 stat_usr_local_sbin.txt
#  -rw-r--r--   1 root root   9416 Sep  2 22:43 stat_usr_sbin.txt
#  -rw-r--r--   1 root root   5463 Sep  2 22:21 stickybits.txt
#  -rw-r--r--   1 root root   3250 Sep  2 22:20 suid.txt
#  -rw-r--r--   1 root root    423 Sep  2 22:54 var_log_gt_640.txt
