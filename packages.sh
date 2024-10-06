#!/bin/bash
echo "======================"
echo "Cleaning APT Cache"
sudo apt clean
sudo apt autoclean
sudo apt autoremove
sudo rm -rf /var/cache/apt/archives/*
sudo apt check
echo "======================"
echo "Add update settings in UI"
read -p "Press Enter to continue" </dev/tty
sudo software-properties-gtk
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo "Upgrading /etc/apt/apt.conf.d/10periodic"
echo "APT::Periodic::Update-Package-Lists \"1\";" >> /etc/apt/apt.conf.d/10periodic
echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" >> /etc/apt/apt.conf.d/10periodic
echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/10periodic
echo "APT::Periodic::AutocleanInterval \"14\";" >> /etc/apt/apt.conf.d/10periodic
echo "APT::Get::AllowUnauthenticated \"false\";" >> /etc/apt/apt.conf.d/10periodic
echo "Upgrading /etc/apt/apt.conf.d/20auto-upgrades"
echo "APT::Periodic::Update-Package-Lists \"1\";" >> /etc/apt/apt.conf.d/20auto-upgrades
echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" >> /etc/apt/apt.conf.d/20auto-upgrades
echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/20auto-upgrades
echo "APT::Periodic::AutocleanInterval \"14\";" >> /etc/apt/apt.conf.d/20auto-upgrades
echo "APT::Get::AllowUnauthenticated \"false\";" >> /etc/apt/apt.conf.d/20auto-upgrades
echo "Upgrading /etc/apt/apt.conf.d/50unattended-upgrades"
echo "APT::Periodic::Update-Package-Lists \"1\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "APT::Periodic::AutocleanInterval \"14\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "APT::Get::AllowUnauthenticated \"false\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "Acquire::AllowInsecureRepositories \"false\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "Acquire::AllowDowngradeToInsecureRepositories \"false\";" >> /etc/apt/apt.conf.d/50unattended-upgrades
echo "======================"
sudo cat /etc/apt/apt.conf
echo "Check /etc/apt/apt.conf for duplicate or bad stuff"
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo cat /etc/apt/apt.conf.d/10periodic
echo "Check /etc/apt/apt.conf.d/10periodic for duplicate or bad stuff"
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo cat /etc/apt/apt.conf.d/20auto-upgrades
echo "Check /etc/apt/apt.conf.d/20auto-upgrades for duplicate or bad stuff"
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo cat /etc/apt/apt.conf.d/50unattended-upgrades
echo "Check /etc/apt/apt.conf.d/50unattended-upgrades for duplicate or bad stuff"
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo cat /etc/apt/sources.list
echo "Check /etc/apt/sources.list for duplicate or bad stuff"
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo "Check that Unattended-Upgrade::Mail has no user other than root, if set"
sudo grep Unattended /etc/apt/apt.conf.d/*
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades
echo "======================"
echo "Updating Apt"
sudo apt update -y
echo "======================"
echo "Upgrading Apt"
sudo apt upgrade -y
echo "======================"
echo "Installing good packages"
sudo apt install -y fail2ban
# sudo apt install -y aide
# sudo aideinit
sudo apt install -y auditd
sudo apt install -y libpam-pwquality
sudo apt install -y ssh
sudo systemctl enable rsyslog.service --now
sudo apt-get install -y apparmor
sudo apt-get install -y vlock
sudo apt-get install -y chrony
sudo systemctl enable auditd.service --now
sudo systemctl enable apparmor.service --now
sudo systemctl enable ssh.service --now
sudo apt-get install -y  opensc-pkcs11
sudo apt-get install -y libpam-pkcs11
sudo apt install -y audispd-plugins
sudo apt install -y debsums
sudo apt install -y rsyslog
sudo systemctl start rsyslog
sudo apt install -y apt-listbugs
sudo apt install -y apt-listchanges
sudo apt install -y checkrestart
sudo apt install -y needrestart
sudo apt install -y libpam-tmpdir
sudo apt install -y libpam-usb

read -p "Press Enter to continue" </dev/tty
echo "======================"
echo "Removing bad packages"
sudo apt autoremove --purge -y reaver
sudo apt autoremove --purge -y pixfrogger
sudo apt autoremove --purge -y cowsay
sudo apt autoremove --purge -y apache2
sudo apt autoremove --purge -y featherpad
sudo apt autoremove --purge -y kollision
sudo apt autoremove --purge -y packit
sudo apt autoremove --purge -y unbound
sudo apt autoremove --purge -y dnsrecon
sudo apt autoremove --purge -y cups
sudo apt autoremove --purge -y nginx
sudo apt autoremove --purge -y nmap
sudo apt autoremove --purge -y yersinia
sudo apt autoremove --purge -y ruby
sudo apt autoremove --purge -y rails
sudo apt autoremove --purge -y xinetd
sudo apt autoremove --purge -y freeciv
sudo apt autoremove --purge -y telnet
sudo apt autoremove --purge -y telnetd
sudo apt autoremove --purge -y wireshark
sudo apt autoremove --purge -y binwalk
sudo apt autoremove --purge -y weevely
sudo apt autoremove --purge -y goldeneye
sudo apt autoremove --purge -y john
sudo apt autoremove --purge -y medusa
sudo apt autoremove --purge -y hydra
sudo apt autoremove --purge -y dsniff
sudo apt autoremove --purge -y ophcrack
sudo apt autoremove --purge -y p0f
sudo apt autoremove --purge -y hping3
sudo apt autoremove --purge -y minetest
sudo apt autoremove --purge -y moon-buggy
sudo apt autoremove --purge -y netcat-*
sudo apt autoremove --purge -y nikto
sudo apt autoremove --purge -y deluge
sudo apt autoremove --purge -y transmission
sudo apt autoremove --purge -y ruby-net-telnet
sudo apt autoremove --purge -y sl
sudo apt autoremove --purge -y sendmail
sudo apt autoremove --purge -y aircrack-ng
sudo apt autoremove --purge -y nsnake
sudo apt autoremove --purge -y httpry
sudo apt autoremove --purge -y t50
sudo apt autoremove --purge -y dirb
sudo apt autoremove --purge -y crack
sudo apt autoremove --purge -y postgresql
sudo apt autoremove --purge -y vsftpd
sudo apt autoremove --purge -y tcpdump
sudo apt autoremove --purge -y recon-ng
sudo apt autoremove --purge -y binwalk
sudo apt autoremove --purge -y dnsenum
sudo apt autoremove --purge -y ncrack
sudo apt autoremove --purge -y cain
sudo apt autoremove --purge -y pyrit
sudo apt autoremove --purge -y zeitgeist-core
sudo apt autoremove --purge -y zeitgeist-datahub
sudo apt autoremove --purge -y python-zeitgeist
sudo apt autoremove --purge -y rhythmbox-plugin-zeitgeist
sudo apt autoremove --purge -y zeitgeist
sudo apt autoremove --purge -y rsh-server
sudo apt autoremove --purge -y ettercap-common
sudo apt autoremove --purge -y ettercap-dbg
sudo apt autoremove --purge -y ettercap-graphical
sudo apt autoremove --purge -y ettercap-text-only
sudo apt autoremove --purge -y cewl
sudo apt autoremove --purge -y torsocks
sudo apt autoremove --purge -y pure-ftpd
sudo apt autoremove --purge -y PostgreSQL
sudo apt autoremove --purge -y finger
sudo apt autoremove --purge -y tmnationsforever
sudo apt autoremove --purge -y aisleriot
sudo apt autoremove --purge -y popularity-contest
sudo apt autoremove --purge -y tnftp
sudo apt autoremove --purge -y totem
sudo apt autoremove --purge -y transmission-common
sudo apt autoremove --purge -y slowhttptest
sudo apt autoremove --purge -y mdk3
sudo apt autoremove --purge -y john-data
sudo apt autoremove --purge -y samba
sudo apt autoremove --purge -y bind9*
sudo apt autoremove --purge -y apport
sudo apt autoremove --purge -y slapd
sudo apt autoremove --purge -y xonotic
sudo apt autoremove --purge -y pacman4console
sudo apt autoremove --purge -y lighttpd
sudo apt autoremove --purge -y proftpd
sudo apt autoremove --purge -y postfix
sudo apt autoremove --purge -y gnuboy-x
sudo apt autoremove --purge -y icmpinfo
echo "Check for other suspicious packages"
dpkg --list | grep -Ei 'poll|vulner|t50|crack|hack|sniff|password|intrusion|server|fake|SMTP|swiss|backdoor|stealth|dos|game|credit|secret|backdoor'
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo "Removing bad snaps"
sudo snap remove docker
sudo snap remove spotify
sudo snap remove code
sudo snap remove go
sudo snap remove cncra
sudo snap remove vscode
echo "Check remaining snaps"
sudo snap list
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo "Showing packages on hold"
sudo apt-mark showhold
echo "Use following command to remove upgrade hold from a package"
echo "\"echo <package-name> install\" | sudo dpkg --set-selections"
echo "An easier way is just: apt-mark unhold <package-name>"
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo "Showing manually installed packages"
sudo apt-mark showmanual
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo dpkg -l | grep -E 'xserver-xorg|geoclue'
#sudo apt autoremove --purge -y xserver-xorg*
#sudo apt autoremove --purge -y xserver-xorg-core*
#sudo apt autoremove --purge -y geoclue-2.0
read -p "See above if xserver-xorg and geoclue are installed and whether to delete them. Press enter to continue" </dev/tty
echo "======================"
