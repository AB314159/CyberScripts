#!/bin/bash
echo “Install debsecan”
sudo apt install -y debsecan
debsecan grep \(
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo “Install clamav”
sudo apt install -y clamav
echo “Update virus definitions”
sudo service clamav-freshclam stop
sudo freshclam
sudo service clamav-freshclam start
echo “Scan all files and display infected ones only. Ignore errors”
clamscan -r -i / 2>/dev/null
read -p "Press Enter to continue" </dev/tty
echo "======================"
echo “Install debsums”
sudo apt install -y debsums
echo “Scan all files and display infected ones only. Ignore errors”
echo “Ignore if shows error on lightdm config for default user autologin”
debsums 2>/dev/null | egrep 'FAILED|REPLACED'
read -p "Press Enter to continue" </dev/tty
echo "======================"
sudo apt install -y lynis
sudo lynis audit system
read -p "Press Enter to continue" </dev/tty
echo "======================"