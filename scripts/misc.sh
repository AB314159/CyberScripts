#!/bin/bash

echo "Enabling UFW"
sudo ufw enable

echo "Setting UFW LOGGING to HIGH"
sudo ufw logging high

echo "Review UFW Status:"
sudo ufw status verbose
read -p "Press Enter to continue" </dev/tty

gsettings set org.gnome.desktop.screensaver lock-enabled true

echo "/etc/crontab differences:"
diff ./crontab.txt /etc/crontab | grep \>

echo "============================"
echo "Shell differences"
diff ./shells.txt /etc/shells | grep \>

passwd -l root