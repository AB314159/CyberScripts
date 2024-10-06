#!/bin/bash

echo "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet page_alloc.shuffle=1\"" >> /etc/default/grub
sudo update-grub
