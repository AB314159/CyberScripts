#!/bin/bash
sysctl_path="/etc/sysctl.conf"

declare - a sysctrl_locations=(
    "/etc/sysctl.d/*.conf" 
    "/run/sysctl.d/*.conf" 
    "/usr/local/lib/sysctl.d/*.conf" 
    "/usr/lib/sysctl.d/*.conf" 
    "/lib/sysctl.d/*.conf" 
    "/etc/sysctl.conf"
    )

for i in "${sysctrl_locations[@]}"
do
   sudo cat $i
   echo "Confirm no bad settings in $i above"
   read -p "Press Enter to continue" </dev/tty
   echo "==========================="
done

if ! [[ -f "$sysctl_path" ]]; then
    echo "***********ERROR***********"
    read -p "File $sysctl_path not found. Ctrl+C, fix path and try again" </dev/tty
else
    echo "$sysctl_path found, continuing"
fi

sudo echo "net.ipv4.ip_forward = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.all.rp_filter = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.default.rp_filter = 1" >> $sysctl_path
sudo echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.all.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.all.send_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.send_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.tcp_syncookies = 1" >> $sysctl_path
sudo echo "net.ipv4.tcp_max_syn_backlog = 2048" >> $sysctl_path
sudo echo "net.ipv4.tcp_synack_retries = 2" >> $sysctl_path
sudo echo "net.ipv4.tcp_syn_retries = 5" >> $sysctl_path
sudo echo "net.ipv4.conf.all.log_martians = 1" >> $sysctl_path
sudo echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.all.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.icmp_echo_ignore_all = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.secure_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.secure_redirects = 0" >> $sysctl_path
sudo echo "kernel.exec-shield = 1" >> $sysctl_path
sudo echo "kernel.randomize_va_space = 2" >> $sysctl_path
sudo echo "net.ipv6.conf.all.disable_ipv6 = 1" >> $sysctl_path
sudo echo "net.ipv6.conf.default.disable_ipv6 = 1" >> $sysctl_path
sudo echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> $sysctl_path
sudo echo "net.ipv4.ip_forward=0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.log_martians = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.lo.disable_xfrm = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.autoconf = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.dad_transmits = 0" >> $sysctl_path
sudo echo "vm.swappiness = 10" >> $sysctl_path
sudo echo "net.ipv4.tcp_timestamps = 0" >> $sysctl_path
sudo echo "kernel.ctrl-alt-del = 0" >> $sysctl_path
sudo echo "fs.protected_symlinks = 1" >> $sysctl_path
sudo echo "#Prevent malicious FIFO writes" >> $sysctl_path
sudo echo "fs.protected_fifos = 2" >> $sysctl_path
sudo echo "vm.unprivileged_userfaultfd = 0" >> $sysctl_path
sudo echo "kernel.sysrq=0" >> $sysctl_path
sudo echo "net.ipv4.tcp_rfc1337 = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.send_redirects = 0" >> $sysctl_path
sudo echo "kernel.perf_event_paranoid = 2" >> $sysctl_path
sudo echo "kernel.kptr_restrict = 2" >> $sysctl_path
sudo echo "kernel.unprivileged_bpf_disabled = 1" >> $sysctl_path
sudo echo "fs.suid_dumpable = 0" >> $sysctl_path
sudo echo "kernel.watchdog = 1" >> $sysctl_path
sudo echo "net.ipv4.tcp_sack = 0" >> $sysctl_path
sudo echo "vm.memory_failure_early_kill = 1" >> $sysctl_path
sudo echo "dev.tty.ldisc_autoload = 0" >> $sysctl_path
sudo echo "fs.protected_hardlinks  =1" >> $sysctl_path
sudo echo "fs.suid_dumpable = 0" >> $sysctl_path
sudo echo "net.ipv4.ip_forward = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.all.rp_filter = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.default.rp_filter = 1" >> $sysctl_path
sudo echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.all.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_source_route = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.all.send_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.send_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.tcp_syncookies = 1" >> $sysctl_path
sudo echo "net.ipv4.tcp_max_syn_backlog = 2048" >> $sysctl_path
sudo echo "net.ipv4.tcp_synack_retries = 2" >> $sysctl_path
sudo echo "net.ipv4.tcp_syn_retries = 5" >> $sysctl_path
sudo echo "net.ipv4.conf.all.log_martians = 1" >> $sysctl_path
sudo echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.all.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.icmp_echo_ignore_all = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.secure_redirects = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.secure_redirects = 0" >> $sysctl_path
sudo echo "kernel.randomize_va_space = 2" >> $sysctl_path
sudo echo "net.ipv6.conf.all.disable_ipv6 = 1" >> $sysctl_path
sudo echo "net.ipv6.conf.default.disable_ipv6 = 1" >> $sysctl_path
sudo echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> $sysctl_path
sudo echo "net.ipv4.ip_forward=0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.log_martians=1" >> $sysctl_path
sudo echo "net.ipv4.conf.lo.disable_xfrm=0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.autoconf = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.dad_transmits = 0" >> $sysctl_path
sudo echo "vm.swappiness = 10" >> $sysctl_path
sudo echo "net.ipv4.tcp_timestamps = 0" >> $sysctl_path
sudo echo "kernel.ctrl-alt-del = 0" >> $sysctl_path
sudo echo "kernel.yama.ptrace_scope = 3" >> $sysctl_path
sudo echo "kernel.core_uses_pid=1" >> $sysctl_path
sudo echo "kernel.dmesg_restrict=1" >> $sysctl_path
sudo echo "vm.mmap_min_addr = 5000" >> $sysctl_path
sudo echo "kernel.modules_disabled = 1" >> $sysctl_path
sudo echo "kernel.randomize_va_space = 2" >> $sysctl_path
sudo echo "user.max_user_namespaces = 0" >> $sysctl_path
sudo echo "dev.tty.ldisc_autoload = 0" >> $sysctl_path
sudo echo "dev.tty.legacy_tiocsti = 0" >> $sysctl_path
sudo echo "kernel.warn_limit = 1" >> $sysctl_path
sudo echo "kernel.oops_limit = 1" >> $sysctl_path
sudo echo "vm.unprivileged_userfaultfd = 0" >> $sysctl_path
sudo echo "fs.protected_symlinks = 1" >> $sysctl_path
sudo echo "fs.protected_hardlinks = 1" >> $sysctl_path
sudo echo "fs.protected_fifos = 2" >> $sysctl_path
sudo echo "fs.protected_regular = 2" >> $sysctl_path
sudo echo "kernel.kptr_restrict=2" >> $sysctl_path
sudo echo "kernel.dmesg_restrict=1" >> $sysctl_path
sudo echo "kernel.unprivileged_bpf_disabled=1" >> $sysctl_path
sudo echo "net.core.bpf_jit_harden=2" >> $sysctl_path
sudo echo "kernel.kexec_load_disabled=1" >> $sysctl_path
sudo echo "net.ipv4.tcp_syncookies=1" >> $sysctl_path
sudo echo "net.ipv4.tcp_rfc1337=1" >> $sysctl_path
sudo echo "net.ipv4.conf.default.rp_filter=1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.rp_filter=1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.accept_redirects=0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.accept_redirects=0" >> $sysctl_path
sudo echo "net.ipv4.conf.all.secure_redirects=0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.secure_redirects=0" >> $sysctl_path
sudo echo "net.ipv6.conf.all.accept_redirects=0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_redirects=0" >> $sysctl_path
sudo echo "net.ipv4.conf.all.send_redirects=0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.send_redirects=0" >> $sysctl_path
sudo echo "net.ipv4.icmp_echo_ignore_all=1" >> $sysctl_path
sudo echo "net.ipv6.icmp.echo_ignore_all = 1" >> $sysctl_path
sudo echo "kernel.ctrl-alt-del = 0" >> $sysctl_path
sudo echo "net.ipv4.conf.default.log_martians = 1" >> $sysctl_path
sudo echo "net.ipv4.conf.all.log_martians = 1" >> $sysctl_path
sudo echo "vm.mmap_rnd_bits=32" >> $sysctl_path
sudo echo "vm.mmap_rnd_compat_bits=16" >> $sysctl_path
sudo echo "vm.mmap_rnd_bits=32" >> $sysctl_path
sudo echo "vm.mmap_rnd_compat_bits=16" >> $sysctl_path
sudo echo "kernel.sysrq=0" >> $sysctl_path
sudo echo "kernel.unprivileged_userns_clone=0" >> $sysctl_path
sudo echo "net.ipv4.tcp_sack=0" >> $sysctl_path
sudo echo "kernel.deny_new_usb=1" >> $sysctl_path
sudo echo "kernel.core_pattern=|/bin/false" >> $sysctl_path
sudo echo "fs.suid_dumpable=0" >> $sysctl_path
sudo echo "net.ipv6.conf.all.use_tempaddr = 2" >> $sysctl_path
sudo echo "net.ipv6.conf.default.use_tempaddr = 2" >> $sysctl_path
sudo echo "net.ipv6.conf.eth0.use_tempaddr = 2" >> $sysctl_path
sudo echo "net.ipv6.conf.wlan0.use_tempaddr = 2" >> $sysctl_path

#NEW: 7th Sept
sudo echo "net.ipv6.conf.default.router_solicitations = 0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.max_addresses = 1" >> $sysctl_path
sudo echo "kernel.panic=10" >> $sysctl_path
sudo echo "kernel.printk=3 3 3 3" >> $sysctl_path
sudo echo "net.ipv6.conf.all.accept_ra=0" >> $sysctl_path
sudo echo "net.ipv6.conf.default.accept_ra=0" >> $sysctl_path
sudo echo "net.ipv4.tcp_dsack=0" >> $sysctl_path
sudo echo "net.ipv4.tcp_fack=0" >> $sysctl_path

sudo sysctl -p

echo "Settings above applied"
