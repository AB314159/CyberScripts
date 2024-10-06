#!/bin/bash

sed -i 's/^PASS_MAX_DAYS[ \t]\+[0-9]\+/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS[ \t]\+[0-9]\+/PASS_MIN_DAYS\t7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE[ \t]\+[0-9]\+/PASS_WARN_AGE\t14/' /etc/login.defs
sed -i 's/^LOG_OK_LOGINS[ \t]\+[a-zA-Z]\+/LOG_OK_LOGINS\tyes/g' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD[ \t]\+[a-zA-Z0-9]\+/ENCRYPT_METHOD\tYESCRYPT/g' /etc/login.defs
