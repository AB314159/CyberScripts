echo -n "Admins (space-separated): "
read admins

user=$(whoami)

while IFS=: read -r name password uid gid gecos home shell; do
    if echo "$admins" | grep -qw "$name"; then
        echo "Adding user $name to adm and sudo groups"
        sudo adduser $name sudo
        sudo adduser $name adm
    else
        if [ $uid -le 60000 ] && [ $uid -ge 1000 ] && [ "$name" != "$user" ]; then
            echo "Removing user $name from adm and sudo groups"
            sudo deluser $name sudo 2> /dev/null
            sudo deluser $name adm 2> /dev/null
        fi
    fi
done < <(getent passwd)
while IFS=: read -r name password gid users; do
    if [ $gid -eq 0 ] && [ "$name" != "root" ]; then
        echo "==========================="
        echo "There is a root group imposter!"
        echo "Removing root group imposter."
        sudo sed -i "/^$name:/d" /etc/group
        echo "==========================="
    fi
done < <(getent group)
cat /etc/group
echo "Inspect /etc/group and delete bad groups. ABOVE"
