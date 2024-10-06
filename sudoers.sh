#/bin/bash

echo "Differences in the /etc/sudoers file"
diff ./sudoers.txt /etc/sudoers | grep \>

echo "Everything in the /etc/sudoers.d directory"
cat /etc/sudoers.d/*