#!/bin/bash

if [ $(whoami) != "root" ]; then
    echo "Installing script for you user only, run as root to install as a system service."
    python3 setup.py install
    exit 0
fi

python3 setup.py install

grep "^rc_push:" /etc/passwd || useradd -c "Rocket.Chat push user" -m -r -s /bin/false rc_push

if [ ! -e /etc/rc_push.conf ]; then
    echo "Enter the required configuration"
    echo "Rocket.Chat instance URL:"
    read -r rc_url
    echo "rc_url='${rc_url}'" > /etc/rc_push.conf

    echo "Rocket.Chat user name:"
    read -r rc_user
    echo "user='${rc_user}" >> /etc/rc_push.conf

    echo "Rocket.Chat user password:"
    read -s -r rc_pass
    echo "password='${rc_pass}" >> /etc/rc_push.conf

    echo "URL to your ntfy instance:"
    read -r ntfy_url
    echo "ntfy_url='${ntfy_url}" >> /etc/rc_push.conf

    echo "Topic in ntfy:"
    read -r ntfy_topic
    echo "ntfy_topic='${ntfy_topic}" >> /etc/rc_push.conf

    echo "User name in ntfy:"
    read -r ntfy_user
    echo "ntfy_user='${ntfy_user}" >> /etc/rc_push.conf

    echo "User password in ntfy:"
    read -s -r ntfy_pass
    echo "ntfy_pass='${ntfy_pass}" >> /etc/rc_push.conf

    echo "If you only want to monitor certain channels, enter them here separated by commas:"
    read -r channels
    echo "channels=['${channels//,/','}']" >> /etc/rc_push.conf
fi

chmod go-rwx /etc/rc_push.conf

cat << EOF > /etc/systemd/system/rc_push.service
[Unit]
Description=Rocket.Chat push
After=syslog.target network.target auditd.service
OnFailure=status_email_antoniodelgado@%n.service

[Service]
User=rc_push
ExecStart=/usr/local/bin/rc_push.py --config /etc/rc_push.conf

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start rc_push.service