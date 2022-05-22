#!/bin/bash

if [ $(whoami) != "root" ]; then
    echo "Installing script for you user only, run as root to install as a system service."
    python3 setup.py install
    exit 0
fi

python3 setup.py install

grep "^rc_push:" /etc/passwd || useradd -c "Rocket.Chat push user" -m -r -s /bin/false rc_push

cat << EOF > /etc/systemd/system/rc_push.service
[Unit]
Description=Rocket.Chat push
After=syslog.target network.target auditd.service
OnFailure=status_email_antoniodelgado@%n.service

[Service]
User=rc_push
ExecStart=/usr/local/bin/rc_push.py

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start rc_push.service