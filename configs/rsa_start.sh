cp rsa.service /lib/systemd/system
systemctl daemon-reload
systemctl start rsa.service

# CHANGE THE $HOME var in rsa.service to your home path