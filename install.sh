chmod +x Diemos-fw
cp Diemos-fw.service /etc/systemd/system
systemctl daemon-reload
systemct start Diemos-fw
systemctl enable Diemos-fw
