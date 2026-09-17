#!/usr/bin/env bash
set -e

echo "Installing LandNav systemd services..."

cp /opt/pr0t31n/LandNav/landnav.service /etc/systemd/system/landnav.service
cp /opt/pr0t31n/LandNav/landnav-watchdog.service /etc/systemd/system/landnav-watchdog.service
cp /opt/pr0t31n/LandNav/landnav-watchdog.timer /etc/systemd/system/landnav-watchdog.timer

systemctl daemon-reload

systemctl enable landnav.service
systemctl enable landnav-watchdog.timer

echo ""
echo "Services installed. To start now:"
echo "  systemctl start landnav"
echo "  systemctl start landnav-watchdog.timer"
echo ""
echo "Status:"
systemctl is-enabled landnav.service
systemctl is-enabled landnav-watchdog.timer

echo ""
echo "LandNav service installation complete."
