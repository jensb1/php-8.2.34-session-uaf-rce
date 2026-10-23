#!/bin/sh
# Install the lab php.ini + Apache vhost and enforce a single prefork worker.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
sudo mkdir -p /etc/php-lab /var/www/lab
sudo cp "$ROOT/lab-config/php.ini" /etc/php-lab/php.ini
sudo cp "$ROOT/lab-config/apache-php-lab.conf" /etc/apache2/conf-available/php-lab.conf
sudo cp "$ROOT"/*.php /var/www/lab/ && sudo chmod 644 /var/www/lab/*.php
sudo a2dismod mpm_event mpm_worker >/dev/null 2>&1 || true
sudo a2enmod mpm_prefork >/dev/null 2>&1 || true
sudo a2enmod php >/dev/null 2>&1 || true
sudo a2enconf php-lab >/dev/null 2>&1 || true
sudo sed -i 's/^StartServers.*/StartServers 1/;s/^MinSpareServers.*/MinSpareServers 1/;s/^MaxSpareServers.*/MaxSpareServers 1/;s/^MaxRequestWorkers.*/MaxRequestWorkers 1/;s/^ServerLimit.*/ServerLimit 1/' /etc/apache2/mods-available/mpm_prefork.conf
sudo mkdir -p /etc/systemd/system/apache2.service.d
printf '[Service]\nPrivateTmp=false\n' | sudo tee /etc/systemd/system/apache2.service.d/lab.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart apache2
echo "apache: $(systemctl is-active apache2), listening on :8084"
