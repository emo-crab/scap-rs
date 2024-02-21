#!/bin/sh

# Terminate the script on first error.
set -e

# Create directory for log.
mkdir -p /app/var/log
echo "0 */2 * * * /prod/helper sync --cve --kb > /app/var/log/helper.log"> /etc/cron.d/crontab
# Load cron configuration.
crontab /etc/cron.d/crontab
# Start cron as a daemon.
printenv > /.env
cron -f &

# Run your main app.
/prod/nvd-server