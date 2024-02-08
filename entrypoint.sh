#!/bin/sh

# Terminate the script on first error.
set -e

# Create directory for log.
mkdir -p /app/var/log
echo "0 */2 * * * /prod/helper sync --cve --exp > /app/var/log/helper.log"> /etc/cron.d/crontab
# Load cron configuration.
crontab /etc/cron.d/crontab
# Start cron as a daemon.
{
  echo "DATABASE_URL=${DATABASE_URL}"
} >> /.env
cron -f &

# Run your main app.
/prod/nvd-server