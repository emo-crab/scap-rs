#!/bin/sh

# Terminate the script on first error.
set -e

# Create directory for log.
mkdir -p /app/var/log
echo "* 2 * * * /prod/helper cve --api --hours 2 > /app/var/log/helper.log 2>&1"> /prod/crontab
# Load cron configuration.
crontab /prod/crontab
# Start cron as a daemon.
cron

# Run your main app.
/prod/nvd-server