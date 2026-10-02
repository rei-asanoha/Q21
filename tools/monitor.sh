#!/bin/sh
# Monitoring for a Q21 node: is the height moving forward?
#
# A node that stops at three in the morning warns no one. This script reads
# the height from the local RPC, compares it with the one recorded on the
# previous run, and acts if nothing has moved for too long: it restarts the
# service and, if an ntfy topic is configured, sends a notification to the
# phone (https://ntfy.sh: free, no account, one app).
#
# Run it every ten minutes from a systemd timer (see SERVER.md), under an
# account that is allowed to restart the service.
#
# Variables, all optional:
#   Q21_RPC        local RPC address           (default: 127.0.0.1:21080)
#   Q21_SERVICE    systemd service name        (default: q21)
#   Q21_STATE      file to record the height in (default: the runtime
#                  directory that systemd provides with
#                  RuntimeDirectory=q21-monitor, otherwise /run/q21-monitor)
#   Q21_THRESHOLD  minutes without a block before acting (default: 30)
#   Q21_NTFY       ntfy topic, for example q21-my-server-a7f3 (default: none;
#                  to be provided through an EnvironmentFile with mode 0600,
#                  not in the unit)
#
# The state file does not live in a shared directory: in /var/tmp, any
# account on the machine could pre-create it, as a symbolic link to a file
# owned by root that this script would have overwritten, or with a frozen
# height to force restarts in a loop. A symbolic link is refused in every
# case.
set -u
RPC="${Q21_RPC:-127.0.0.1:21080}"
SERVICE="${Q21_SERVICE:-q21}"
STATE="${Q21_STATE:-${RUNTIME_DIRECTORY:-/run/q21-monitor}/state}"
THRESHOLD="${Q21_THRESHOLD:-30}"
NTFY="${Q21_NTFY:-}"

if [ -L "$STATE" ]; then
  logger -t q21-monitor "state file $STATE: symbolic link refused"
  exit 1
fi
mkdir -p "$(dirname "$STATE")" 2>/dev/null || true

now=$(date +%s)
response=$(curl -s -m 10 -X POST "http://$RPC/rpc" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}}' 2>/dev/null)
height=$(printf '%s' "$response" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')

notify() {
  logger -t q21-monitor "$1"
  if [ -n "$NTFY" ]; then
    curl -s -m 10 -H "Title: Q21" -d "$1" "https://ntfy.sh/$NTFY" >/dev/null 2>&1
  fi
}

# The RPC does not answer. Three cases, and only one justifies a restart.
#
# The defect this closes: this script used to restart the service as soon as
# the RPC did not answer, so during every index rebuild or revalidation at
# startup (more than ten minutes on a long chain), and on every run if the
# RPC requires a token (401 response). The bootstrap node was then restarted
# every ten minutes and never finished starting up.
#
# - The service was (re)started less than an hour ago: it is starting up,
#   let it be. A restart here would be the loop.
# - The RPC answers but refuses (401, token required): that is a
#   configuration error in the monitoring, not in the node. We notify, we do
#   not restart; restarting would change nothing.
# - The service is dead, or has been silent for more than an hour: restart.
if [ -z "$height" ]; then
  if printf '%s' "$response" | grep -qi 'access token'; then
    notify "the RPC $RPC requires a token: monitoring misconfigured, service $SERVICE left as is"
    exit 0
  fi
  if systemctl is-active --quiet "$SERVICE"; then
    # How long has the service been running?
    service_since=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$SERVICE" 2>/dev/null)
    boot_since=$(awk '{printf "%d", $1 * 1000000}' /proc/uptime 2>/dev/null)
    if [ -n "$service_since" ] && [ -n "$boot_since" ] && [ "$service_since" -gt 0 ]; then
      active_for=$(( (boot_since - service_since) / 60000000 ))
      if [ "$active_for" -lt 60 ]; then
        logger -t q21-monitor "node unreachable on $RPC but the service has been running for $active_for min: starting up, no restart"
        exit 0
      fi
    fi
    notify "node unreachable on $RPC after more than an hour of service: restarting $SERVICE"
  else
    notify "service $SERVICE stopped: restarting"
  fi
  systemctl restart "$SERVICE"
  printf '0 %s\n' "$now" > "$STATE"
  exit 0
fi

# First measurement: record it, and wait.
if [ ! -f "$STATE" ]; then
  printf '%s %s\n' "$height" "$now" > "$STATE"
  exit 0
fi

read -r last_height since < "$STATE"
if [ "$height" -gt "$last_height" ]; then
  printf '%s %s\n' "$height" "$now" > "$STATE"
  exit 0
fi

# The height has not moved: for how long?
minutes=$(( (now - since) / 60 ))
if [ "$minutes" -ge "$THRESHOLD" ]; then
  # A height frozen right after a restart is the catch-up, not a failure:
  # we never restart twice within the same hour.
  service_since=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$SERVICE" 2>/dev/null)
  boot_since=$(awk '{printf "%d", $1 * 1000000}' /proc/uptime 2>/dev/null)
  if [ -n "$service_since" ] && [ -n "$boot_since" ] && [ "$service_since" -gt 0 ] \
     && [ $(( (boot_since - service_since) / 60000000 )) -lt 60 ]; then
    logger -t q21-monitor "height frozen at $height but the service was restarted less than an hour ago: waiting"
    exit 0
  fi
  notify "height frozen at $height for $minutes min: restarting service $SERVICE"
  systemctl restart "$SERVICE"
  printf '%s %s\n' "$height" "$now" > "$STATE"
fi
