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
#                  RuntimeDirectory=q21-monitor, otherwise /run/q21-monitor;
#                  the unit needs RuntimeDirectoryPreserve=yes, or systemd
#                  deletes the file after every run, see SERVER.md)
#   Q21_THRESHOLD  minutes without a block before acting (default: 30)
#   Q21_SILENT_RUNS consecutive runs without an RPC answer before a running
#                  service is restarted (default: 3, half an hour at one run
#                  every ten minutes)
#   Q21_NTFY       ntfy topic, for example q21-my-server-a7f3 (default: none;
#                  to be provided through an EnvironmentFile with mode 0600,
#                  not in the unit)
#   Q21_PUBLIC_URL public explorer address, for example
#                  https://explorer.example.org/ (default: none, no check)
#   Q21_PROXY      service of the reverse proxy in front of it
#                  (default: caddy)
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
SILENT_RUNS="${Q21_SILENT_RUNS:-3}"
SILENT="$STATE.silent"
NTFY="${Q21_NTFY:-}"
PUBLIC_URL="${Q21_PUBLIC_URL:-}"
PROXY="${Q21_PROXY:-caddy}"

if [ -L "$STATE" ] || [ -L "$SILENT" ]; then
  logger -t q21-monitor "state file $STATE: symbolic link refused"
  exit 1
fi
mkdir -p "$(dirname "$STATE")" 2>/dev/null || true

now=$(date +%s)
response=$(curl -s -m 30 -X POST "http://$RPC/rpc" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":{}}' 2>/dev/null)
height=$(printf '%s' "$response" | sed -n 's/.*"height":\([0-9]*\).*/\1/p')

notify() {
  logger -t q21-monitor "$1"
  if [ -n "$NTFY" ]; then
    curl -s -m 10 -H "Title: Q21" -d "$1" "https://ntfy.sh/$NTFY" >/dev/null 2>&1
  fi
}

# The public explorer, seen from outside: the height can move forward while
# nobody can read it. In October 2026 the reverse proxy crashed and the public
# explorer stayed down for more than a day, while this script, which only
# watched the node, saw nothing wrong.
#
# The answer decides who is at fault:
# - no connection at all (code 000): the proxy is down. Restart it.
# - 502, 503 or 504: the proxy answers, the node behind it does not. The node
#   check below handles it; restarting the proxy would change nothing.
# - anything else outside 2xx and 3xx: notify, touch nothing.
if [ -n "$PUBLIC_URL" ]; then
  code=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "$PUBLIC_URL" 2>/dev/null)
  case "$code" in
    2??|3??) ;;
    000|"")
      if systemctl is-active --quiet "$PROXY"; then
        notify "public explorer $PUBLIC_URL unreachable while $PROXY runs: restarting $PROXY"
      else
        notify "$PROXY stopped, public explorer $PUBLIC_URL unreachable: restarting $PROXY"
      fi
      systemctl restart "$PROXY"
      ;;
    502|503|504)
      logger -t q21-monitor "public explorer answers $code: the node behind $PROXY is checked below"
      ;;
    *)
      notify "public explorer $PUBLIC_URL answers HTTP $code: $PROXY left as is"
      ;;
  esac
fi

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
# - The RPC answers but refuses (401, token required; or 403, another
#   account, from a node older than 0.4.3 that did not admit root): that is a
#   configuration error in the monitoring, not in the node. We notify, we do
#   not restart; restarting would change nothing.
# - The service runs but did not answer this time: busy is not dead. Up to
#   0.4.8 a single silent run was enough: during the endurance test of
#   2026-10-18, a node held up for a few minutes by a reorg was restarted in
#   the middle of its work, and had to start it all over again. A running
#   service is now restarted only after Q21_SILENT_RUNS runs in a row without
#   an answer.
# - The service is dead, or has been silent for that long: restart.
if [ -z "$height" ]; then
  if printf '%s' "$response" | grep -qi 'access token'; then
    notify "the RPC $RPC requires a token: monitoring misconfigured, service $SERVICE left as is"
    exit 0
  fi
  if printf '%s' "$response" | grep -qi 'another account'; then
    notify "the RPC $RPC refuses this account: update the node to 0.4.3 or later, service $SERVICE left as is"
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
    silent=0
    if [ -f "$SILENT" ]; then
      read -r silent < "$SILENT" 2>/dev/null || silent=0
      case "$silent" in ''|*[!0-9]*) silent=0 ;; esac
    fi
    silent=$((silent + 1))
    if [ "$silent" -lt "$SILENT_RUNS" ]; then
      printf '%s\n' "$silent" > "$SILENT"
      logger -t q21-monitor "node unreachable on $RPC ($silent run(s) in a row out of $SILENT_RUNS): busy, not restarted yet"
      exit 0
    fi
    notify "node unreachable on $RPC for $silent runs in a row: restarting $SERVICE"
  else
    notify "service $SERVICE stopped: restarting"
  fi
  systemctl restart "$SERVICE"
  rm -f "$SILENT"
  printf '0 %s\n' "$now" > "$STATE"
  exit 0
fi
rm -f "$SILENT"

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
  # A frozen height is not always this node's fault. When nobody mines, the
  # whole network stops, and restarting changes nothing: on 2026-10-12 both
  # entry points were restarted every hour for a morning, while they were
  # fine and simply waiting for a miner. So we first ask the node whether any
  # peer knows a longer chain. Connected, and no peer ahead: the network is
  # idle, the node is not stuck. We note it about once an hour and leave the
  # service alone. No peer at all, or a peer ahead: the node is the problem,
  # and the restart below applies.
  sync=$(curl -s -m 10 -X POST "http://$RPC/rpc" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"getsyncstatus","params":{}}' 2>/dev/null)
  peers=$(printf '%s' "$sync" | sed -n 's/.*"peers":\([0-9]*\).*/\1/p')
  network=$(printf '%s' "$sync" | sed -n 's/.*"network_height":\([0-9]*\).*/\1/p')
  if [ -n "$peers" ] && [ "$peers" -gt 0 ] && [ -n "$network" ] && [ "$network" -le "$height" ]; then
    if [ $(( (minutes - THRESHOLD) % 60 )) -lt 10 ]; then
      logger -t q21-monitor "height frozen at $height for $minutes min, but none of the $peers peers knows a longer chain: the network is idle (nobody mining), service $SERVICE left running"
    fi
    exit 0
  fi
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
