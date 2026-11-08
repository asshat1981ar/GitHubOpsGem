#!/usr/bin/env bash
# deploy_awsbox.sh — install or upgrade the B200 lifecycle controller (WU-07) on awsbox. Idempotent.
#
#   sudo ./lifecycle/deploy_awsbox.sh                 first install: DRY mode (logs decisions, never scales)
#   sudo ./lifecycle/deploy_awsbox.sh --live          let it scale the deployment for real
#   sudo ./lifecycle/deploy_awsbox.sh --dry           back to DRY mode
#   sudo ./lifecycle/deploy_awsbox.sh --uninstall [--purge [--force]]
#
# Options:
#   --deployment accounts/<acct>/deployments/<id>   required on first install; later runs reuse the saved one
#   --api-key-file PATH        read the Fireworks key from a file instead of prompting (never put it in argv)
#   --autodelete-off           you created the deployment with --unused-auto-delete-duration 0
#   --accept-autodelete-risk   you didn't (or don't know); wakes allowed, status shows the risk
#   --fix-window               run `firectl deployment update <id> --scale-to-zero-window 5m` (as $SUDO_USER)
#   --litellm-dir DIR          copy the LiteLLM callback next to your LiteLLM config
#   --yes                      never prompt (CI / scripted runs)
#   --force                    with --uninstall --purge: purge even if the B200 could not be confirmed asleep
#
# --uninstall first asks the running controller to scale the B200 to zero and waits for Fireworks to confirm.
# If it can't, it prints the firectl command to do it by hand, and --purge stops before deleting the env file
# (it holds the Fireworks key) unless --force is given.
#
# Run it from the unzipped gem package. It never prints the API key or the controller tokens.
set -euo pipefail
umask 027

DEPLOYMENT=""
MODE=""            # "", live, dry
AUTODELETE=""      # "", off, risk
API_KEY_FILE=""
LITELLM_DIR=""
FIX_WINDOW=0
UNINSTALL=0
PURGE=0
FORCE=0
YES=0

PREFIX="${GEM_DEPLOY_PREFIX:-}"          # tests install into a scratch root
SYSTEMCTL="${GEM_SYSTEMCTL:-systemctl}"
ETC="$PREFIX/etc/gem"
OPT="$PREFIX/opt/gem"
STATE="$PREFIX/var/lib/gem"
UNIT_DIR="$PREFIX/etc/systemd/system"
UNIT="gem-lifecycle.service"
ENV_FILE="$ETC/lifecycle.env"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(dirname "$HERE")"

if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=""; G=""; Y=""; R=""; N=""; fi
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%sdeploy_awsbox: %s%s\n' "$R" "$*" "$N" >&2; exit 1; }
loud() { printf '  %s!!! %s%s\n' "$R$B" "$*" "$N" >&2; }
usage() { awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deployment) DEPLOYMENT="${2:?--deployment needs a value}"; shift 2 ;;
    --api-key-file) API_KEY_FILE="${2:?--api-key-file needs a path}"; shift 2 ;;
    --live) MODE=live; shift ;;
    --dry) MODE=dry; shift ;;
    --autodelete-off) AUTODELETE=off; shift ;;
    --accept-autodelete-risk) AUTODELETE=risk; shift ;;
    --fix-window) FIX_WINDOW=1; shift ;;
    --litellm-dir) LITELLM_DIR="${2:?--litellm-dir needs a path}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    --force) FORCE=1; shift ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage 0 ;;
    *) printf 'unknown option: %s\n\n' "$1" >&2; usage 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run with sudo"
PY="$(command -v python3 || true)"
[[ -n "$PY" ]] || die "python3 not found"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Edits KEY=VALUE lines in place (comments and unknown keys kept). Values arrive on stdin, never in argv.
cat > "$WORK/envtool.py" <<'PY'
import os, re, sys, tempfile
cmd, path = sys.argv[1:3]
lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []


def write(out):
    st = os.stat(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".lifecycle.env.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    os.chown(tmp, st.st_uid, st.st_gid)
    os.chmod(tmp, st.st_mode & 0o7777)
    os.replace(tmp, path)


if cmd == "normalize":
    # systemd reads "KEY=value   # note" as the value "value   # note": move such notes onto their own line.
    out, moved = [], 0
    for line in lines:
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s#]*)[ \t]+#[ \t]?(.*)", line)
        if m:
            out += [("# " + m.group(3)).rstrip(), f"{m.group(1)}={m.group(2)}"]
            moved += 1
        else:
            out.append(line)
    if moved:
        write(out)
    print(moved)
    sys.exit(0)
key = sys.argv[3]
if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
    sys.exit(f"bad key {key!r}")
if cmd == "get":
    for line in lines:
        if line.startswith(key + "="):
            print(line.split("=", 1)[1])
            break
    sys.exit(0)
val = sys.stdin.read().strip()
if not re.fullmatch(r"[A-Za-z0-9_./:@+,=-]*", val):
    sys.exit(f"{key}: value contains characters an EnvironmentFile cannot hold unquoted")
out, done = [], False
for line in lines:
    if line.startswith(key + "="):
        if not done:
            out.append(f"{key}={val}")
            done = True
        continue
    out.append(line)
if not done:
    out.append(f"{key}={val}")
write(out)
PY
envget() { python3 -I "$WORK/envtool.py" get "$ENV_FILE" "$1"; }
envset() { printf '%s' "$2" | python3 -I "$WORK/envtool.py" set "$ENV_FILE" "$1"; }
envset_stdin() { python3 -I "$WORK/envtool.py" set "$ENV_FILE" "$1"; }

# Loads the env file the way systemd's EnvironmentFile= does, then execs the command with only that environment.
# Lines starting with # or ; are comments; everything after the first "=" is the value, verbatim (a trailing
# "# note" included, unlike a shell). It refuses any value with whitespace or "#" instead of guessing.
ENVEXEC="$(cat <<'PY'
import os, sys
path, argv = sys.argv[1], sys.argv[2:]
env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/")}
bad = []
with open(path, encoding="utf-8") as fh:
    for n, line in enumerate(fh.read().split("\n"), 1):
        s = line.lstrip()
        if not s or s[0] in "#;" or "=" not in s:
            continue
        key, val = s.split("=", 1)
        key = key.strip()
        if "#" in val or any(c.isspace() for c in val):
            bad.append(f"{path}:{n}: {key}: the value contains whitespace or '#'. systemd would pass all of it "
                       "to the controller; put comments on their own line")
        env[key] = val
if bad:
    sys.stderr.write("\n".join(bad) + "\n")
    sys.exit(78)
if argv:
    os.execvpe(argv[0], argv, env)
PY
)"
# with_env runs as root, as_gem as the service user; both see exactly what systemd gives the service.
with_env() { env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$STATE" "$PY" -I -c "$ENVEXEC" "$ENV_FILE" "$@"; }
as_gem() {
  runuser -u gem -- env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$STATE" "$PY" -I -c "$ENVEXEC" "$ENV_FILE" "$@"
}

# Asks the running controller to scale the B200 to zero and waits until Fireworks reports desired replicas 0.
sleep_b200() {
  with_env "$PY" -I - <<'PY'
import json, os, sys, time, urllib.error, urllib.request
base = "http://" + os.environ.get("GEM_LIFECYCLE_BIND", "127.0.0.1:8090")
tok = os.environ.get("GEM_LIFECYCLE_TOKEN", "")
if not tok:
    sys.exit("no GEM_LIFECYCLE_TOKEN (operator) in the env file")


def call(method, path, body=None, timeout=10.0):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read()[:200].decode("utf-8", "replace")}


try:
    code, body = call("POST", "/heavy", {"on": False}, timeout=40.0)
except OSError as exc:
    sys.exit(f"controller unreachable at {base} ({exc})")
if code >= 300:
    sys.exit(f"the controller could not scale it down: HTTP {code} {body}")
deadline = time.monotonic() + 30
while True:
    try:
        _, st = call("GET", "/status")
    except OSError:
        st = {}
    if st.get("desired") == 0:
        print(f"B200 scaled to zero (Fireworks reports desired 0, replicas {st.get('replicas')})")
        sys.exit(0)
    if time.monotonic() > deadline:
        sys.exit(f"Fireworks still reports {st.get('desired')} desired replica(s) after 30 s")
    time.sleep(1)
PY
}

# ----------------------------------------------------------------------------- uninstall
if [[ $UNINSTALL -eq 1 ]]; then
  step "Removing the lifecycle controller"
  if [[ -f "$ENV_FILE" ]]; then
    DEP_NOW="$(envget GEM_BURST_DEPLOYMENT)"
    DEP_NOW="${DEP_NOW:-$DEPLOYMENT}"
    if sleep_b200 > "$WORK/sleep.txt" 2>&1; then
      ok "$(tail -1 "$WORK/sleep.txt")"
    else
      loud "could not confirm the B200 is asleep: $(tail -1 "$WORK/sleep.txt")"
      loud "once this controller is gone, nothing scales it down except Fireworks' scale-to-zero window."
      loud "scale it to zero yourself:  firectl deployment scale ${DEP_NOW##*/} --replica-count 0"
      if [[ $PURGE -eq 1 && $FORCE -eq 0 ]]; then
        die "stopped before removing anything: --purge would delete $ENV_FILE and the Fireworks key in it. Scale the B200 down first, or re-run with --uninstall --purge --force"
      fi
    fi
  else
    warn "no $ENV_FILE, so the controller can't be asked to put the B200 to sleep; check it with firectl"
  fi
  "$SYSTEMCTL" disable --now "$UNIT" >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/$UNIT" "$OPT/gem_lifecycle.py"
  "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
  ok "service stopped and removed"
  warn "nothing scales the B200 down now except Fireworks' own scale-to-zero window"
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$ETC" "$STATE"
    rmdir "$OPT" 2>/dev/null || true
    if id gem >/dev/null 2>&1; then userdel gem >/dev/null 2>&1 || true; fi
    ok "removed $ETC (token, API key), $STATE (spend ledger) and the gem user"
  else
    ok "kept $ENV_FILE and $STATE (spend ledger); add --purge to delete them"
  fi
  exit 0
fi

# ----------------------------------------------------------------------------- 1. preflight
step "1/7 Preflight"
[[ -f "$PKG/lifecycle/gem_lifecycle.py" && -f "$HERE/gem-lifecycle.service" ]] \
  || die "run this from the unzipped gem package (missing lifecycle/gem_lifecycle.py)"
if [[ -z "$DEPLOYMENT" ]]; then                       # later runs reuse the saved deployment
  DEPLOYMENT="$(envget GEM_BURST_DEPLOYMENT 2>/dev/null || true)"
  [[ "$DEPLOYMENT" == *YOUR_ACCOUNT* ]] && DEPLOYMENT=""
fi
[[ "$DEPLOYMENT" =~ ^accounts/[A-Za-z0-9_.-]+/deployments/[A-Za-z0-9_.-]+$ ]] \
  || die "pass --deployment accounts/<acct>/deployments/<id> (needed on the first install)"
"$PY" -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || die "needs Python 3.9+ (found $("$PY" -V 2>&1)); zoneinfo is required for the cap periods"
ok "$("$PY" -V) at $PY"
if "$PY" -c 'from zoneinfo import ZoneInfo; ZoneInfo("America/Chicago")' 2>/dev/null; then
  ok "time zone data present (caps roll over at midnight America/Chicago)"
else
  die "no tz data for America/Chicago: install the tzdata package (the controller refuses an unknown GEM_CAP_TZ)"
fi
if [[ -z "$PREFIX" ]]; then
  command -v "$SYSTEMCTL" >/dev/null && [[ -d /run/systemd/system ]] || die "systemd is not running on this host"
fi
command -v runuser >/dev/null || die "runuser not found (util-linux)"
if "$PY" -I "$PKG/lifecycle/gem_lifecycle.py" dryrun > "$WORK/dryrun.txt"; then
  ok "self-test: $(tail -1 "$WORK/dryrun.txt" | cut -d' ' -f1-3) on this host's Python"
else
  cat "$WORK/dryrun.txt"
  die "self-test failed on this host; not installing"
fi

# ----------------------------------------------------------------------------- 2. user and files
step "2/7 Service user and files"
if ! id gem >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --home-dir /var/lib/gem --no-create-home --shell "$NOLOGIN" gem
  ok "created system user gem"
else
  ok "user gem exists"
fi
[[ -n "$PREFIX" ]] && install -d -m 0755 "$PREFIX" "$PREFIX/opt" "$PREFIX/etc" "$PREFIX/var" "$PREFIX/var/lib"
install -d -m 0755 "$OPT"
install -m 0644 "$PKG/lifecycle/gem_lifecycle.py" "$OPT/gem_lifecycle.py"
install -d -m 0750 -o root -g gem "$ETC"
install -d -m 0750 -o gem -g gem "$STATE"
NEW_ENV=0
if [[ ! -f "$ENV_FILE" ]]; then
  install -m 0640 -o root -g gem "$HERE/lifecycle.env.example" "$ENV_FILE"
  NEW_ENV=1
fi
chown root:gem "$ENV_FILE"
chmod 0640 "$ENV_FILE"
MOVED="$("$PY" -I "$WORK/envtool.py" normalize "$ENV_FILE")"
[[ "$MOVED" == "0" ]] || ok "moved $MOVED inline comment(s) in $ENV_FILE onto their own line (systemd keeps them in the value)"
ok "controller $("$PY" -I "$OPT/gem_lifecycle.py" version) in $OPT; config $ENV_FILE (0640 root:gem)"

# ----------------------------------------------------------------------------- 3. configuration
step "3/7 Configuration"
envset GEM_BURST_DEPLOYMENT "$DEPLOYMENT"
envset GEM_LIFECYCLE_STATE "/var/lib/gem/lifecycle.json"
[[ -n "$PREFIX" ]] && envset GEM_LIFECYCLE_STATE "$STATE/lifecycle.json"

if [[ -n "$API_KEY_FILE" ]]; then
  [[ -r "$API_KEY_FILE" ]] || die "cannot read $API_KEY_FILE"
  tr -d ' \r\n' < "$API_KEY_FILE" | envset_stdin FIREWORKS_API_KEY || die "API key file has unexpected characters"
  ok "Fireworks API key set from $API_KEY_FILE"
elif [[ -z "$(envget FIREWORKS_API_KEY)" ]]; then
  [[ -t 0 && $YES -eq 0 ]] || die "no Fireworks API key yet: re-run interactively or pass --api-key-file PATH"
  read -rsp "  Fireworks API key (input hidden): " KEY; echo
  [[ -n "$KEY" ]] || die "empty API key"
  printf '%s' "$KEY" | envset_stdin FIREWORKS_API_KEY || die "API key has unexpected characters"
  unset KEY
  ok "Fireworks API key saved"
else
  ok "Fireworks API key kept"
fi

for pair in operator:GEM_LIFECYCLE_TOKEN feed:GEM_LIFECYCLE_FEED_TOKEN session:GEM_LIFECYCLE_SESSION_TOKEN; do
  role="${pair%%:*}" var="${pair#*:}"
  if [[ -z "$(envget "$var")" ]]; then
    "$PY" -c 'import secrets; print(secrets.token_urlsafe(32))' | envset_stdin "$var"
    ok "generated the $role token ($var)"
  else
    ok "$role token kept ($var)"
  fi
done

case "$MODE" in
  live) envset GEM_LIFECYCLE_DRY 0 ;;
  dry) envset GEM_LIFECYCLE_DRY 1 ;;
  *) [[ $NEW_ENV -eq 1 ]] && envset GEM_LIFECYCLE_DRY 1 ;;
esac
if [[ "$(envget GEM_LIFECYCLE_DRY)" == "1" ]]; then
  ok "mode: DRY (logs every decision, never calls the scale API)"
else
  ok "mode: LIVE (scales the deployment)"
fi

if [[ -z "$AUTODELETE" && "$(envget GEM_AUTODELETE_VERIFIED)" != "1" && "$(envget GEM_AUTODELETE_ACCEPT_RISK)" != "1" \
      && -t 0 && $YES -eq 0 ]]; then
  echo "  Fireworks auto-deletes a scale-to-zero deployment after 7 days without traffic unless it was created"
  echo "  with --unused-auto-delete-duration 0. The API can't report this, and it can't be changed after creation."
  read -rp "  Was ${DEPLOYMENT##*/} created with --unused-auto-delete-duration 0? [y = yes / r = not sure, accept the risk / N = leave wakes off] " A
  case "${A,,}" in y|yes) AUTODELETE=off ;; r|risk) AUTODELETE=risk ;; *) AUTODELETE="" ;; esac
fi
case "$AUTODELETE" in
  off) envset GEM_AUTODELETE_VERIFIED 1; envset GEM_AUTODELETE_ACCEPT_RISK 0 ;;
  risk) envset GEM_AUTODELETE_VERIFIED 0; envset GEM_AUTODELETE_ACCEPT_RISK 1 ;;
esac
if [[ "$(envget GEM_AUTODELETE_VERIFIED)" == "1" ]]; then ok "auto-delete: off (your confirmation)"
elif [[ "$(envget GEM_AUTODELETE_ACCEPT_RISK)" == "1" ]]; then warn "auto-delete: unknown, risk accepted (use the B200 at least weekly)"
else warn "auto-delete: unconfirmed, so the controller will refuse every wake (re-run with --autodelete-off or --accept-autodelete-risk)"
fi
if ! with_env true 2> "$WORK/envlint.txt"; then
  cat "$WORK/envlint.txt" >&2
  die "$ENV_FILE has values systemd would pass on verbatim (see above); fix those lines and re-run"
fi
ok "$ENV_FILE reads cleanly as a systemd EnvironmentFile"

# ----------------------------------------------------------------------------- 4. deployment check
step "4/7 Deployment check (${DEPLOYMENT})"
set +e
as_gem "$PY" -I "$OPT/gem_lifecycle.py" check > "$WORK/check.json" 2> "$WORK/check.err"
CHECK_RC=$?
set -e
[[ $CHECK_RC -eq 0 || $CHECK_RC -eq 3 ]] || { cat "$WORK/check.err" >&2; die "check could not run (exit $CHECK_RC)"; }
"$PY" -I - "$WORK/check.json" > "$WORK/check.txt" <<'PY'
import json, sys
rep = json.load(open(sys.argv[1]))
info = rep.get("info", {})
if info.get("state"):
    print(f"ok|state {info['state']}, {info.get('gpus_per_replica')} GPUs per replica, ${info.get('usd_per_replica_hour')}/h while up")
for h in rep.get("hard", []):
    print(f"hard|{h}")
for w in rep.get("warn", []):
    print(f"warn|{w}")
PY
WINDOW_WARN=0
while IFS='|' read -r kind msg; do
  case "$kind" in
    ok) ok "$msg" ;;
    hard) printf '  %s✗%s %s\n' "$R" "$N" "$msg"
          [[ "$msg" == "cannot read the deployment"* ]] && READ_FAIL=1 ;;
    warn) warn "$msg"; [[ "$msg" == *"scale-to-zero"* ]] && WINDOW_WARN=1 ;;
  esac
done < "$WORK/check.txt"
[[ "${READ_FAIL:-0}" -eq 1 ]] && die "the Fireworks API refused the read: fix FIREWORKS_API_KEY or --deployment and re-run"

if [[ $WINDOW_WARN -eq 1 ]]; then
  FC_USER="${SUDO_USER:-root}"
  if [[ $FIX_WINDOW -eq 1 ]] && runuser -u "$FC_USER" -- bash -lc 'command -v firectl' >/dev/null 2>&1; then
    # shellcheck disable=SC2016  # $1 is expanded by the login shell
    if runuser -u "$FC_USER" -- bash -lc 'firectl deployment update "$1" --scale-to-zero-window 5m' _ "$DEPLOYMENT"; then
      ok "Fireworks backstop window set to 5 min"
    else
      warn "firectl update failed; run it yourself: firectl deployment update $DEPLOYMENT --scale-to-zero-window 5m"
    fi
  else
    warn "or re-run with --fix-window to have firectl (as ${FC_USER}) apply it"
  fi
fi

# ----------------------------------------------------------------------------- 5. systemd unit
step "5/7 systemd unit"
sed -e "s#/usr/bin/python3#${PY}#" \
    -e "s#/opt/gem/gem_lifecycle.py#${OPT}/gem_lifecycle.py#" \
    -e "s#/etc/gem/lifecycle.env#${ENV_FILE}#" \
    "$HERE/gem-lifecycle.service" > "$WORK/$UNIT"
install -d -m 0755 "$UNIT_DIR"
install -m 0644 "$WORK/$UNIT" "$UNIT_DIR/$UNIT"
"$SYSTEMCTL" daemon-reload || die "systemctl daemon-reload failed"
"$SYSTEMCTL" enable "$UNIT" >/dev/null 2>&1 || die "systemctl enable $UNIT failed"
"$SYSTEMCTL" restart "$UNIT" || { "$SYSTEMCTL" status "$UNIT" --no-pager -n 30 >&2 || true; die "systemctl restart $UNIT failed"; }
ok "installed $UNIT_DIR/$UNIT, enabled, (re)started"

# ----------------------------------------------------------------------------- 6. health
step "6/7 Health"
if ! as_gem "$PY" -I - > "$WORK/status.txt" 2>&1 <<'PY'
import json, os, time, urllib.request
bind = os.environ.get("GEM_LIFECYCLE_BIND", "127.0.0.1:8090")
base = "http://" + bind
tok = os.environ["GEM_LIFECYCLE_TOKEN"]
deadline = time.time() + 20
while True:
    try:
        with urllib.request.urlopen(base + "/health", timeout=2) as r:
            if json.loads(r.read()).get("status") == "ok":
                break
    except Exception:
        pass
    if time.time() > deadline:
        raise SystemExit(f"no /health from {base} after 20 s")
    time.sleep(0.5)
req = urllib.request.Request(base + "/status", headers={"Authorization": "Bearer " + tok})
st = json.loads(urllib.request.urlopen(req, timeout=5).read())
print(f"ok|listening on {bind}; B200 {st['b200']}; mode {'DRY' if st['dry_run'] else 'LIVE'}")
print(f"ok|spend today ${st['spend_day_usd']} of ${st['cap_day_usd']}, this week ${st['spend_week_usd']} of ${st['cap_week_usd']}")
print(f"ok|auto-delete {st['auto_delete']}")
if st.get("wake_disabled"):
    print(f"warn|wakes disabled: {st['wake_disabled']}")
else:
    print("ok|wakes enabled (gemctl heavy on, or a ds-main 429 storm)")
PY
then
  cat "$WORK/status.txt" >&2
  "$SYSTEMCTL" status "$UNIT" --no-pager -n 30 >&2 || true
  die "the controller did not come up"
fi
while IFS='|' read -r kind msg; do
  if [[ "$kind" == "warn" ]]; then warn "$msg"; else ok "$msg"; fi
done < "$WORK/status.txt"

# ----------------------------------------------------------------------------- 7. LiteLLM
step "7/7 LiteLLM callbacks"
# The lifecycle feed, the think-strip guardrail (WU-05) and the gemcore library the guardrail imports.
LITELLM_FILES=(gateway/gem_lifecycle_callback.py gateway/gem_guardrail.py mcp_reference_monitor.py)
if [[ -n "$LITELLM_DIR" ]]; then
  [[ -d "$LITELLM_DIR" ]] || die "--litellm-dir $LITELLM_DIR is not a directory"
  for f in "${LITELLM_FILES[@]}"; do
    install -m 0644 "$PKG/$f" "$LITELLM_DIR/$(basename "$f")"
  done
  ok "copied gem_lifecycle_callback.py, gem_guardrail.py and mcp_reference_monitor.py to $LITELLM_DIR"
  for cb in gem_lifecycle_callback gem_guardrail; do
    if grep -qs "${cb}.proxy_handler_instance" "$LITELLM_DIR"/*.yaml "$LITELLM_DIR"/*.yml; then
      ok "LiteLLM config lists ${cb}"
    else
      warn "add ${cb}.proxy_handler_instance to litellm_settings.callbacks (see gateway/litellm_config.v7.yaml)"
    fi
  done
else
  warn "not copied (no --litellm-dir): put ${LITELLM_FILES[*]} next to your LiteLLM config"
fi
if [[ -z "$PREFIX" ]] && command -v docker >/dev/null 2>&1; then
  while read -r cid; do
    [[ -n "$cid" ]] || continue
    net="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$net" != "host" ]]; then
      warn "LiteLLM runs in container $cid on network '$net': 127.0.0.1:8090 inside it is the container, not this host."
      warn "  Use --network host for LiteLLM, or tell me and I'll add a docker-bridge bind for the controller."
    fi
  done < <(docker ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null | grep -i litellm | cut -d' ' -f1)
fi
LITELLM_UNIT=""
if [[ -z "$PREFIX" ]]; then
  LITELLM_UNIT="$("$SYSTEMCTL" list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep -i litellm | head -1 || true)"
fi
if [[ -n "$LITELLM_UNIT" ]]; then
  warn "give LiteLLM the feed token: sudo systemctl edit $LITELLM_UNIT  → [Service] Environment=GEM_LIFECYCLE_FEED_TOKEN=<feed token>"
  warn "  then: sudo systemctl restart $LITELLM_UNIT"
else
  warn "give LiteLLM's process GEM_LIFECYCLE_FEED_TOKEN=<feed token> in its environment, then restart it"
fi

# ----------------------------------------------------------------------------- summary
cat <<EOF

${B}Done.${N} Three controller tokens, each only where it belongs (show one with
  sudo grep '^GEM_LIFECYCLE_FEED_TOKEN=' $ENV_FILE | cut -d= -f2-):
  GEM_LIFECYCLE_FEED_TOKEN     LiteLLM's environment (the callback: /touch, /signal/429)
  GEM_LIFECYCLE_SESSION_TOKEN  Termux, exported (Claude Code hooks: sessions and status)
  GEM_LIFECYCLE_TOKEN          operator (wake/sleep): Termux file ~/.gem/operator.token, mode 0600, never exported

On Termux:
  ssh -N -L 8000:127.0.0.1:8000 -L 8080:127.0.0.1:8080 -L 8090:127.0.0.1:8090 awsbox &
  (umask 077; mkdir -p ~/.gem; cat > ~/.gem/operator.token)   # paste the operator token, Enter, Ctrl-D
  export GEM_LIFECYCLE_SESSION_TOKEN=<session token>
  python3 install_hooks.py && source gateway/claude-gem.env && gem heavy status

Logs:     journalctl -u gem-lifecycle -f      (one JSON line per decision)
Go live:  sudo $HERE/deploy_awsbox.sh --live  (after a few days of DRY logs look right)
EOF
