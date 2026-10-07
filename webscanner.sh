#!/usr/bin/env bash
set -uo pipefail
# ============================================================================
#  webscanner.sh — passive recon & attack-surface mapper for bug bounty triage
#
#  Crawls a target, maps its attack surface, and flags CANDIDATE endpoints
#  for manual testing against OWASP categories (Access Control, IDOR/BOLA,
#  Injection, SSRF, Insecure Design, Cryptographic Failures). It performs
#  PASSIVE analysis only: it reads what the server actually sends back
#  (headers, cookies, HTML, JS source, robots.txt) and never sends exploit
#  payloads, never fires SSRF probes, and never swaps IDs against live
#  accounts. Confirming a finding is a manual step (Burp/ZAP + human
#  judgment), by design.
#
#  Only run this against targets you are explicitly authorized to test.
# ============================================================================

VERSION="2.0.0"

RED='\033[91m'; BLUE='\033[94m'; MAGENTA='\033[95m'; CYAN='\033[96m'
YELLOW='\033[93m'; GREEN='\033[92m'; NC='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

# ---------------------------------------------------------------------------
# DEFAULTS
# ---------------------------------------------------------------------------
TARGET_URL=""
MAX_PAGES=50
MAX_DEPTH=3
DELAY=1
MAX_QUERY_VARIANTS=5
INCLUDE_SUBDOMAINS=0
OUT_DIR=""
WANT_JSON=0
WANT_HTML=0
QUIET=0

banner() {
  echo -e "${CYAN}${BOLD}"
  cat <<'EOF'
 __    __     _                                           
/ / /\ \ \___| |__  ___  ___ __ _ _ __  _ __   ___ _ __   
\ \/  \/ / _ \ '_ \/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|  
 \  /\  /  __/ |_) \__ \ (_| (_| | | | | | | |  __/ |     
  \/  \/ \___|_.__/|___/\___\__,_|_| |_|_| |_|\___|_|     
EOF
  echo -e "${NC}${DIM}  passive recon & attack-surface mapper  v${VERSION}${NC}"
  echo
}

usage() {
  cat <<EOF
Usage: $0 -u <url> [options]

  -u, --url URL              Target URL (e.g. https://example.com)
  -p, --max-pages N          Max pages to crawl                 (default: $MAX_PAGES)
  -d, --max-depth N          Max crawl depth                    (default: $MAX_DEPTH)
  -t, --delay SECONDS        Delay between requests              (default: $DELAY)
  -q, --max-query-variants N Max query-string variants per path  (default: $MAX_QUERY_VARIANTS)
  -s, --subdomains           Include subdomains in scope
  -o, --output-dir DIR       Output directory (default: scan_<host>_<timestamp>)
      --json                 Also write a machine-readable JSON report
      --html                 Also write a styled HTML report
      --quiet                Suppress the live per-page console output
  -h, --help                 Show this help and exit

If -u/--url is omitted, the script falls back to interactive prompts.

Example:
  $0 -u https://example.com -p 100 -d 4 -s --json --html
EOF
}

# ---------------------------------------------------------------------------
# ARG PARSING
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--url) TARGET_URL="$2"; shift 2 ;;
    -p|--max-pages) MAX_PAGES="$2"; shift 2 ;;
    -d|--max-depth) MAX_DEPTH="$2"; shift 2 ;;
    -t|--delay) DELAY="$2"; shift 2 ;;
    -q|--max-query-variants) MAX_QUERY_VARIANTS="$2"; shift 2 ;;
    -s|--subdomains) INCLUDE_SUBDOMAINS=1; shift ;;
    -o|--output-dir) OUT_DIR="$2"; shift 2 ;;
    --json) WANT_JSON=1; shift ;;
    --html) WANT_HTML=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) banner; usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

banner

# ---------------------------------------------------------------------------
# INTERACTIVE FALLBACK + VALIDATION
# ---------------------------------------------------------------------------
read_int() {
  local prompt="$1" default="$2" val
  while true; do
    read -rp "$prompt [$default]: " val
    val="${val:-$default}"
    [[ "$val" =~ ^[0-9]+$ ]] && { echo "$val"; return; }
    echo -e "${RED}[-] Please enter a non-negative integer.${NC}" >&2
  done
}
read_number() {
  local prompt="$1" default="$2" val
  while true; do
    read -rp "$prompt [$default]: " val
    val="${val:-$default}"
    [[ "$val" =~ ^[0-9]+(\.[0-9]+)?$ ]] && { echo "$val"; return; }
    echo -e "${RED}[-] Please enter a non-negative number.${NC}" >&2
  done
}

if [[ -z "$TARGET_URL" ]]; then
  read -rp "Enter the url: " TARGET_URL
  MAX_PAGES=$(read_int "Max pages to crawl" "$MAX_PAGES")
  MAX_DEPTH=$(read_int "Max depth" "$MAX_DEPTH")
  DELAY=$(read_number "Delay between requests in seconds" "$DELAY")
  MAX_QUERY_VARIANTS=$(read_int "Max query-string variants per path" "$MAX_QUERY_VARIANTS")
  read -rp "Include subdomains? (y/N): " sub_ans
  [[ "${sub_ans,,}" == "y" ]] && INCLUDE_SUBDOMAINS=1
else
  for pair in "MAX_PAGES:$MAX_PAGES" "MAX_DEPTH:$MAX_DEPTH" "MAX_QUERY_VARIANTS:$MAX_QUERY_VARIANTS"; do
    val="${pair#*:}"
    if [[ ! "$val" =~ ^[0-9]+$ ]]; then
      echo -e "${RED}[-] ${pair%%:*} must be a non-negative integer (got '$val')${NC}"; exit 1
    fi
  done
  if [[ ! "$DELAY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo -e "${RED}[-] --delay must be a non-negative number (got '$DELAY')${NC}"; exit 1
  fi
fi

if [[ "$TARGET_URL" =~ ^https?:// ]]; then
  base_url="$TARGET_URL"
else
  base_url="https://$TARGET_URL"
fi

domain=$(echo "$base_url" | grep -oE '^https?://[^/]+')
if [[ -z "$domain" ]]; then
  echo -e "${RED}[!] Could not determine domain from '$TARGET_URL', aborting${NC}"; exit 1
fi
host="${domain#http://}"; host="${host#https://}"

# ---------------------------------------------------------------------------
# OUTPUT DIR
# ---------------------------------------------------------------------------
if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="scan_${host//[:\/]/_}_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUT_DIR"

CURL_OPTS=(-sL --max-time 15 --connect-timeout 7 -A "Mozilla/5.0 (compatible; WebScanner/${VERSION})")

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

queue_file="$tmp_dir/queue.txt"
visited_file="$tmp_dir/visited.txt"
path_variant_count="$tmp_dir/path_variants.txt"
curl_err="$tmp_dir/curl_err.txt"
js_visited="$tmp_dir/js_visited.txt"

endpoints_file="$OUT_DIR/endpoints.txt"
external_file="$OUT_DIR/external_links.txt"
headers_report="$OUT_DIR/headers_report.txt"
cookie_report="$OUT_DIR/cookie_report.txt"
redirect_report="$OUT_DIR/redirect_report.txt"
forms_report="$OUT_DIR/forms_report.txt"
idor_candidates="$OUT_DIR/idor_bola_candidates.txt"
ssrf_candidates="$OUT_DIR/ssrf_param_candidates.txt"
sensitive_paths="$OUT_DIR/sensitive_paths.txt"
mixed_content_report="$OUT_DIR/mixed_content_report.txt"
js_endpoints_file="$OUT_DIR/js_discovered_endpoints.txt"
common_paths_report="$OUT_DIR/common_paths_found.txt"
summary_file="$OUT_DIR/summary_report.txt"
json_file="$OUT_DIR/report.json"
html_file="$OUT_DIR/report.html"

for f in "$endpoints_file" "$external_file" "$headers_report" "$cookie_report" \
         "$redirect_report" "$forms_report" "$idor_candidates" "$ssrf_candidates" \
         "$sensitive_paths" "$mixed_content_report" "$js_endpoints_file" \
         "$common_paths_report" "$summary_file"; do
  : > "$f"
done
: > "$queue_file"; : > "$visited_file"; : > "$path_variant_count"; : > "$js_visited"

echo "$base_url|0" >> "$queue_file"

log() { [[ "$QUIET" -eq 1 ]] || echo -e "$1"; }

# ---------------------------------------------------------------------------
# URL RESOLUTION (handles ../ and ./ correctly)
# ---------------------------------------------------------------------------
resolve_path() {
  local path="$1"
  local IFS='/'
  local -a parts=() stack=()
  read -ra parts <<< "$path"
  for seg in "${parts[@]}"; do
    case "$seg" in
      ""|".") continue ;;
      "..") [[ ${#stack[@]} -gt 0 ]] && unset 'stack[-1]' ;;
      *) stack+=("$seg") ;;
    esac
  done
  local out="/"
  [[ ${#stack[@]} -gt 0 ]] && out="/$(IFS=/; echo "${stack[*]}")"
  echo "$out"
}

normalize_url() {
  local link="$1" current_page="$2"
  link="${link%%#*}"
  [[ -z "$link" ]] && return
  case "$link" in
    javascript:*|mailto:*|tel:*|data:*) return ;;
    http://*|https://*) echo "$link"; return ;;
    //*) echo "https:$link"; return ;;
  esac

  local cur_domain cur_path
  cur_domain=$(echo "$current_page" | grep -oE '^https?://[^/]+')
  cur_path="${current_page#"$cur_domain"}"
  [[ "$cur_path" != /* ]] && cur_path="/"

  local query=""
  if [[ "$link" == *\?* ]]; then
    query="?${link#*\?}"
    link="${link%%\?*}"
  fi

  local resolved_path
  if [[ "$link" == /* ]]; then
    resolved_path=$(resolve_path "$link")
  else
    local cur_dir="${cur_path%/*}"
    [[ -z "$cur_dir" ]] && cur_dir="/"
    resolved_path=$(resolve_path "${cur_dir}/${link}")
  fi
  echo "${cur_domain}${resolved_path}${query}"
}

in_scope() {
  local abs="$1"
  local abs_host="${abs#http://}"; abs_host="${abs_host#https://}"
  abs_host="${abs_host%%/*}"
  [[ "$abs_host" == "$host" ]] && return 0
  [[ "$INCLUDE_SUBDOMAINS" -eq 1 && "$abs_host" == *".$host" ]] && return 0
  return 1
}

# ---------------------------------------------------------------------------
# PASSIVE ANALYSIS HELPERS
# ---------------------------------------------------------------------------
check_header() {
  local header="$1" headers="$2" url="$3"
  if grep -qi "^${header}:" <<< "$headers"; then
    log "  ${GREEN}[+] ${header}: Present${NC}"
  else
    log "  ${RED}[-] ${header}: Missing${NC}"
    echo "$url | missing $header" >> "$headers_report"
  fi
}

check_cookies() {
  local headers="$1" url="$2"
  local cookies; cookies=$(grep -i '^set-cookie:' <<< "$headers" || true)
  [[ -z "$cookies" ]] && return
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local name flags=""
    name=$(sed -E 's/^set-cookie:\s*//i' <<< "$line" | cut -d'=' -f1)
    grep -qi 'secure'   <<< "$line" || flags+="missing-Secure "
    grep -qi 'httponly' <<< "$line" || flags+="missing-HttpOnly "
    grep -qi 'samesite' <<< "$line" || flags+="missing-SameSite "
    if [[ -n "$flags" ]]; then
      log "  ${RED}[-] Cookie '$name': $flags${NC}"
      echo "$url | cookie=$name | $flags" >> "$cookie_report"
    fi
  done <<< "$cookies"
}

flag_idor_candidates() {
  local url="$1" query="${1#*\?}"
  [[ "$query" == "$url" ]] && query=""
  if [[ -n "$query" ]]; then
    IFS='&' read -ra pairs <<< "$query"
    for p in "${pairs[@]}"; do
      local key="${p%%=*}" val="${p#*=}"
      if [[ "$key" =~ ^(id|uid|user_id|userid|account|acct|order|order_id|doc|document|file_id|ref|token|object_id)$ ]] \
         || [[ "$val" =~ ^[0-9]+$ ]] \
         || [[ "$val" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        echo "$url | param=$key | value=$val" >> "$idor_candidates"
        break
      fi
    done
  fi
  [[ "$url" =~ /[A-Za-z_]+/[0-9]+(/|$|\?) ]] && echo "$url | path-based numeric ID" >> "$idor_candidates"
}

flag_ssrf_candidates() {
  local url="$1" query="${1#*\?}"
  [[ "$query" == "$url" ]] && return
  IFS='&' read -ra pairs <<< "$query"
  for p in "${pairs[@]}"; do
    local key="${p%%=*}"
    if [[ "$key" =~ ^(url|uri|path|dest|destination|redirect|redirect_uri|return|return_url|next|callback|webhook|target|host|domain|src|fetch|proxy|out|continue)$ ]]; then
      echo "$url | param=$key" >> "$ssrf_candidates"
    fi
  done
}

flag_sensitive_path() {
  local url="$1"
  if [[ "$url" =~ /(admin|administrator|internal|dashboard|manage|account|settings|config|api/v[0-9]+|api/internal|upload|download|export|import|reset[-_]?password|forgot[-_]?password|change[-_]?password|login|signin|signup|register|auth|oauth|token|session|impersonate|debug|backup|graphql|swagger|\.git|\.env) ]]; then
    echo "$url" >> "$sensitive_paths"
  fi
}

# Common sensitive files/paths — existence check only (standard recon, like a
# small dirb/gobuster wordlist), no exploitation of whatever is found.
check_common_paths() {
  log "${BLUE}-------------------------${NC}"
  log "${MAGENTA}Checking common sensitive paths...${NC}"
  local wordlist=(
    "/robots.txt" "/sitemap.xml" "/.well-known/security.txt"
    "/.git/HEAD" "/.env" "/.env.local" "/.DS_Store" "/.htaccess"
    "/wp-admin/" "/wp-login.php" "/admin/" "/administrator/"
    "/api/" "/api/docs" "/api-docs" "/swagger.json" "/swagger-ui.html"
    "/graphql" "/server-status" "/.aws/credentials" "/config.php.bak"
    "/backup.zip" "/backup.sql" "/phpinfo.php" "/actuator/health"
    "/.well-known/openid-configuration"
  )
  for p in "${wordlist[@]}"; do
    local full="${domain}${p}"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 --connect-timeout 5 \
      -A "Mozilla/5.0 (compatible; WebScanner/${VERSION})" "$full" 2>/dev/null || echo "000")
    if [[ "$code" == 2* || "$code" == 3* ]]; then
      log "  ${YELLOW}[i] $p -> HTTP $code${NC}"
      echo "$full | HTTP $code" >> "$common_paths_report"
    fi
    sleep 0.2
  done
}

# Pull robots.txt and sitemap.xml paths into the crawl queue
seed_from_robots_sitemap() {
  log "${MAGENTA}Seeding from robots.txt / sitemap.xml...${NC}"
  local robots body
  robots=$(curl "${CURL_OPTS[@]}" "${domain}/robots.txt" 2>/dev/null || true)
  if [[ -n "$robots" ]]; then
    while IFS= read -r p; do
      p=$(echo "$p" | tr -d '\r')
      [[ -z "$p" || "$p" == "/" ]] && continue
      local abs="${domain}${p}"
      grep -qxF "$abs" "$visited_file" 2>/dev/null || echo "${abs}|1" >> "$queue_file"
    done < <(grep -oiE '^(Dis)?[Aa]llow:[[:space:]]*/[^[:space:]]*' <<< "$robots" | sed -E 's/^[^:]+:[[:space:]]*//')

    sitemap_url=$(grep -ioE 'Sitemap:[[:space:]]*\S+' <<< "$robots" | sed -E 's/Sitemap:[[:space:]]*//i' | head -n1)
    if [[ -n "$sitemap_url" ]]; then
      body=$(curl "${CURL_OPTS[@]}" "$sitemap_url" 2>/dev/null || true)
      while IFS= read -r loc; do
        loc=$(echo "$loc" | sed -E 's#</?loc>##g' | tr -d '\r')
        [[ -z "$loc" ]] && continue
        in_scope "$loc" && { grep -qxF "$loc" "$visited_file" 2>/dev/null || echo "${loc}|1" >> "$queue_file"; }
      done < <(grep -oE '<loc>[^<]+</loc>' <<< "$body")
    fi
  fi
}

# Mine a .js file for endpoint-looking string literals (passive — no execution)
mine_js_endpoints() {
  local js_url="$1"
  grep -qxF "$js_url" "$js_visited" 2>/dev/null && return
  echo "$js_url" >> "$js_visited"
  local body
  body=$(curl "${CURL_OPTS[@]}" --max-time 10 "$js_url" 2>/dev/null || true)
  [[ -z "$body" ]] && return
  grep -oE "[\"'](/[A-Za-z0-9_/-]{2,80})[\"']" <<< "$body" \
    | tr -d "\"'" | sort -u | while read -r p; do
      [[ "$p" =~ \.(png|jpe?g|gif|svg|css|woff2?|ttf)$ ]] && continue
      echo "$js_url | $p" >> "$js_endpoints_file"
    done
}

# ---------------------------------------------------------------------------
# CRAWL
# ---------------------------------------------------------------------------
pages_crawled=0
log "${BOLD}${CYAN}===== CRAWLING $domain =====${NC}"
log "${CYAN}(passive recon only — no exploit payloads are sent)${NC}"

check_common_paths
seed_from_robots_sitemap

while [[ -s "$queue_file" ]] && (( pages_crawled < MAX_PAGES )); do
  line=$(head -n1 "$queue_file"); sed -i '1d' "$queue_file"
  current_url="${line%|*}"; current_depth="${line##*|}"
  current_url=$(printf '%s' "$current_url" | tr -d '\r')

  grep -qxF "$current_url" "$visited_file" 2>/dev/null && continue
  echo "$current_url" >> "$visited_file"

  path_only="${current_url%%\?*}"
  variant_count=$(grep -c "^${path_only}|" "$path_variant_count" 2>/dev/null || true)
  variant_count="${variant_count:-0}"
  if [[ "$current_url" == *\?* ]]; then
    (( variant_count >= MAX_QUERY_VARIANTS )) && continue
    echo "${path_only}|x" >> "$path_variant_count"
  fi

  (( current_depth > MAX_DEPTH )) && continue

  log "${BLUE}-------------------------${NC}"
  log "${GREEN}[*] [depth $current_depth] ${YELLOW}$current_url${NC}"

  tmp_body="$tmp_dir/body.html"; tmp_hdr="$tmp_dir/hdr.txt"
  : > "$curl_err"

  stats=$(curl "${CURL_OPTS[@]}" -D "$tmp_hdr" -o "$tmp_body" \
    -w '%{http_code}|%{content_type}|%{url_effective}' "$current_url" 2>"$curl_err")
  rc=$?
  if (( rc != 0 )); then
    log "${RED}[-] Failed to fetch: $(cat "$curl_err")${NC}"
    continue
  fi
  IFS='|' read -r status_code content_type final_url <<< "$stats"

  if [[ "$final_url" != "$current_url" ]]; then
    log "  ${YELLOW}[~] Redirected to: $final_url${NC}"
    echo "$current_url -> $final_url" >> "$redirect_report"
    if [[ "$final_url" =~ /(login|signin|sso|auth) ]]; then
      log "  ${MAGENTA}[!] Bounced to an auth page — access-control test candidate${NC}"
      echo "$current_url | redirected to login: $final_url" >> "$sensitive_paths"
    fi
  fi

  if [[ "$status_code" != 2* && "$status_code" != 3* ]]; then
    log "${RED}[-] HTTP $status_code${NC}"
    echo "$current_url | HTTP $status_code" >> "$endpoints_file"
    continue
  fi

  log "  ${GREEN}[+] HTTP $status_code  ($content_type)${NC}"
  echo "$current_url" >> "$endpoints_file"
  ((pages_crawled++))

  flag_idor_candidates "$current_url"
  flag_ssrf_candidates "$current_url"
  flag_sensitive_path "$current_url"

  headers=$(tr -d '\r' < "$tmp_hdr" | awk 'BEGIN{RS="";ORS="\n\n"} {last=$0} END{print last}')
  for h in Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options; do
    check_header "$h" "$headers" "$current_url"
  done
  check_cookies "$headers" "$current_url"

  srv=$(grep -i '^server:' <<< "$headers" | head -n1 | sed -E 's/^[Ss]erver:\s*//')
  pow=$(grep -i '^x-powered-by:' <<< "$headers" | head -n1 | sed -E 's/^[Xx]-[Pp]owered-[Bb]y:\s*//')
  [[ -n "$srv" ]] && log "  ${YELLOW}[i] Server: $srv${NC}"
  [[ -n "$pow" ]] && log "  ${YELLOW}[i] X-Powered-By: $pow${NC}"

  [[ "$content_type" != *"text/html"* ]] && continue

  if [[ "$current_url" == https://* ]]; then
    mixed=$(grep -oE '(src|href)="http://[^"]+"' "$tmp_body" 2>/dev/null || true)
    if [[ -n "$mixed" ]]; then
      log "  ${RED}[-] Mixed content found${NC}"
      while IFS= read -r m; do echo "$current_url | $m" >> "$mixed_content_report"; done <<< "$mixed"
    fi
  fi

  forms=$(grep -oiE '<form[^>]*>' "$tmp_body" 2>/dev/null || true)
  if [[ -n "$forms" ]]; then
    while IFS= read -r form_tag; do
      faction=$(grep -oiE 'action="[^"]*"' <<< "$form_tag" | sed -E 's/action="//i; s/"$//' || true)
      fmethod=$(grep -oiE 'method="[^"]*"' <<< "$form_tag" | sed -E 's/method="//i; s/"$//' || true)
      fmethod="${fmethod:-GET}"
      echo "$current_url | action=${faction:-<same page>} | method=${fmethod^^}" >> "$forms_report"
    done <<< "$forms"
    inputs=$(grep -oiE '<input[^>]*name="[^"]*"[^>]*>' "$tmp_body" 2>/dev/null || true)
    has_csrf=$(grep -ioE 'name="[^"]*(csrf|token|_token|authenticity)[^"]*"' <<< "$inputs" || true)
    if [[ -z "$has_csrf" ]]; then
      log "  ${RED}[-] Form(s) with no obvious CSRF field${NC}"
      echo "$current_url | no CSRF-looking field in form inputs" >> "$forms_report"
    fi
  fi

  links=$(grep -oE "(href|src|action)=[\"'][^\"']+[\"']" "$tmp_body" 2>/dev/null \
    | sed -E "s/^(href|src|action)=[\"']//; s/[\"']$//")

  while IFS= read -r raw_link; do
    [[ -z "$raw_link" ]] && continue
    abs=$(normalize_url "$raw_link" "$current_url")
    [[ -z "$abs" ]] && continue

    if ! in_scope "$abs"; then
      echo "$abs" >> "$external_file"
      continue
    fi

    if [[ "$abs" =~ \.js(\?|$) ]]; then
      mine_js_endpoints "$abs"
      continue
    fi
    [[ "$abs" =~ \.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip)(\?|$) ]] && continue

    grep -qxF "$abs" "$visited_file" 2>/dev/null || echo "${abs}|$((current_depth + 1))" >> "$queue_file"
  done <<< "$links"

  sleep "$DELAY"
done

# ---------------------------------------------------------------------------
# DEDUPE
# ---------------------------------------------------------------------------
for f in "$endpoints_file" "$external_file" "$headers_report" "$cookie_report" \
         "$redirect_report" "$forms_report" "$idor_candidates" "$ssrf_candidates" \
         "$sensitive_paths" "$mixed_content_report" "$js_endpoints_file" "$common_paths_report"; do
  sort -u "$f" -o "$f"
done

count() { wc -l < "$1" | tr -d ' '; }

# ---------------------------------------------------------------------------
# SEVERITY SCORE (rough, for triage prioritization only)
# ---------------------------------------------------------------------------
score=0
score=$(( score + $(count "$idor_candidates") * 3 ))
score=$(( score + $(count "$ssrf_candidates") * 4 ))
score=$(( score + $(count "$sensitive_paths") * 2 ))
score=$(( score + $(count "$headers_report") * 1 ))
score=$(( score + $(count "$cookie_report") * 2 ))
score=$(( score + $(count "$mixed_content_report") * 2 ))
score=$(( score + $(count "$common_paths_report") * 3 ))

risk_label="Low"
(( score >= 15 )) && risk_label="Medium"
(( score >= 35 )) && risk_label="High"

# ---------------------------------------------------------------------------
# TEXT SUMMARY
# ---------------------------------------------------------------------------
{
  echo "===================================================================="
  echo " WEBSCANNER RECON SUMMARY — $domain"
  echo " Generated: $(date)"
  echo " Triage score: $score  (rough priority indicator, not a CVSS score)"
  echo " Attack-surface size: $risk_label"
  echo "===================================================================="
  echo
  echo "Pages crawled:               $pages_crawled"
  echo "In-scope endpoints:          $(count "$endpoints_file")"
  echo "External links (not tested): $(count "$external_file")"
  echo "JS-mined endpoints:          $(count "$js_endpoints_file")"
  echo
  echo "---- Common sensitive paths found -----------------------------------"
  cat "$common_paths_report"
  echo
  echo "---- Access Control / IDOR / BOLA candidates -------------------------"
  cat "$idor_candidates"
  echo
  echo "---- SSRF param candidates --------------------------------------------"
  cat "$ssrf_candidates"
  echo
  echo "---- Sensitive / high-value paths ---------------------------------------"
  cat "$sensitive_paths"
  echo
  echo "---- Missing security headers --------------------------------------------"
  cat "$headers_report"
  echo
  echo "---- Cookie flag issues ------------------------------------------------------"
  cat "$cookie_report"
  echo
  echo "---- Mixed content (transport/crypto weakness) -----------------------------"
  cat "$mixed_content_report"
  echo
  echo "---- Redirects observed --------------------------------------------------------"
  cat "$redirect_report"
  echo
  echo "---- Forms discovered -------------------------------------------------------------"
  cat "$forms_report"
  echo
  echo "---- Endpoints discovered via JS source -----------------------------------------------"
  cat "$js_endpoints_file"
} > "$summary_file"

# ---------------------------------------------------------------------------
# JSON REPORT
# ---------------------------------------------------------------------------
if [[ "$WANT_JSON" -eq 1 ]]; then
  to_json_array() {
    local f="$1"
    if [[ ! -s "$f" ]]; then echo "[]"; return; fi
    python3 - "$f" <<'PYEOF' 2>/dev/null || awk 'BEGIN{print "["} {gsub(/"/,"\\\"",$0); printf "%s\"%s\"", (NR>1?",":""), $0} END{print "]"}' "$f"
import json, sys
with open(sys.argv[1]) as fh:
    lines = [l.rstrip("\n") for l in fh if l.strip()]
print(json.dumps(lines))
PYEOF
  }

  {
    echo "{"
    echo "  \"target\": \"$domain\","
    echo "  \"generated\": \"$(date -Iseconds 2>/dev/null || date)\","
    echo "  \"pages_crawled\": $pages_crawled,"
    echo "  \"triage_score\": $score,"
    echo "  \"risk_label\": \"$risk_label\","
    echo "  \"endpoints\": $(to_json_array "$endpoints_file"),"
    echo "  \"external_links\": $(to_json_array "$external_file"),"
    echo "  \"common_paths_found\": $(to_json_array "$common_paths_report"),"
    echo "  \"idor_bola_candidates\": $(to_json_array "$idor_candidates"),"
    echo "  \"ssrf_param_candidates\": $(to_json_array "$ssrf_candidates"),"
    echo "  \"sensitive_paths\": $(to_json_array "$sensitive_paths"),"
    echo "  \"missing_headers\": $(to_json_array "$headers_report"),"
    echo "  \"cookie_issues\": $(to_json_array "$cookie_report"),"
    echo "  \"mixed_content\": $(to_json_array "$mixed_content_report"),"
    echo "  \"redirects\": $(to_json_array "$redirect_report"),"
    echo "  \"forms\": $(to_json_array "$forms_report"),"
    echo "  \"js_discovered_endpoints\": $(to_json_array "$js_endpoints_file")"
    echo "}"
  } > "$json_file"
fi

# ---------------------------------------------------------------------------
# HTML REPORT
# ---------------------------------------------------------------------------
if [[ "$WANT_HTML" -eq 1 ]]; then
  html_rows() {
    local f="$1"
    if [[ ! -s "$f" ]]; then echo "<tr><td class=\"empty\" colspan=\"2\">None found</td></tr>"; return; fi
    while IFS= read -r line; do
      esc=$(echo "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
      echo "<tr><td>${esc}</td></tr>"
    done < "$f"
  }

  cat > "$html_file" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebScanner Report — $domain</title>
<style>
  :root { color-scheme: dark; }
  body { background:#0d1117; color:#c9d1d9; font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0; padding:2rem; }
  h1 { color:#58a6ff; margin-bottom:0.2rem; }
  .meta { color:#8b949e; margin-bottom:2rem; font-size:0.9rem; }
  .score { display:inline-block; padding:0.3rem 0.8rem; border-radius:6px; font-weight:bold; }
  .score.Low { background:#1f6feb33; color:#58a6ff; }
  .score.Medium { background:#9e6a0333; color:#d29922; }
  .score.High { background:#da363333; color:#f85149; }
  section { margin-bottom:2rem; border:1px solid #30363d; border-radius:8px; padding:1rem 1.2rem; background:#161b22; }
  section h2 { margin-top:0; font-size:1.05rem; color:#e6edf3; border-bottom:1px solid #30363d; padding-bottom:0.5rem; }
  table { width:100%; border-collapse:collapse; font-size:0.85rem; }
  td { padding:0.35rem 0.4rem; border-bottom:1px solid #21262d; word-break:break-all; }
  td.empty { color:#484f58; font-style:italic; }
  .count { float:right; color:#8b949e; font-weight:normal; }
  code { background:#21262d; padding:0.1rem 0.3rem; border-radius:4px; }
</style>
</head>
<body>
  <h1>WebScanner Report</h1>
  <div class="meta">
    Target: <code>$domain</code> &nbsp;|&nbsp;
    Generated: $(date) &nbsp;|&nbsp;
    Pages crawled: $pages_crawled &nbsp;|&nbsp;
    Triage score: <span class="score $risk_label">$score ($risk_label)</span>
  </div>

  <section><h2>Common sensitive paths found <span class="count">$(count "$common_paths_report")</span></h2><table>$(html_rows "$common_paths_report")</table></section>
  <section><h2>Access Control / IDOR / BOLA candidates <span class="count">$(count "$idor_candidates")</span></h2><table>$(html_rows "$idor_candidates")</table></section>
  <section><h2>SSRF param candidates <span class="count">$(count "$ssrf_candidates")</span></h2><table>$(html_rows "$ssrf_candidates")</table></section>
  <section><h2>Sensitive / high-value paths <span class="count">$(count "$sensitive_paths")</span></h2><table>$(html_rows "$sensitive_paths")</table></section>
  <section><h2>Missing security headers <span class="count">$(count "$headers_report")</span></h2><table>$(html_rows "$headers_report")</table></section>
  <section><h2>Cookie flag issues <span class="count">$(count "$cookie_report")</span></h2><table>$(html_rows "$cookie_report")</table></section>
  <section><h2>Mixed content <span class="count">$(count "$mixed_content_report")</span></h2><table>$(html_rows "$mixed_content_report")</table></section>
  <section><h2>Redirects observed <span class="count">$(count "$redirect_report")</span></h2><table>$(html_rows "$redirect_report")</table></section>
  <section><h2>Forms discovered <span class="count">$(count "$forms_report")</span></h2><table>$(html_rows "$forms_report")</table></section>
  <section><h2>JS-mined endpoints <span class="count">$(count "$js_endpoints_file")</span></h2><table>$(html_rows "$js_endpoints_file")</table></section>
  <section><h2>All in-scope endpoints <span class="count">$(count "$endpoints_file")</span></h2><table>$(html_rows "$endpoints_file")</table></section>
</body>
</html>
HTMLEOF
fi

# ---------------------------------------------------------------------------
# FINAL CONSOLE SUMMARY
# ---------------------------------------------------------------------------
echo -e "${BLUE}=====================================================${NC}"
echo -e "${BOLD}${GREEN}Crawl finished. ${pages_crawled} pages visited. Triage score: ${score} (${risk_label})${NC}"
echo -e "${GREEN}[+] Output directory:         ${YELLOW}$OUT_DIR${NC}"
echo -e "${GREEN}[+] Full text summary:        ${YELLOW}$summary_file${NC}"
[[ "$WANT_JSON" -eq 1 ]] && echo -e "${GREEN}[+] JSON report:              ${YELLOW}$json_file${NC}"
[[ "$WANT_HTML" -eq 1 ]] && echo -e "${GREEN}[+] HTML report:              ${YELLOW}$html_file${NC}"
echo -e "${BLUE}=====================================================${NC}"
