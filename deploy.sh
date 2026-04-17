#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# SentinelAgent — Production Deployment Script
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh              # first run or routine update
#   ./deploy.sh --no-prune   # skip Docker image pruning (useful while debugging)
#
# What this script does (in order):
#   1. Validate prerequisites (.env file, Docker, Compose plugin)
#   2. Pull the latest code from Git
#   3. Ensure ./data directory exists (volume mount for SQLite)
#   4. Build the Docker image with --no-cache on first run, layer cache after
#   5. Restart services with zero manual steps
#   6. Prune dangling images to reclaim disk space (skip with --no-prune)
#   7. Print a live status summary
#
# Target OS: Ubuntu 24.04 · 1 GB RAM + Swap · Docker 25+
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail   # exit on error, unset var, or pipe failure

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Parse flags ───────────────────────────────────────────────────────────────
PRUNE=true
for arg in "$@"; do
  [[ "$arg" == "--no-prune" ]] && PRUNE=false
done

# ── 0. Banner ─────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║        SentinelAgent — Deploy Script         ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── 1. Validate prerequisites ─────────────────────────────────────────────────
info "Checking prerequisites…"

command -v docker  >/dev/null 2>&1 || die "Docker is not installed. Run: curl -fsSL https://get.docker.com | sh"
command -v git     >/dev/null 2>&1 || die "Git is not installed. Run: apt-get install -y git"

# Prefer the Compose V2 plugin (docker compose) over the legacy binary
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
  warn "Using legacy docker-compose. Consider upgrading to Docker Compose V2."
else
  die "Docker Compose not found. Install the Compose plugin: apt-get install docker-compose-plugin"
fi

success "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
success "Compose: $($COMPOSE version --short 2>/dev/null || echo 'legacy')"

# ── 2. .env guard ─────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  warn ".env not found — creating from .env.example"
  cp .env.example .env
  die "Please edit .env (set DEEPSEEK_API_KEY and ADMIN_PASSWORD) then re-run deploy.sh"
fi

# Refuse to start if the operator forgot to change the placeholder password
if grep -q "CHANGE_ME_BEFORE_DEPLOY" .env; then
  die "ADMIN_PASSWORD is still the default placeholder. Edit .env before deploying."
fi

# HIGH-01: Refuse to start if the API key still contains any placeholder string.
# The .env.example template uses "sk-REPLACE_WITH_YOUR_REAL_KEY" — catch that
# and any other obviously un-edited value.
DEEPSEEK_KEY_VAL=$(grep -E "^DEEPSEEK_API_KEY=" .env | cut -d= -f2-)
if [[ -z "$DEEPSEEK_KEY_VAL" || "$DEEPSEEK_KEY_VAL" == *"REPLACE"* || "$DEEPSEEK_KEY_VAL" == *"YOUR"* || "$DEEPSEEK_KEY_VAL" == *"xxxx"* ]]; then
  # Only enforce when provider is deepseek
  PROVIDER=$(grep -E "^LLM_PROVIDER=" .env | cut -d= -f2-)
  if [[ -z "$PROVIDER" || "$PROVIDER" == "deepseek" ]]; then
    die "DEEPSEEK_API_KEY still contains the placeholder value. Edit .env with your real API key."
  fi
fi

success ".env present, ADMIN_PASSWORD and DEEPSEEK_API_KEY are set"

# ── 3. Pull latest code ───────────────────────────────────────────────────────
info "Pulling latest code from Git…"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  BEFORE=$(git rev-parse --short HEAD)
  git pull --ff-only
  AFTER=$(git rev-parse --short HEAD)
  if [[ "$BEFORE" == "$AFTER" ]]; then
    info "Already up to date ($AFTER)."
  else
    success "Updated $BEFORE → $AFTER"
  fi
else
  warn "Not a Git repository — skipping git pull. Copy files manually if needed."
fi

# ── 4. Prepare data directory ─────────────────────────────────────────────────
info "Ensuring ./data directory exists for SQLite volume mount…"
mkdir -p ./data
# Grant write access to all users so the sentinel system user inside the
# container (whose UID differs from the host user's UID) can create and
# write the SQLite database file.  The directory holds only the audit DB —
# no secrets live here.
chmod 777 ./data
# If the DB file already exists, ensure it is readable by the dashboard
# container (which mounts the directory read-only).
if [[ -f ./data/sentinel_audit.db ]]; then
  chmod 644 ./data/sentinel_audit.db
  # WAL mode creates two sidecar files; fix those too if present
  [[ -f ./data/sentinel_audit.db-wal ]] && chmod 644 ./data/sentinel_audit.db-wal
  [[ -f ./data/sentinel_audit.db-shm ]] && chmod 644 ./data/sentinel_audit.db-shm
fi
success "./data ready (permissions set)"

# ── 5. Build image ────────────────────────────────────────────────────────────
info "Building Docker image (sentinel-agent:latest)…"
# Pass DOCKER_BUILDKIT for faster, more cache-efficient builds
DOCKER_BUILDKIT=1 $COMPOSE build --pull
success "Image built successfully"

# ── 6. Restart services ───────────────────────────────────────────────────────
info "Restarting services…"
$COMPOSE up -d --remove-orphans
success "Services started"

# ── 7. Prune dangling images ──────────────────────────────────────────────────
if $PRUNE; then
  info "Pruning dangling images to reclaim disk space…"
  FREED=$(docker image prune -f --filter "until=24h" 2>&1 | grep "reclaimed" || echo "nothing to prune")
  success "Prune complete: $FREED"
else
  info "Skipping image prune (--no-prune flag set)"
fi

# ── 8. Health summary ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── Container Status ──────────────────────────────${RESET}"
$COMPOSE ps
echo ""

# Wait briefly for health checks to settle, then report
sleep 5

echo -e "${BOLD}── Endpoint Smoke Tests ──────────────────────────${RESET}"

GW_URL="http://localhost:8000/health"
DB_URL="http://localhost:8501/_stcore/health"

if curl -sf "$GW_URL" >/dev/null 2>&1; then
  success "Gateway  → $GW_URL  ✓"
else
  warn    "Gateway  → $GW_URL  (not yet responding — check: docker compose logs gateway)"
fi

if curl -sf "$DB_URL" >/dev/null 2>&1; then
  success "Dashboard→ $DB_URL ✓"
else
  warn    "Dashboard→ $DB_URL (not yet responding — check: docker compose logs dashboard)"
fi

echo ""
echo -e "${BOLD}"
echo "  Gateway API  → http://$(hostname -I | awk '{print $1}'):8000"
echo "  Admin Panel  → http://127.0.0.1:8501  (SSH tunnel required — NOT public)"
echo "                 ssh -L 8501:localhost:8501 $(whoami)@$(hostname -I | awk '{print $1}')"
echo -e "${RESET}"
echo -e "${GREEN}${BOLD}Deployment complete.${RESET}"
