#!/usr/bin/env bash
# Reset the PT Kopi Senja demo to its clean starting state:
#   - reseed the source database from demo/seed.sql (plaintext NIKs, old rows, undeclared table)
#   - make sure the read-only scanner role exists and can read every demo table
#   - empty the evidence store, so the first scan starts a fresh hash chain
#
# Usage:  demo/reset.sh
#
# Environment (defaults suit a local Homebrew Postgres):
#   DEMO_ADMIN_URL     owner connection to the demo source database
#                      (default postgresql://localhost:5432/pdpg_source)
#   DEMO_RO_PASSWORD   password for the pdp_guardian_ro role when it is created (default ro_local)
#   PDP_EVIDENCE_URL   evidence store to empty (default sqlite:///pdp_guardian.db, as in the CLI)
#
# Needs psql on PATH.
set -euo pipefail

cd "$(dirname "$0")/.."

admin_url="${DEMO_ADMIN_URL:-postgresql://localhost:5432/pdpg_source}"
ro_password="${DEMO_RO_PASSWORD:-ro_local}"
evidence_url="${PDP_EVIDENCE_URL:-sqlite:///pdp_guardian.db}"
export PGOPTIONS="-c client_min_messages=warning"  # hide "already exists, skipping" notices
started=$SECONDS

echo "1/3 Seeding source database"
psql "$admin_url" --quiet --no-psqlrc -v ON_ERROR_STOP=1 -f demo/seed.sql

echo "2/3 Granting read-only access to pdp_guardian_ro"
psql "$admin_url" --quiet --no-psqlrc -v ON_ERROR_STOP=1 -v ro_password="$ro_password" <<'SQL'
SELECT format('CREATE ROLE pdp_guardian_ro LOGIN PASSWORD %L', :'ro_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pdp_guardian_ro') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO pdp_guardian_ro', current_database()) \gexec
GRANT USAGE ON SCHEMA public TO pdp_guardian_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pdp_guardian_ro;
SQL

echo "3/3 Emptying evidence store"
# HACKATHON: demo only. A real evidence store is append-only and never reset; here the
# chain is dropped so the rerun does not diff against the previous run's final scan.
case "$evidence_url" in
  sqlite:///*)
    rm -f "${evidence_url#sqlite:///}"
    ;;
  postgres://* | postgresql://*)
    psql "$evidence_url" --quiet --no-psqlrc -v ON_ERROR_STOP=1 \
      -c "DROP TABLE IF EXISTS evidence, evidence_diff"
    ;;
  *)
    echo "PDP_EVIDENCE_URL must start with sqlite:/// or postgresql://" >&2
    exit 1
    ;;
esac

echo "Demo reset in $((SECONDS - started))s. Next:"
echo "  uv run pdp-guardian scan --declaration demo/declaration.yaml --connector sqlurl \\"
echo "    --source-name cloudsql://kopi-senja/app --location asia-southeast2"
echo "  psql \"\${DEMO_ADMIN_URL:-postgresql://localhost:5432/pdpg_source}\" \\"
echo "    -f demo/migrate_encrypt_nik.sql   # then scan again"
