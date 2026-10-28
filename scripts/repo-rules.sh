#!/usr/bin/env bash
# Docelowe zabezpieczenia repo sejfu (README, „Zabezpieczenia repo”). Idempotentne; wymaga `gh`
# zalogowanego jako administrator repo. Uruchomienie: bash scripts/repo-rules.sh
set -euo pipefail
R=repos/bobik-2/bobik-2.github.io
CHECKS_APP=15368 # GitHub Actions

# Ustawienia repo: wyłącznie merge commitem (otagowany commit musi zostać w historii main).
gh api -X PATCH "$R" -F allow_merge_commit=true -F allow_squash_merge=false -F allow_rebase_merge=false \
  --jq '{allow_merge_commit, allow_squash_merge, allow_rebase_merge}'

ruleset_id() { gh api "$R/rulesets" --jq ".[] | select(.name == \"$1\") | .id"; }

put_ruleset() { # $1 = nazwa, stdin = JSON
  local id body
  body=$(cat)
  id=$(ruleset_id "$1")
  if [ -n "$id" ]; then
    gh api -X PUT "$R/rulesets/$id" --input - <<<"$body" --jq '{id, name, enforcement}'
  else
    gh api -X POST "$R/rulesets" --input - <<<"$body" --jq '{id, name, enforcement}'
  fi
}

put_ruleset main <<JSON
{"name": "main", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "bypass_actors": [],
 "rules": [
  {"type": "deletion"},
  {"type": "non_fast_forward"},
  {"type": "required_signatures"},
  {"type": "pull_request", "parameters": {"allowed_merge_methods": ["merge"], "dismiss_stale_reviews_on_push": false,
    "require_code_owner_review": false, "require_last_push_approval": false, "required_approving_review_count": 0,
    "required_review_thread_resolution": false}},
  {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": false, "do_not_enforce_on_create": false,
    "required_status_checks": [{"context": "test", "integration_id": $CHECKS_APP}, {"context": "build", "integration_id": $CHECKS_APP}]}}
 ]}
JSON

# Tagi wydań: tworzy, przesuwa i usuwa wyłącznie administrator repo (rola 5 = admin); podpisane.
put_ruleset "tagi v*" <<'JSON'
{"name": "tagi v*", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
 "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}, {"type": "required_signatures"}]}
JSON
