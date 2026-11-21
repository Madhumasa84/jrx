#!/usr/bin/env bash
# Read Git objects as data. Never check out the proposed merge.
set -euo pipefail

ref="refs/pull/$PR/merge"
ref_status=conflict
for attempt in 1 2 3 4 5; do
  if git fetch --quiet --no-tags --depth=2 origin "$ref" 2>/dev/null; then
    merge=$(git rev-parse FETCH_HEAD)
    parents=$(git show -s --format=%P "$merge")
    if [[ "$parents" == "$BASE $HEAD_SHA" && "${EXPECTED_MERGE:-$merge}" == "$merge" ]]; then
      ref_status=ok
      break
    fi
    ref_status=stale
  else
    # Only classify an absent ref as a conflict. Authentication or transport
    # failures leave the check unassessed.
    rc=0
    git ls-remote --exit-code origin "$ref" >/dev/null 2>&1 || rc=$?
    case "$rc" in
      0) exit 2 ;;
      2) ref_status=conflict ;;
      *) exit 2 ;;
    esac
  fi
  if [[ $attempt != 5 ]]; then sleep 2; fi
done

echo "ref_status=$ref_status" >> "$GITHUB_OUTPUT"
if [[ "$ref_status" != ok ]]; then
  echo 'changed=false' >> "$GITHUB_OUTPUT"
  exit 2
fi

base_entry=$(git ls-tree "$BASE" -- "$POLICY")
merge_entry=$(git ls-tree "$merge" -- "$POLICY")
if [[ -z "$base_entry" && -z "$merge_entry" ]]; then
  echo 'changed=false' >> "$GITHUB_OUTPUT"
  exit 0
fi
for rev in "$BASE" "$merge"; do
  mode=$(git ls-tree "$rev" -- "$POLICY" | cut -d' ' -f1)
  size=0
  if [[ "$mode" == 100644 ]]; then size=$(git cat-file -s "$rev:$POLICY"); fi
  if [[ "$mode" != 100644 ]] || (( size > 1048576 )); then
    echo "Both policies must be non-executable regular files of at most 1 MiB." >&2
    echo 'changed=false' >> "$GITHUB_OUTPUT"
    exit 2
  fi
done
if [[ "$base_entry" == "$merge_entry" ]]; then
  echo 'changed=false' >> "$GITHUB_OUTPUT"
  exit 0
fi
if [[ -n "${EXPECTED_MERGE:-}" ]]; then
  git cat-file blob "$BASE:$POLICY" > "$RUNNER_TEMP/base.yaml"
  git cat-file blob "$merge:$POLICY" > "$RUNNER_TEMP/candidate.yaml"
fi
printf 'changed=true\nmerge=%s\n' "$merge" >> "$GITHUB_OUTPUT"
