#!/usr/bin/env bash
# Build INDEX.md for a notification-digest run — pure bash/awk/sed/sort, no Python.
#
# Reads every report in <run-dir>/items/*.md, parses its frontmatter, sorts
# newest-to-oldest by `updated_at`, groups by priority, and writes
# <run-dir>/INDEX.md. Links are repo-relative by default; if a `.drafts-remote`
# config is found walking up from <run-dir> (one line: "owner/repo" or a repo URL,
# optional "#branch"), links become absolute github.com blob URLs so the digest
# can hand out tappable links. A human-written lede is preserved across re-runs.
#
#   usage: build_index.sh <run-dir>
set -uo pipefail

RUN="${1:?usage: build_index.sh <run-dir>}"
ITEMS="$RUN/items"
[ -d "$ITEMS" ] || { echo "no items/ directory under $RUN" >&2; exit 1; }
DATE="$(basename "$RUN")"
OUT="$RUN/INDEX.md"
PLACEHOLDER='> _Lede pending._ <!-- LEDE -->'
SEP=$'\037'   # unit separator: a non-whitespace field delimiter so EMPTY fields
              # (e.g. a CheckSuite with no number) survive `read`/sort/awk.

# --- discover the absolute blob base from .drafts-remote (walk up to 4 levels) ---
base=""
d="$(cd "$RUN" && pwd)"
for _ in 1 2 3 4; do
  if [ -f "$d/.drafts-remote" ]; then
    slug="$(head -n1 "$d/.drafts-remote" | tr -d '[:space:]')"
    if [ -n "$slug" ]; then
      branch=main
      case "$slug" in *"#"*) branch="${slug#*#}"; slug="${slug%%#*}";; esac
      slug="${slug#https://github.com/}"; slug="${slug%.git}"; slug="${slug#/}"; slug="${slug%/}"
      if [ -n "$slug" ]; then base="https://github.com/$slug/blob/$branch/triage/$DATE/items"; fi
    fi
    break
  fi
  if [ "$d" = "/" ]; then break; fi
  d="$(dirname "$d")"
done

# --- frontmatter extractor: prints "updated SEP priority SEP number SEP title SEP reason SEP repo" ---
fm_fields() {
  awk -v S="$SEP" '
    BEGIN { n=0; u=""; p=""; num=""; t=""; r=""; repo="" }
    /^---[[:space:]]*$/ { n++; if (n>=2) exit; next }
    n==1 {
      i=index($0,":"); if (i==0) next
      k=substr($0,1,i-1); gsub(/[[:space:]]/,"",k)
      v=substr($0,i+1); sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v)
      if (v ~ /^".*"$/) v=substr(v,2,length(v)-2)
      if (k=="updated_at") u=v
      else if (k=="priority") p=v
      else if (k=="number") num=v
      else if (k=="title") t=v
      else if (k=="reason") r=v
      else if (k=="repo") repo=v
    }
    END { printf "%s%s%s%s%s%s%s%s%s%s%s\n", u,S,p,S,num,S,t,S,r,S,repo }
  ' "$1"
}

# --- collect records: updated SEP priority SEP file SEP number SEP title SEP reason SEP repo ---
recs="$(mktemp)"; trap 'rm -f "$recs"' EXIT
skipped=0
for f in "$ITEMS"/*.md; do
  [ -e "$f" ] || continue
  IFS="$SEP" read -r u p num t r repo < <(fm_fields "$f") || true
  if [ -z "${u:-}" ]; then skipped=$((skipped+1)); continue; fi
  printf '%s%s%s%s%s%s%s%s%s%s%s%s%s\n' \
    "$u" "$SEP" "$p" "$SEP" "$(basename "$f")" "$SEP" "$num" "$SEP" "$t" "$SEP" "$r" "$SEP" "$repo" >> "$recs"
done
# newest first — ISO-8601 UTC sorts correctly as plain strings
LC_ALL=C sort -t"$SEP" -k1,1r -o "$recs" "$recs"

href()  { if [ -n "$base" ]; then printf '%s/%s' "$base" "$1"; else printf 'items/%s' "$1"; fi; }
human() { printf '%s' "$1" | sed -E 's/T([0-9]{2}:[0-9]{2}).*/ \1 UTC/'; }
label() { if [ -n "$1" ]; then printf '#%s %s' "$1" "$2"; else printf '%s' "${2:-(untitled)}"; fi; }

# --- preserve an existing human lede (the line carrying the LEDE marker) ---
lede="$PLACEHOLDER"
if [ -f "$OUT" ]; then
  existing="$(grep -m1 -- '<!-- LEDE -->' "$OUT" || true)"
  if [ -n "$existing" ] && [ "$existing" != "$PLACEHOLDER" ]; then lede="$existing"; fi
fi

total="$(grep -c '' "$recs" 2>/dev/null || printf 0)"
c1="$(awk -F"$SEP" '$2=="P1"' "$recs" | grep -c '' || true)"
c2="$(awk -F"$SEP" '$2=="P2"' "$recs" | grep -c '' || true)"
c3="$(awk -F"$SEP" '$2=="P3"' "$recs" | grep -c '' || true)"
other="$(awk -F"$SEP" '$2!="P1" && $2!="P2" && $2!="P3"' "$recs" | grep -c '' || true)"

stat="$total reports"
if [ "$c1" -gt 0 ]; then stat="$stat · $c1 P1"; fi
if [ "$c2" -gt 0 ]; then stat="$stat · $c2 P2"; fi
if [ "$c3" -gt 0 ]; then stat="$stat · $c3 P3"; fi
if [ "$other" -gt 0 ]; then stat="$stat · $other other"; fi

{
  printf '# Notification digest — %s\n\n' "$DATE"
  printf '%s\n\n' "$lede"
  printf '%s · newest first\n\n' "$stat"
  if [ -n "$base" ]; then printf '> 📂 [All drafts for %s (INDEX)](%s)\n\n' "$DATE" "${base%/items}/INDEX.md"; fi
} > "$OUT"

emit_rows() { # reads SEP-delimited rows on stdin, appends bullets to $OUT
  while IFS="$SEP" read -r u p file num t r repo; do
    [ -n "$file" ] || continue
    printf -- '- **[%s](%s)** — %s · %s · %s\n' \
      "$(label "$num" "$t")" "$(href "$file")" "${r:-?}" "${repo:-?}" "$(human "$u")" >> "$OUT"
  done
}

emit_band() { # $1=priority key  $2=heading  $3=desc
  local key="$1" head="$2" desc="$3" group count
  group="$(awk -F"$SEP" -v b="$key" '($2==b)' "$recs")"
  if [ -z "$group" ]; then return 0; fi
  count="$(printf '%s\n' "$group" | grep -c '')"
  printf '## %s — %s (%s)\n\n' "$head" "$desc" "$count" >> "$OUT"
  printf '%s\n' "$group" | emit_rows
  printf '\n' >> "$OUT"
}

emit_band P1 P1 "needs you"
emit_band P2 P2 "drafted & waiting"
emit_band P3 P3 "FYI"

unpri="$(awk -F"$SEP" '($2!="P1" && $2!="P2" && $2!="P3")' "$recs")"
if [ -n "$unpri" ]; then
  printf '## Unprioritized (%s)\n\n' "$(printf '%s\n' "$unpri" | grep -c '')" >> "$OUT"
  printf '%s\n' "$unpri" | emit_rows
  printf '\n' >> "$OUT"
fi

printf '## All items, newest → oldest\n\n' >> "$OUT"
i=0
while IFS="$SEP" read -r u p file num t r repo; do
  [ -n "$file" ] || continue
  i=$((i+1))
  printf '%s. [%s](%s) — %s\n' "$i" "$(label "$num" "$t")" "$(href "$file")" "$(human "$u")" >> "$OUT"
done < "$recs"
printf '\n' >> "$OUT"

echo "Wrote $OUT ($total reports indexed)."
if [ "$skipped" -gt 0 ]; then echo "Skipped $skipped file(s) with missing/invalid frontmatter."; fi
exit 0
