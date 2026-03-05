#!/usr/bin/env bash

set -euo pipefail

: "${DAV_USER:?set DAV_USER}"
: "${DAV_PASS:?set DAV_PASS}"
DAV_BASE="${DAV_BASE:-http://127.0.0.1:8080}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

expect_code() {
  local got="$1"
  shift
  for want in "$@"; do
    if [[ "$got" == "$want" ]]; then return 0; fi
  done
  echo "Expected HTTP $* but got $got" >&2
  exit 1
}

req() {
  # req METHOD URL OUT_FILE [extra curl args...]
  local method="$1"
  shift
  local url="$1"
  shift
  local out="$1"
  shift
  curl -sS -u "$DAV_USER:$DAV_PASS" -X "$method" "$url" -o "$out" -w '%{http_code}' "$@"
}

req_path_as_is() {
  # req_path_as_is METHOD URL OUT_FILE [extra curl args...]
  local method="$1"
  shift
  local url="$1"
  shift
  local out="$1"
  shift
  curl --path-as-is -sS -u "$DAV_USER:$DAV_PASS" -X "$method" "$url" -o "$out" -w '%{http_code}' "$@"
}

echo "1) Discovery endpoints"
code="$(req GET "$DAV_BASE/.well-known/carddav" "$TMP_DIR/carddav_discovery.txt")"
expect_code "$code" 301 302 307 308
code="$(req GET "$DAV_BASE/.well-known/caldav" "$TMP_DIR/caldav_discovery.txt")"
expect_code "$code" 301 302 307 308

echo "2) Principal discovery"
code="$(req PROPFIND "$DAV_BASE/dav/principals/me/" "$TMP_DIR/principal.xml" -H 'Depth: 0')"
expect_code "$code" 207
ACCOUNT_UID="$(grep -oE '/dav/[^/]+/principal/' "$TMP_DIR/principal.xml" | head -n1 | awk -F/ '{print $3}')"
if [[ -z "${ACCOUNT_UID:-}" ]]; then
  echo "Could not extract UID from principal PROPFIND response" >&2
  exit 1
fi
echo "   UID: $ACCOUNT_UID"

CARD_URL="$DAV_BASE/dav/$ACCOUNT_UID/addressbooks/default/c1.vcf"
CAL_COLL="$DAV_BASE/dav/$ACCOUNT_UID/calendars/work/"
CAL_EVT="$DAV_BASE/dav/$ACCOUNT_UID/calendars/work/e1.ics"

cat >"$TMP_DIR/c1.vcf" <<'VCF'
BEGIN:VCARD
VERSION:3.0
UID:c1
FN:Alice Test
EMAIL:alice@example.com
END:VCARD
VCF

cat >"$TMP_DIR/e1.ics" <<'ICS'
BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:event-1
DTSTART:20260305T120000Z
DTEND:20260305T130000Z
SUMMARY:Test Event
END:VEVENT
END:VCALENDAR
ICS

echo "3) CardDAV CRUD"
code="$(req DELETE "$CARD_URL" "$TMP_DIR/card_delete_pre.txt")"
expect_code "$code" 204 404
code="$(req PUT "$CARD_URL" "$TMP_DIR/card_put.txt" --data-binary @"$TMP_DIR/c1.vcf")"
expect_code "$code" 201 204
code="$(req GET "$CARD_URL" "$TMP_DIR/card_get.txt")"
expect_code "$code" 200
grep -q "BEGIN:VCARD" "$TMP_DIR/card_get.txt"

echo "4) CardDAV REPORT"
cat >"$TMP_DIR/addressbook_query.xml" <<'XML'
<card:addressbook-query xmlns:card="urn:ietf:params:xml:ns:carddav"/>
XML
CARD_COLLECTION_A="$DAV_BASE/dav/$ACCOUNT_UID/addressbooks/default/"
CARD_COLLECTION_B="$DAV_BASE/dav/$ACCOUNT_UID/addressbooks/default"
code="$(req REPORT "$CARD_COLLECTION_A" "$TMP_DIR/card_report.xml" --data-binary @"$TMP_DIR/addressbook_query.xml")"
if [[ "$code" == "404" ]]; then
  code="$(req REPORT "$CARD_COLLECTION_B" "$TMP_DIR/card_report.xml" --data-binary @"$TMP_DIR/addressbook_query.xml")"
fi
if [[ "$code" != "207" ]]; then
  echo "CardDAV REPORT failed with HTTP $code" >&2
  echo "--- response body ---" >&2
  cat "$TMP_DIR/card_report.xml" >&2 || true
  echo >&2
  exit 1
fi
grep -q "/dav/$ACCOUNT_UID/addressbooks/default/c1.vcf" "$TMP_DIR/card_report.xml"

echo "5) CalDAV CRUD + MKCALENDAR"
code="$(req MKCALENDAR "$CAL_COLL" "$TMP_DIR/mkcalendar.txt")"
expect_code "$code" 201 405
code="$(req PUT "$CAL_EVT" "$TMP_DIR/cal_put.txt" --data-binary @"$TMP_DIR/e1.ics")"
expect_code "$code" 201 204
code="$(req GET "$CAL_EVT" "$TMP_DIR/cal_get.txt")"
expect_code "$code" 200
grep -q "BEGIN:VCALENDAR" "$TMP_DIR/cal_get.txt"

echo "6) Path-hardening check"
code="$(req_path_as_is GET "$DAV_BASE/dav/$ACCOUNT_UID/addressbooks/default/%2e%2e/x" "$TMP_DIR/hardening.txt")"
expect_code "$code" 400 404
if [[ "$code" == "404" ]]; then
  echo "   Note: got 404 (older DAV build); latest hardening returns 400 for this probe."
fi

echo "7) Cleanup"
code="$(req DELETE "$CARD_URL" "$TMP_DIR/card_delete.txt")"
expect_code "$code" 204

echo "PASS: DAV smoke tests succeeded."
