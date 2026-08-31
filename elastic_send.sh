#!/bin/bash
# elastic_send.sh — sends findings to Elastic Cloud via curl.
# Credentials come from .env (never hardcoded, never committed to git).

ENV_FILE="/home/lakshmi/sentinel-hids/.env"

send_to_elastic() {
  local json_file="$1"
  local index_name="$2"

  if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
  else
    echo "Error: .env file not found at $ENV_FILE"
    return 1
  fi

  if [ -z "$ELASTIC_URL" ] || [ -z "$ELASTIC_API_KEY" ]; then
    echo "Error: ELASTIC_URL or ELASTIC_API_KEY not set in $ENV_FILE"
    return 1
  fi

  # Turn each JSON line into a bulk "index" instruction + the record itself.
  local response_code
  response_code=$(jq -c '{"index": {}}, .' "$json_file" \
    | curl -s -k -o /dev/null -w "%{http_code}" \
                -X POST "$ELASTIC_URL/$index_name/_bulk?pipeline=sentinel_ts" \
        -H "Authorization: ApiKey $ELASTIC_API_KEY" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary @-)

  if [ "$response_code" = "200" ] || [ "$response_code" = "201" ]; then
    echo "Sent $json_file to Elastic index: $index_name (HTTP $response_code)"
  else
    echo "FAILED to send to Elastic. HTTP code: $response_code"
  fi
}

# If run directly (not sourced), send the given file to the given index.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  send_to_elastic "$1" "$2"
fi
