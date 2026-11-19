#!/usr/bin/env bash
# load_to_elasticsearch.sh - send the bulk files made by tools/make_bulk_files.py to an Elasticsearch you choose.
#
# NOT TESTED against a real Elasticsearch (only --dry-run is tested). It sends data only to the address you give
# in ES_URL, and it reads the API key from the environment so that no secret is ever stored in a file or a command line.
# Use it on a lab cluster. It does not delete or change anything except by adding the synthetic documents.
set -u
set -o pipefail

usage() {
    cat <<'USAGE'
Usage: ES_URL=https://host:9200 ES_API_KEY=... scripts/load_to_elasticsearch.sh [--bulk-dir DIR] [--dry-run]

  --bulk-dir DIR   folder with the .ndjson files (default: build/bulk)
  --dry-run        show what would be sent, send nothing
USAGE
}

bulk_dir=build/bulk
dry_run=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --bulk-dir) bulk_dir=${2:?--bulk-dir needs a value} && shift 2 ;;
        --dry-run) dry_run=1 && shift ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "load_to_elasticsearch.sh: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z ${ES_URL:-} ]]; then
    echo "load_to_elasticsearch.sh: set ES_URL to the address of your Elasticsearch, for example https://localhost:9200" >&2
    exit 2
fi
if [[ ! -d $bulk_dir ]]; then
    echo "load_to_elasticsearch.sh: $bulk_dir does not exist; run: python3 tools/make_bulk_files.py" >&2
    exit 3
fi

found=0
for file in "$bulk_dir"/*.ndjson; do
    [[ -f $file ]] || continue
    found=1
    documents=$(($(wc -l <"$file") / 2))
    if ((dry_run)); then
        printf 'dry run: would send %s (%d documents) to %s/_bulk\n' "$file" "$documents" "$ES_URL"
        continue
    fi
    if [[ -z ${ES_API_KEY:-} ]]; then
        echo "load_to_elasticsearch.sh: set ES_API_KEY (an API key created in Kibana)" >&2
        exit 2
    fi
    response=$(curl --fail --silent --show-error -X POST "$ES_URL/_bulk" \
        -H "Authorization: ApiKey $ES_API_KEY" -H 'Content-Type: application/x-ndjson' \
        --data-binary "@$file") || {
        echo "load_to_elasticsearch.sh: sending $file failed" >&2
        exit 1
    }
    if [[ $response == *'"errors":true'* ]]; then
        echo "load_to_elasticsearch.sh: Elasticsearch reported errors for $file; check the response" >&2
        exit 1
    fi
    printf 'sent %s (%d documents)\n' "$file" "$documents"
done
if ((! found)); then
    echo "load_to_elasticsearch.sh: no .ndjson files in $bulk_dir" >&2
    exit 3
fi
