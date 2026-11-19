#!/usr/bin/env python3
"""Turn the ECS JSON Lines datasets into Elasticsearch _bulk request files.

The Elasticsearch _bulk API wants an action line before every document:
    {"index":{"_index":"soc-lab-linux-auth"}}
    {...the document...}

This script only writes files. Sending them is a separate, deliberate step (scripts/load_to_elasticsearch.sh).
Standard library only.

Usage:
    python3 tools/make_bulk_files.py --datasets datasets --out-dir build/bulk
"""

import argparse
import json
from pathlib import Path

SOURCES = {
    "linux/auth_ecs.jsonl": "soc-lab-linux-auth",
    "windows/sysmon_ecs.jsonl": "soc-lab-windows-sysmon",
}


def convert(source, index_name, destination):
    count = 0
    with source.open(encoding="utf-8") as reader, destination.open("w", encoding="utf-8", newline="\n") as writer:
        for line in reader:
            if not line.strip():
                continue
            document = json.loads(line)  # raises on invalid JSON instead of passing it on
            writer.write(json.dumps({"index": {"_index": index_name}}, separators=(",", ":")) + "\n")
            writer.write(json.dumps(document, separators=(",", ":")) + "\n")
            count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description="Create Elasticsearch _bulk files from the ECS datasets.")
    parser.add_argument("--datasets", default="datasets", help="folder that contains linux/ and windows/ (default: datasets)")
    parser.add_argument("--out-dir", default="build/bulk", help="where to write the bulk files (default: build/bulk)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for relative, index_name in SOURCES.items():
        destination = out_dir / f"{index_name}.ndjson"
        count = convert(Path(args.datasets) / relative, index_name, destination)
        print(f"wrote {destination} ({count} documents)")


if __name__ == "__main__":
    main()
