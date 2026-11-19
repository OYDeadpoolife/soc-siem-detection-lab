# Elasticsearch Query DSL bodies

These files are plain request bodies. Elasticsearch rejects unknown keys, so they contain no comments; the documentation is here.
**All are NOT TESTED against a real Elasticsearch.** They are checked locally only for valid JSON and expected keys.

| File | Detection | Send to | What it does | Expected on the synthetic data |
|---|---|---|---|---|
| `ssh_bruteforce_agg.json` | DET-01 | `POST soc-lab-linux-auth/_search` | Counts failed SSH logins per source address (at least 5) with distinct users and first/last time | `203.0.113.45` with 59 failures; `10.10.30.60` with 7. Raise `min_doc_count` to 10 to hide the lab scanner |
| `encoded_powershell.json` | DET-09b | `POST soc-lab-windows-sysmon/_search` | PowerShell with an encoded command, excluding the known inventory agent | One hit at 11:30:14 |
| `ioc_pivot.json` | DET-12 | `POST soc-lab-*/_search` | Counts, per index, documents that mention the address `203.0.113.45` | Hits in both indices |

Example with curl (replace the host; the API key is read from an environment variable so it never appears in a file):

```bash
curl -s -H "Authorization: ApiKey $ES_API_KEY" -H 'Content-Type: application/json' \
     -X POST 'https://siem01.harbor.test:9200/soc-lab-linux-auth/_search' -d @elastic/queries/ssh_bruteforce_agg.json
```
