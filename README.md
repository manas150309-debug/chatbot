# DarkTraceX Console

Defensive cybersecurity chatbot with:

- SQLite persistence for conversations, notes, and offline knowledge
- Defensive network inspection tools
- A local Ollama model path with no external API key requirement
- Browser session persistence and a dark console UI
- Transcript export in Markdown or JSON

## What it does

- Saves chat messages in `assistant.db`
- Stores and searches internal notes
- Seeds an offline security knowledge base from `data/security_kb.json`
- Runs defensive-only tools such as:
  - `search_knowledge`
  - `dns_lookup`
  - `reverse_dns`
  - `http_headers`
  - `security_headers_audit`
  - `tls_inspect`
  - `search_code_examples`
  - `search_detection_rules`
  - `search_phishing_examples`
  - `classify_defense_text`

## Run it

```bash
cd /Users/manas/Desktop/chatbot
ollama pull llama3.2:1b
export MODEL_PROVIDER="ollama"
export MODEL_NAME="llama3.2:1b"
python3 server.py
```

Open `http://127.0.0.1:8000`

## Tooling

Node.js is installed locally for frontend checks. Project scripts:

```bash
cd /Users/manas/Desktop/chatbot
npm install
npm run check
npm run healthcheck
```

Available checks:

- `npm run check:js`
- `npm run lint:js`
- `npm run check:py`
- `npm run format:check`
- `npm run healthcheck`

## Export Conversations

Use the `Export MD` or `Export JSON` buttons in the UI after a conversation exists.

- Markdown export is useful for readable reports
- JSON export is useful for tooling or later processing

## Notes

- The database file is `assistant.db`
- `.gitignore` excludes the local database, model files, and cache artifacts from Git commits
- The offline knowledge seed file is `data/security_kb.json`
- Additional code-fix training examples can be generated into `data/code_fix_pairs.json`
- If the local model is unavailable, the app can still answer from offline retrieval over notes and the local knowledge base
- The tool layer is defensive only. It does not implement exploitation or intrusive attack workflows

## Bulk Evaluation

Use `authorized_sites.csv` for websites you own or are explicitly permitted to assess, then run:

```bash
cd /Users/manas/Desktop/chatbot
python3 bulk_audit.py
```

The report is written to `evaluation_report.csv`.

## Generate 100 Secure Fix Examples

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_code_examples.py
```

This writes `data/code_fix_pairs.json` with 100 insecure-to-secure defensive code examples across common vulnerability classes.

## Generate Cyber Attack Taxonomy And Detection Rules

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_attack_knowledge.py
```

This writes `data/cyber_attack_kb.json` with offline attack categories and detection guidance.

## Generate Extended Attack Playbooks

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_attack_playbooks.py
```

This writes `data/attack_playbooks_kb.json` with large-scale defensive playbook entries so the local knowledge base can exceed 500 documents.

## Generate 100 Phishing Examples

```bash
cd /Users/manas/Desktop/chatbot
python3 generate_phishing_examples.py
```

This writes `data/phishing_examples_kb.json` with 100 stored phishing examples for direct retrieval.

For the current system-level evaluation summary, use:

- `REPORT.csv`
