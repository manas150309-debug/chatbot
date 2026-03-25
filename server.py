import json
import os
import re
import socket
import sqlite3
import ssl
import subprocess
import urllib.parse
import ipaddress
import math
import joblib
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import error, request


HOST = "127.0.0.1"
PORT = 8000
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "assistant.db"
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
KB_PATH = DATA_DIR / "security_kb.json"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
OLLAMA_API_URL = os.environ.get("OLLAMA_API_URL", "http://127.0.0.1:11434/api/generate")
MODEL_PROVIDER = os.environ.get("MODEL_PROVIDER", "ollama").lower()
DEFAULT_MODEL = os.environ.get("MODEL_NAME", os.environ.get("OLLAMA_MODEL", "llama3.2:1b"))
SSL_CONTEXT = None
DEFENSE_MODELS = {}
MAX_TOOL_STEPS = 4
MAX_CONTEXT_MESSAGES = 12
MODEL_THRESHOLDS = {
    "phishing_email": 0.72,
    "log_threat": 0.68,
    "attack_category": 0.62,
    "code_security": 0.68,
}

SYSTEM_PROMPT = """You are DarkTraceX, an elite AI-powered cybersecurity expert designed to assist developers, security analysts, and organizations in identifying, analyzing, and mitigating security threats.

Your role is strictly defensive, ethical, and educational. You do NOT assist in illegal activities, exploitation, malware creation, credential theft, persistence, privilege escalation, or harm. Focus on prevention, detection, secure design, and mitigation.

Core behavior:
- Think like a top-tier cybersecurity expert.
- Be precise, technical, structured, and concise.
- Use tools and memory when they materially improve accuracy.
- Do not claim to have executed a tool if you did not.
- Only use network tools for public internet targets. Do not target localhost, private IP ranges, link-local ranges, or internal hostnames.

Response patterns:
- When explaining a vulnerability, include:
  1. What it is
  2. How it works
  3. Why it is dangerous
  4. How to prevent it
  5. A secure code example when applicable
- When analyzing code, identify concrete vulnerabilities, point to insecure logic, explain impact, and propose safer code.
- If the code is clearly phishing, credential theft, malware-like, or otherwise malicious, explicitly say so, explain the indicators, assess the risk, and give defensive cleanup or reporting guidance. Do not optimize, repair, or extend the malicious behavior.
- When analyzing logs, detect anomalies, summarize threat level as Low, Medium, or High, and recommend mitigations.
- When reviewing emails or messages for phishing, classify as Safe, Suspicious, or Phishing, explain why, and highlight red flags.

Tool protocol:
- When you need a tool, respond with JSON only:
  {"tool_name":"tool_name","arguments":{"key":"value"}}
- Use exactly one tool call at a time.
- After tool results are returned, continue reasoning and either answer normally or request another tool.

Available tools:
- remember_note: save an internal note or fact for future chats. arguments: {"content":"text"}
- search_notes: search internal memory. arguments: {"query":"text"}
- search_knowledge: search the offline security knowledge base. arguments: {"query":"text"}
- search_code_examples: return stored insecure and secure code pairs from the offline dataset. arguments: {"query":"text"}
- search_detection_rules: return stored cyber-attack detection guidance from the offline dataset. arguments: {"query":"text"}
- classify_defense_text: apply local pattern-learning models to phishing text, logs, code, or attack labels. arguments: {"model":"phishing_email|log_threat|attack_category|code_security","text":"content"}
- search_phishing_examples: return stored phishing examples from the offline dataset. arguments: {"query":"text","limit":100}
- dns_lookup: resolve hostname to IP addresses. arguments: {"hostname":"example.com"}
- reverse_dns: resolve a public IP address back to its hostname. arguments: {"ip":"8.8.8.8"}
- http_headers: fetch response headers for a URL. arguments: {"url":"https://example.com"}
- security_headers_audit: review common web security headers for a URL. arguments: {"url":"https://example.com"}
- tls_inspect: inspect TLS certificate summary for a host. arguments: {"hostname":"example.com","port":443}
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def build_ssl_context():
    ssl_cert_file = os.environ.get("SSL_CERT_FILE")
    if ssl_cert_file:
        return ssl.create_default_context(cafile=ssl_cert_file)

    try:
        result = subprocess.run(
            [
                "security",
                "find-certificate",
                "-a",
                "-p",
                "/System/Library/Keychains/SystemRootCertificates.keychain",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        pem_data = result.stdout.strip()
        if pem_data:
            context = ssl.create_default_context()
            context.load_verify_locations(cadata=pem_data)
            return context
    except Exception:
        pass

    return ssl.create_default_context()


def tokenize_text(text):
    return [token for token in re.findall(r"[a-zA-Z0-9_@./:-]{2,}", (text or "").lower())]


def normalize_security_query(text):
    candidate = (text or "").lower()
    replacements = {
        "phising": "phishing",
        "phisihng": "phishing",
        "phshing": "phishing",
        "fishing email": "phishing email",
    }
    for wrong, correct in replacements.items():
        candidate = candidate.replace(wrong, correct)
    return candidate


def extract_requested_count(text, default=10, maximum=100):
    candidate = normalize_security_query(text)
    match = re.search(r"\b(\d{1,3})\b", candidate)
    if not match:
        return default
    return max(1, min(int(match.group(1)), maximum))


def load_defense_models():
    global DEFENSE_MODELS
    DEFENSE_MODELS = {}
    if not MODELS_DIR.exists():
        return

    for model_path in MODELS_DIR.glob("*.joblib"):
        try:
            payload = joblib.load(model_path)
            model_name = payload.get("model_name")
            if model_name:
                DEFENSE_MODELS[model_name] = payload
        except Exception:
            continue


def classify_with_local_model(model_name, text):
    model = DEFENSE_MODELS.get(model_name)
    if not model:
        raise RuntimeError(f"Local model not available: {model_name}")

    tokens = tokenize_text(text)
    if not tokens:
        raise RuntimeError("Text is required for classification.")

    labels = model["labels"]
    priors = model["priors"]
    token_counts = model["token_counts"]
    total_tokens = model["total_tokens"]
    vocabulary = model["vocabulary"]
    vocab_size = max(len(vocabulary), 1)

    scores = {}
    for label in labels:
        score = math.log(priors.get(label, 1e-9))
        denom = total_tokens.get(label, 0) + vocab_size
        label_counts = token_counts.get(label, {})
        for token in tokens:
            score += math.log((label_counts.get(token, 0) + 1) / denom)
        scores[label] = score

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_label, best_score = ranked[0]
    second_score = ranked[1][1] if len(ranked) > 1 else best_score - 1.0
    confidence = round(1 / (1 + math.exp(-(best_score - second_score))), 4)
    return {
        "model": model_name,
        "label": best_label,
        "confidence": confidence,
        "scores": [{ "label": label, "score": round(score, 4)} for label, score in ranked[:5]],
    }


def db_connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = db_connect()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                text TEXT NOT NULL,
                meta_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'assistant',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_docs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_key TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                source_url TEXT,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()


def seed_knowledge():
    if not DATA_DIR.exists():
        return

    connection = db_connect()
    try:
        doc_index = 1
        for data_file in sorted(DATA_DIR.glob("*.json")):
            raw = json.loads(data_file.read_text(encoding="utf-8"))
            docs = raw.get("documents", [])
            if not isinstance(docs, list):
                continue

            for doc in docs:
                title = (doc.get("title") or "").strip()
                content = (doc.get("content") or "").strip()
                category = (doc.get("category") or "general").strip()
                source_url = (doc.get("source_url") or "").strip()
                doc_key = (doc.get("doc_key") or f"{data_file.stem}-doc-{doc_index}").strip()

                if not title or not content:
                    doc_index += 1
                    continue

                connection.execute(
                    """
                    INSERT INTO knowledge_docs (doc_key, title, category, source_url, content, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(doc_key) DO UPDATE SET
                        title = excluded.title,
                        category = excluded.category,
                        source_url = excluded.source_url,
                        content = excluded.content
                    """,
                    (doc_key, title, category, source_url, content, utc_now()),
                )
                doc_index += 1
        connection.commit()
    finally:
        connection.close()


def ensure_conversation(conversation_id):
    connection = db_connect()
    try:
        if conversation_id:
            row = connection.execute(
                "SELECT id FROM conversations WHERE id = ?",
                (conversation_id,),
            ).fetchone()
            if row:
                connection.execute(
                    "UPDATE conversations SET updated_at = ? WHERE id = ?",
                    (utc_now(), conversation_id),
                )
                connection.commit()
                return conversation_id

        now = utc_now()
        cursor = connection.execute(
            "INSERT INTO conversations (created_at, updated_at) VALUES (?, ?)",
            (now, now),
        )
        connection.commit()
        return cursor.lastrowid
    finally:
        connection.close()


def save_message(conversation_id, role, text, meta=None):
    connection = db_connect()
    try:
        connection.execute(
            """
            INSERT INTO messages (conversation_id, role, text, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                conversation_id,
                role,
                text,
                json.dumps(meta or {}),
                utc_now(),
            ),
        )
        connection.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (utc_now(), conversation_id),
        )
        connection.commit()
    finally:
        connection.close()


def get_conversation_messages(conversation_id):
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, role, text, meta_json, created_at
            FROM messages
            WHERE conversation_id = ?
            ORDER BY id ASC
            """,
            (conversation_id,),
        ).fetchall()

        messages = []
        for row in rows:
            item = dict(row)
            try:
                item["meta"] = json.loads(item.pop("meta_json") or "{}")
            except json.JSONDecodeError:
                item["meta"] = {}
            messages.append(item)
        return messages
    finally:
        connection.close()


def remember_note(content, source="assistant"):
    text = (content or "").strip()
    if not text:
        raise RuntimeError("Cannot save an empty note.")

    connection = db_connect()
    try:
        cursor = connection.execute(
            "INSERT INTO notes (content, source, created_at) VALUES (?, ?, ?)",
            (text, source, utc_now()),
        )
        connection.commit()
        return {
            "id": cursor.lastrowid,
            "content": text,
            "source": source,
        }
    finally:
        connection.close()


def search_notes(query, limit=5):
    term = (query or "").strip()
    if not term:
        return []

    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, content, source, created_at
            FROM notes
            WHERE content LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (f"%{term}%", limit),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def search_knowledge(query, limit=5):
    term = (query or "").strip()
    if not term:
        return []

    tokens = [token for token in re.findall(r"[a-zA-Z0-9_-]{3,}", term.lower()) if token]
    if not tokens:
        tokens = [term.lower()]

    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            """
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            haystack = " ".join(
                [
                    item.get("title", "").lower(),
                    item.get("category", "").lower(),
                    item.get("content", "").lower(),
                ]
            )
            score = 0
            for token in tokens[:8]:
                if token in item.get("title", "").lower():
                    score += 6
                if token in item.get("category", "").lower():
                    score += 3
                if token in haystack:
                    score += 1

            if term.lower() in haystack:
                score += 10

            if score > 0:
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        return [item for _, _, item in scored[:limit]]
    finally:
        connection.close()


def parse_code_example(content):
    lines = content.splitlines()
    sections = {"language": "", "vulnerability": "", "insecure_code": "", "secure_code": "", "why_insecure": ""}
    current = None
    insecure_lines = []
    secure_lines = []
    why_lines = []

    for line in lines:
        if line.startswith("Language: "):
            sections["language"] = line.removeprefix("Language: ").strip()
            current = None
        elif line.startswith("Vulnerability: "):
            sections["vulnerability"] = line.removeprefix("Vulnerability: ").strip()
            current = None
        elif line == "Insecure code:":
            current = "insecure"
        elif line == "Secure code:":
            current = "secure"
        elif line == "Why insecure:":
            current = "why"
        else:
            if current == "insecure":
                insecure_lines.append(line)
            elif current == "secure":
                secure_lines.append(line)
            elif current == "why":
                why_lines.append(line)

    sections["insecure_code"] = "\n".join(insecure_lines).strip()
    sections["secure_code"] = "\n".join(secure_lines).strip()
    sections["why_insecure"] = "\n".join(why_lines).strip()
    return sections


def search_code_examples(query, limit=3):
    term = (query or "").strip().lower()
    if not term:
        return []

    stopwords = {
        "find",
        "show",
        "give",
        "need",
        "want",
        "secure",
        "fix",
        "example",
        "examples",
        "code",
        "for",
        "the",
        "and",
        "with",
        "that",
        "this",
        "in",
        "a",
    }
    tokens = [
        token
        for token in re.findall(r"[a-zA-Z0-9_-]{2,}", term)
        if token and token not in stopwords
    ]
    requested_languages = {
        token
        for token in tokens
        if token in {"python", "php", "node", "javascript", "java", "ruby", "go", "csharp", "rust", "kotlin", "scala"}
    }
    requested_vulnerability_tokens = {
        token
        for token in tokens
        if token
        in {
            "sql",
            "injection",
            "xss",
            "csrf",
            "xxe",
            "deserialization",
            "redirect",
            "traversal",
            "secrets",
            "secret",
            "command",
            "password",
        }
    }

    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE doc_key LIKE ? OR content LIKE '%Insecure code:%'
            """,
            ("code_fix_pairs%",),
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            parsed = parse_code_example(item["content"])
            vulnerability = parsed["vulnerability"].lower()
            language = parsed["language"].lower()
            haystack = " ".join(
                [
                    item.get("title", "").lower(),
                    language,
                    vulnerability,
                    parsed["insecure_code"].lower(),
                    parsed["secure_code"].lower(),
                    parsed["why_insecure"].lower(),
                ]
            )
            score = 0
            for token in tokens[:8]:
                if token == language:
                    score += 45
                elif token in language:
                    score += 14
                if token == vulnerability:
                    score += 45
                elif token in vulnerability:
                    score += 16
                if token in item.get("title", "").lower():
                    score += 8
                if token in haystack:
                    score += 1

            if vulnerability and vulnerability in term:
                score += 30
            if language and language in term:
                score += 24

            if score > 0:
                item.update(parsed)
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        ranked_items = [item for _, _, item in scored]

        if requested_languages:
            language_hits = [
                item for item in ranked_items if item["language"].lower() in requested_languages
            ]
            if language_hits:
                ranked_items = language_hits

        if requested_vulnerability_tokens:
            vulnerability_hits = []
            for item in ranked_items:
                vulnerability = item["vulnerability"].lower()
                if all(token in vulnerability for token in requested_vulnerability_tokens):
                    vulnerability_hits.append(item)
            if vulnerability_hits:
                ranked_items = vulnerability_hits

        return ranked_items[:limit]
    finally:
        connection.close()


def build_code_example_response(results):
    if not results:
        return "No matching stored code example was found in the offline dataset."

    parts = []
    for item in results:
        parts.append(
            "\n".join(
                [
                    f"Title: {item['title']}",
                    f"Language: {item['language']}",
                    f"Vulnerability: {item['vulnerability']}",
                    "Insecure code:",
                    item["insecure_code"],
                    "",
                    "Secure code:",
                    item["secure_code"],
                    "",
                    "Why insecure:",
                    item["why_insecure"],
                ]
            )
        )
    return "\n\n---\n\n".join(parts)


def detect_code_example_request(text):
    candidate = normalize_security_query(text)
    direct_triggers = [
        "secure fix",
        "secure code",
        "insecure code",
        "code example",
        "fix example",
        "secure snippet",
        "fix this code",
        "safer code",
    ]
    if any(trigger in candidate for trigger in direct_triggers):
        return True

    asks_for_code = any(token in candidate for token in ["code", "snippet", "query"])
    asks_for_fix = any(token in candidate for token in ["secure", "safer", "fix", "fixed", "prevent", "parameterized"])
    return asks_for_code and asks_for_fix


def search_detection_rules(query, limit=5):
    term = (query or "").strip().lower()
    if not term:
        return []

    tokens = [token for token in re.findall(r"[a-zA-Z0-9_-]{3,}", term) if token]
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE category = 'detection-rules' OR category = 'taxonomy'
            """
        ).fetchall()

        scored = []
        for row in rows:
            item = dict(row)
            haystack = " ".join([item["title"].lower(), item["content"].lower(), item["category"].lower()])
            score = 0
            for token in tokens[:8]:
                if token in item["title"].lower():
                    score += 8
                if token in haystack:
                    score += 2
            if "cyber attack" in term and item["doc_key"] == "cyber-attack-taxonomy":
                score += 20
            if "detect" in term and item["category"] == "detection-rules":
                score += 6
            if score > 0:
                scored.append((score, item["id"], item))

        scored.sort(key=lambda entry: (-entry[0], -entry[1]))
        return [item for _, _, item in scored[:limit]]
    finally:
        connection.close()


def build_detection_rule_response(results):
    if not results:
        return "No matching cyber-attack taxonomy or detection rule was found in the offline dataset."

    return "\n\n---\n\n".join(
        [
            "\n".join(
                [
                    f"Title: {item['title']}",
                    f"Category: {item['category']}",
                    item["content"],
                ]
            )
            for item in results
        ]
    )


def search_phishing_examples(query, limit=100):
    connection = db_connect()
    try:
        rows = connection.execute(
            """
            SELECT id, doc_key, title, category, source_url, content
            FROM knowledge_docs
            WHERE category = 'phishing-examples'
            ORDER BY id ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def build_phishing_examples_response(results):
    if not results:
        return "No phishing examples were found in the offline dataset."

    lines = [f"Stored phishing examples: {len(results)}", ""]
    for item in results:
        lines.append(f"{item['title']}:")
        lines.append(item["content"])
        lines.append("")
    return "\n".join(lines).strip()


def detect_attack_taxonomy_request(text):
    candidate = normalize_security_query(text)
    return (
        ("list" in candidate or "types" in candidate or "category" in candidate)
        and "attack" in candidate
        and "cyber" in candidate
    )


def detect_phishing_examples_request(text):
    candidate = normalize_security_query(text)
    wants_examples = any(token in candidate for token in ["example", "examples", "sample", "samples", "list"])
    wants_phishing = "phishing" in candidate or "spear phishing" in candidate
    explicit_count = re.search(r"\b\d{1,3}\b", candidate) is not None
    return wants_phishing and (wants_examples or explicit_count)


def detect_detection_rule_request(text):
    candidate = normalize_security_query(text)
    return "detect" in candidate and ("attack" in candidate or "phishing" in candidate or "ransomware" in candidate)


def detect_phishing_classification_request(text):
    candidate = normalize_security_query(text)
    return ("phishing" in candidate or "email" in candidate) and (
        "classify" in candidate or "is this" in candidate or "analyze" in candidate
    )


def detect_log_analysis_request(text):
    candidate = (text or "").lower()
    return "log" in candidate and ("analyze" in candidate or "threat" in candidate or "rate" in candidate)


def detect_attack_label_request(text):
    candidate = (text or "").lower()
    return "what attack" in candidate or "attack type" in candidate or "classify attack" in candidate


def build_classifier_response(result):
    return "\n".join(
        [
            f"Model: {result['model']}",
            f"Predicted label: {result['label']}",
            f"Confidence: {result['confidence']}",
            "Top scores:",
            *[f"- {item['label']}: {item['score']}" for item in result["scores"]],
        ]
    )


def build_conversation_export(conversation_id, export_format="markdown"):
    messages = get_conversation_messages(conversation_id)
    if not messages:
        raise RuntimeError("Conversation not found or has no messages.")

    if export_format == "json":
        payload = {
            "conversation_id": conversation_id,
            "exported_at": utc_now(),
            "messages": messages,
        }
        return json.dumps(payload, indent=2), "application/json", f"conversation-{conversation_id}.json"

    lines = [
        f"# DarkTraceX Conversation {conversation_id}",
        "",
        f"Exported at: {utc_now()}",
        "",
    ]
    for item in messages:
        lines.append(f"## {item['role'].title()} · {item['created_at']}")
        lines.append("")
        lines.append(item["text"])
        lines.append("")
        if item.get("meta", {}).get("tool_events"):
            lines.append("Tool events:")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(item["meta"]["tool_events"], indent=2))
            lines.append("```")
            lines.append("")

    return "\n".join(lines).strip() + "\n", "text/markdown; charset=utf-8", f"conversation-{conversation_id}.md"


def classify_with_threshold(model_name, text):
    result = classify_with_local_model(model_name, text)
    threshold = MODEL_THRESHOLDS.get(model_name, 0.7)
    result["threshold"] = threshold
    result["meets_threshold"] = result["confidence"] >= threshold
    return result


def detect_credential_theft_code(text):
    candidate = (text or "").lower()
    indicators = [
        "$_post",
        "captured_creds",
        "fwrite(",
        "passwd",
        "password",
        "location:",
        "header(",
    ]
    matches = sum(1 for item in indicators if item in candidate)
    if matches < 4:
        return None

    return {
        "classification": "Phishing / Credential Theft",
        "risk_level": "High",
        "analysis": (
            "This code is a credential-harvesting phishing handler. It accepts user-supplied login data, "
            "writes the captured credentials to a local file, and redirects the victim to the real site to hide the theft."
        ),
        "red_flags": [
            "Raw credential capture from POST parameters",
            "Credential storage in a hidden local file",
            "Post-capture redirect intended to hide malicious behavior",
            "No legitimate authentication or server-side validation flow",
        ],
        "defensive_guidance": [
            "Remove the script immediately from any server or repository",
            "Preserve forensic evidence and review access logs",
            "Rotate any exposed credentials and invalidate affected sessions",
            "Scan the host for related phishing artifacts and persistence",
            "Report the incident through the appropriate abuse, SOC, or incident-response channel",
        ],
    }


def build_credential_theft_response(result):
    lines = [
        "Classification: Phishing / Credential Theft",
        f"Threat Level: {result['risk_level']}",
        "",
        "What it is:",
        "This PHP snippet is a phishing credential harvester.",
        "",
        "How it works:",
        "It receives credentials from POST fields, stores them in a local file, and redirects the victim to the legitimate site to reduce suspicion.",
        "",
        "Why it is dangerous:",
        "It steals usernames and passwords, hides the theft with a redirect, and can directly support account compromise.",
        "",
        "Indicators:",
    ]
    lines.extend([f"- {item}" for item in result["red_flags"]])
    lines.extend(
        [
            "",
            "Defensive response:",
        ]
    )
    lines.extend([f"- {item}" for item in result["defensive_guidance"]])
    lines.extend(
        [
            "",
            "Safe replacement guidance:",
            "Use legitimate authentication handlers that validate input, avoid credential logging, and never redirect users as part of a deceptive flow.",
        ]
    )
    return "\n".join(lines)


def detect_sql_injection_code(text):
    candidate = (text or "").lower()
    indicators = [
        "select * from users where",
        "f\"select",
        "username = '{username}'",
        "password = '{password}'",
        "cur.execute(query)",
    ]
    matches = sum(1 for item in indicators if item in candidate)
    if matches < 3:
        return None

    return {
        "classification": "SQL Injection",
        "risk_level": "High",
        "secure_example": """import psycopg2

def secure_get_user(username, password):
    conn = psycopg2.connect("dbname=test user=app_user password=REPLACE_ME")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s;",
                (username, password),
            )
            return cur.fetchone()
    finally:
        conn.close()""",
    }


def build_sql_injection_response(result):
    lines = [
        "Classification: SQL Injection",
        f"Threat Level: {result['risk_level']}",
        "",
        "1. What it is:",
        "This code is vulnerable to SQL injection because untrusted input is inserted directly into the SQL statement.",
        "",
        "2. How it works:",
        "The query is built with string interpolation. An attacker can inject SQL syntax such as `admin' --` to alter the WHERE clause and bypass the password check.",
        "",
        "3. Why it is dangerous:",
        "It can allow authentication bypass, unauthorized data access, data modification, or broader database compromise depending on the database permissions.",
        "",
        "4. How to prevent it:",
        "- Use parameterized queries or prepared statements",
        "- Never concatenate user input into SQL strings",
        "- Remove hardcoded database credentials from source code",
        "- Apply least-privilege database permissions",
        "",
        "5. Secure code example:",
        result["secure_example"],
        "",
        "Extra finding:",
        "The connection string also contains a hardcoded password, which should be moved to environment variables or a secret manager.",
    ]
    return "\n".join(lines)


def conversation_stats():
    connection = db_connect()
    try:
        totals = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM conversations) AS conversations,
                (SELECT COUNT(*) FROM messages) AS messages,
                (SELECT COUNT(*) FROM notes) AS notes,
                (SELECT COUNT(*) FROM knowledge_docs) AS knowledge_docs
            """
        ).fetchone()
        recent_notes = connection.execute(
            """
            SELECT id, content, source, created_at
            FROM notes
            ORDER BY id DESC
            LIMIT 6
            """
        ).fetchall()
        return {
            "conversations": totals["conversations"],
            "messages": totals["messages"],
            "notes": totals["notes"],
            "knowledge_docs": totals["knowledge_docs"],
            "recent_notes": [dict(row) for row in recent_notes],
        }
    finally:
        connection.close()


def validate_hostname(hostname):
    value = (hostname or "").strip().lower()
    if not value:
        raise RuntimeError("hostname is required.")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise RuntimeError("Invalid hostname.")
    if value in {"localhost"} or value.endswith(".local"):
        raise RuntimeError("Local or private hostnames are not allowed.")
    return value


def validate_public_ip(ip_value):
    raw = (ip_value or "").strip()
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise RuntimeError("A valid IP address is required.") from exc

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise RuntimeError("Only public IP addresses are allowed.")

    return str(ip)


def ensure_public_hostname(hostname):
    infos = socket.getaddrinfo(hostname, None)
    addresses = sorted({item[4][0] for item in infos})
    if not addresses:
        raise RuntimeError("No public address found for hostname.")

    for address in addresses:
        validate_public_ip(address)

    return addresses


def validate_url(url):
    raw = (url or "").strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("A valid http or https URL is required.")
    hostname = parsed.hostname
    if not hostname:
        raise RuntimeError("A valid URL hostname is required.")

    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname) or ":" in hostname:
        validate_public_ip(hostname)
    else:
        validate_hostname(hostname)
        ensure_public_hostname(hostname)

    return raw


def tool_dns_lookup(arguments):
    hostname = validate_hostname(arguments.get("hostname"))
    addresses = ensure_public_hostname(hostname)
    return {"hostname": hostname, "addresses": addresses}


def tool_reverse_dns(arguments):
    ip_value = validate_public_ip(arguments.get("ip"))
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_value)
    except socket.herror as exc:
        raise RuntimeError(f"No reverse DNS entry for {ip_value}.") from exc

    return {
        "ip": ip_value,
        "hostname": hostname,
        "aliases": aliases,
    }


def fetch_url(url, method="HEAD"):
    req = request.Request(
        url,
        headers={"User-Agent": "Blackwall/1.0"},
        method=method,
    )
    return request.urlopen(req, timeout=15, context=SSL_CONTEXT)


def tool_http_headers(arguments):
    url = validate_url(arguments.get("url"))
    try:
        response = fetch_url(url, method="HEAD")
    except error.HTTPError as exc:
        if exc.code != 405:
            raise
        response = fetch_url(url, method="GET")

    with response:
        headers = dict(response.headers.items())
        return {
            "url": url,
            "final_url": response.geturl(),
            "status": response.status,
            "headers": headers,
        }


def tool_security_headers_audit(arguments):
    header_result = tool_http_headers(arguments)
    headers = {key.lower(): value for key, value in header_result["headers"].items()}

    recommended = {
        "strict-transport-security": "Missing HSTS header.",
        "content-security-policy": "Missing Content-Security-Policy header.",
        "x-content-type-options": "Missing X-Content-Type-Options header.",
        "referrer-policy": "Missing Referrer-Policy header.",
    }

    findings = []
    for header_name, missing_message in recommended.items():
        value = headers.get(header_name)
        if not value:
            findings.append(missing_message)

    if headers.get("x-frame-options") is None and headers.get("content-security-policy") is None:
        findings.append("Neither X-Frame-Options nor CSP frame-ancestors is present.")

    if headers.get("server"):
        findings.append(f"Server header exposed: {headers['server']}")

    if not findings:
        findings.append("No obvious missing baseline headers were detected.")

    return {
        "url": header_result["url"],
        "status": header_result["status"],
        "final_url": header_result["final_url"],
        "findings": findings,
        "headers": header_result["headers"],
    }


def tool_tls_inspect(arguments):
    hostname = validate_hostname(arguments.get("hostname"))
    ensure_public_hostname(hostname)
    port = int(arguments.get("port", 443))
    if port < 1 or port > 65535:
        raise RuntimeError("Invalid port.")

    context = SSL_CONTEXT or ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            cert = secure_sock.getpeercert()

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))

    return {
        "hostname": hostname,
        "port": port,
        "subject_common_name": subject.get("commonName"),
        "issuer_common_name": issuer.get("commonName"),
        "serial_number": cert.get("serialNumber"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"],
    }


def tool_remember_note(arguments):
    return remember_note(arguments.get("content"), source="tool")


def tool_search_notes(arguments):
    return {"results": search_notes(arguments.get("query"))}


def tool_search_knowledge(arguments):
    return {"results": search_knowledge(arguments.get("query"))}


def tool_search_code_examples(arguments):
    return {"results": search_code_examples(arguments.get("query"))}


def tool_search_detection_rules(arguments):
    return {"results": search_detection_rules(arguments.get("query"))}


def tool_search_phishing_examples(arguments):
    limit = int(arguments.get("limit", 100))
    limit = max(1, min(limit, 100))
    return {"results": search_phishing_examples(arguments.get("query"), limit=limit)}


def tool_classify_defense_text(arguments):
    model_name = (arguments.get("model") or "").strip()
    text = arguments.get("text") or ""
    return classify_with_local_model(model_name, text)


TOOLS = {
    "remember_note": tool_remember_note,
    "search_notes": tool_search_notes,
    "search_knowledge": tool_search_knowledge,
    "search_code_examples": tool_search_code_examples,
    "search_detection_rules": tool_search_detection_rules,
    "search_phishing_examples": tool_search_phishing_examples,
    "classify_defense_text": tool_classify_defense_text,
    "dns_lookup": tool_dns_lookup,
    "reverse_dns": tool_reverse_dns,
    "http_headers": tool_http_headers,
    "security_headers_audit": tool_security_headers_audit,
    "tls_inspect": tool_tls_inspect,
}


def build_gemini_contents(messages):
    contents = []
    for message in messages[-MAX_CONTEXT_MESSAGES:]:
        role = message.get("role")
        text = (message.get("text") or "").strip()
        if role not in {"user", "assistant"} or not text:
            continue
        contents.append(
            {
                "role": "model" if role == "assistant" else "user",
                "parts": [{"text": text}],
            }
        )
    return contents


def extract_gemini_text(data):
    for candidate in data.get("candidates", []):
        content = candidate.get("content", {})
        for part in content.get("parts", []):
            text = (part.get("text") or "").strip()
            if text:
                return text

    prompt_feedback = data.get("promptFeedback", {})
    block_reason = prompt_feedback.get("blockReason")
    if block_reason:
        raise RuntimeError(f"Gemini blocked the prompt: {block_reason}")

    raise RuntimeError("The model returned no text.")


def call_gemini(contents):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set.")

    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.5},
    }

    url = f"{GEMINI_API_URL}/{DEFAULT_MODEL}:generateContent"
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=90, context=SSL_CONTEXT) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
            message = parsed.get("error", {}).get("message") or raw
        except json.JSONDecodeError:
            message = raw
        raise RuntimeError(f"Gemini API error ({exc.code}): {message}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Network error: {exc.reason}") from exc

    return extract_gemini_text(json.loads(body))


def build_local_prompt(messages, memory_hits, knowledge_hits, tool_events):
    sections = [SYSTEM_PROMPT]

    if knowledge_hits:
        sections.append("Offline knowledge base matches:\n" + json.dumps(knowledge_hits, indent=2))
    if memory_hits:
        sections.append("Relevant memory:\n" + json.dumps(memory_hits, indent=2))
    if tool_events:
        sections.append("Executed tool results:\n" + json.dumps(tool_events, indent=2))

    transcript = []
    for message in messages[-MAX_CONTEXT_MESSAGES:]:
        role = message.get("role")
        text = (message.get("text") or "").strip()
        if role in {"user", "assistant"} and text:
            transcript.append(f"{role.upper()}: {text}")

    sections.append("Conversation:\n" + "\n".join(transcript))
    sections.append(
        "Respond to the latest user message. If a tool is needed, return JSON only using the declared tool protocol."
    )
    return "\n\n".join(sections)


def call_ollama(prompt):
    payload = {
        "model": DEFAULT_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.4},
    }

    req = request.Request(
        OLLAMA_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=120) as response:
            body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Ollama API error ({exc.code}): {raw}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Ollama is unavailable: {exc.reason}") from exc

    data = json.loads(body)
    text = (data.get("response") or "").strip()
    if not text:
        raise RuntimeError("The local model returned no text.")
    return text


def build_gemini_context_messages(memory_hits, knowledge_hits, tool_events):
    parts = []
    if knowledge_hits:
        parts.append("Offline knowledge base matches:\n" + json.dumps(knowledge_hits, indent=2))
    if memory_hits:
        parts.append("Relevant memory:\n" + json.dumps(memory_hits, indent=2))
    if tool_events:
        parts.append("Executed tool results:\n" + json.dumps(tool_events, indent=2))
    if not parts:
        return []
    return [{"role": "user", "parts": [{"text": "\n\n".join(parts)}]}]


def build_offline_fallback(last_user_text, knowledge_hits, memory_hits):
    lines = [
        "Local model is unavailable, so this response is coming from the offline knowledge base and stored notes only.",
    ]
    if knowledge_hits:
        lines.append("Knowledge base matches:")
        for hit in knowledge_hits[:3]:
            lines.append(f"- {hit['title']}: {hit['content'][:280]}")
    if memory_hits:
        lines.append("Related memory:")
        for hit in memory_hits[:3]:
            lines.append(f"- {hit['content']}")
    if not knowledge_hits and not memory_hits:
        lines.append(f"No offline knowledge match was found for: {last_user_text}")
    return "\n".join(lines)


def call_model(messages, memory_hits, knowledge_hits, tool_events):
    if MODEL_PROVIDER == "ollama":
        prompt = build_local_prompt(messages, memory_hits, knowledge_hits, tool_events)
        return call_ollama(prompt)

    if MODEL_PROVIDER == "gemini":
        contents = build_gemini_contents(messages) + build_gemini_context_messages(
            memory_hits, knowledge_hits, tool_events
        )
        return call_gemini(contents)

    raise RuntimeError(f"Unsupported MODEL_PROVIDER: {MODEL_PROVIDER}")


def parse_tool_call(text):
    candidate = (text or "").strip()
    if not candidate.startswith("{"):
        return None
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    tool_name = parsed.get("tool_name")
    arguments = parsed.get("arguments", {})
    if tool_name in TOOLS and isinstance(arguments, dict):
        return {"tool_name": tool_name, "arguments": arguments}
    return None


def run_tool(tool_name, arguments):
    tool = TOOLS[tool_name]
    result = tool(arguments)
    return {
        "tool_name": tool_name,
        "arguments": arguments,
        "result": result,
    }


def handle_chat(messages):
    working_messages = [dict(message) for message in messages]
    last_user_text = next(
        (message.get("text", "") for message in reversed(working_messages) if message.get("role") == "user"),
        "",
    )
    credential_theft_result = detect_credential_theft_code(last_user_text)
    if credential_theft_result:
        return {
            "reply": build_credential_theft_response(credential_theft_result),
            "tool_events": [],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    sql_injection_result = detect_sql_injection_code(last_user_text)
    if sql_injection_result:
        return {
            "reply": build_sql_injection_response(sql_injection_result),
            "tool_events": [],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "rule-based-defense",
        }

    if detect_code_example_request(last_user_text):
        code_results = search_code_examples(last_user_text, limit=3)
        return {
            "reply": build_code_example_response(code_results),
            "tool_events": [
                {
                    "tool_name": "search_code_examples",
                    "arguments": {"query": last_user_text},
                    "result": {"results": code_results},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": code_results,
            "model": "rule-based-defense",
        }

    if detect_attack_taxonomy_request(last_user_text) or detect_detection_rule_request(last_user_text):
        detection_results = search_detection_rules(last_user_text, limit=5)
        return {
            "reply": build_detection_rule_response(detection_results),
            "tool_events": [
                {
                    "tool_name": "search_detection_rules",
                    "arguments": {"query": last_user_text},
                    "result": {"results": detection_results},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": detection_results,
            "model": "rule-based-defense",
        }

    if detect_phishing_examples_request(last_user_text):
        requested_limit = extract_requested_count(last_user_text, default=100, maximum=100)
        phishing_results = search_phishing_examples(last_user_text, limit=requested_limit)
        return {
            "reply": build_phishing_examples_response(phishing_results),
            "tool_events": [
                {
                    "tool_name": "search_phishing_examples",
                    "arguments": {"query": last_user_text, "limit": requested_limit},
                    "result": {"results_count": len(phishing_results)},
                }
            ],
            "memory_hits": [],
            "knowledge_hits": phishing_results[:5],
            "model": "rule-based-defense",
        }

    if detect_phishing_classification_request(last_user_text):
        result = classify_with_threshold("phishing_email", last_user_text)
        if not result["meets_threshold"]:
            detection_results = search_detection_rules("detect phishing", limit=3)
            return {
                "reply": build_detection_rule_response(detection_results),
                "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "phishing_email", "text": last_user_text}, "result": result}],
                "memory_hits": [],
                "knowledge_hits": detection_results,
                "model": "fallback-detection-rules",
            }
        return {
            "reply": build_classifier_response(result),
            "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "phishing_email", "text": last_user_text}, "result": result}],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-pattern-model",
        }

    if detect_log_analysis_request(last_user_text):
        result = classify_with_threshold("log_threat", last_user_text)
        if not result["meets_threshold"]:
            detection_results = search_detection_rules("detect brute force ransomware phishing", limit=4)
            return {
                "reply": build_detection_rule_response(detection_results),
                "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "log_threat", "text": last_user_text}, "result": result}],
                "memory_hits": [],
                "knowledge_hits": detection_results,
                "model": "fallback-detection-rules",
            }
        return {
            "reply": build_classifier_response(result),
            "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "log_threat", "text": last_user_text}, "result": result}],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-pattern-model",
        }

    if detect_attack_label_request(last_user_text):
        result = classify_with_threshold("attack_category", last_user_text)
        if not result["meets_threshold"]:
            detection_results = search_detection_rules(last_user_text, limit=4)
            return {
                "reply": build_detection_rule_response(detection_results),
                "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "attack_category", "text": last_user_text}, "result": result}],
                "memory_hits": [],
                "knowledge_hits": detection_results,
                "model": "fallback-detection-rules",
            }
        return {
            "reply": build_classifier_response(result),
            "tool_events": [{"tool_name": "classify_defense_text", "arguments": {"model": "attack_category", "text": last_user_text}, "result": result}],
            "memory_hits": [],
            "knowledge_hits": [],
            "model": "local-pattern-model",
        }

    memory_hits = search_notes(last_user_text, limit=4) if last_user_text else []
    knowledge_hits = search_knowledge(last_user_text, limit=4) if last_user_text else []
    tool_events = []

    for _ in range(MAX_TOOL_STEPS):
        try:
            model_text = call_model(working_messages, memory_hits, knowledge_hits, tool_events)
        except RuntimeError as exc:
            if MODEL_PROVIDER == "ollama":
                return {
                    "reply": build_offline_fallback(last_user_text, knowledge_hits, memory_hits),
                    "tool_events": tool_events,
                    "memory_hits": memory_hits,
                    "knowledge_hits": knowledge_hits,
                    "model": "offline-retrieval",
                }
            raise exc
        tool_call = parse_tool_call(model_text)

        if not tool_call:
            return {
                "reply": model_text,
                "tool_events": tool_events,
                "memory_hits": memory_hits,
                "knowledge_hits": knowledge_hits,
                "model": DEFAULT_MODEL,
            }

        tool_result = run_tool(tool_call["tool_name"], tool_call["arguments"])
        tool_events.append(tool_result)
        working_messages.append(
            {
                "role": "assistant",
                "text": f"Tool request: {json.dumps(tool_call)}",
            }
        )
        working_messages.append(
            {
                "role": "user",
                "text": f"Tool result: {json.dumps(tool_result)}",
            }
        )

    raise RuntimeError("Tool loop limit reached.")


def normalize_messages(raw_messages):
    normalized = []
    for message in raw_messages:
        role = message.get("role")
        text = (message.get("text") or "").strip()
        if role in {"user", "assistant"} and text:
            normalized.append({"role": role, "text": text})
    return normalized


class ChatHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status_code, body, content_type, filename=None):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/state":
            self._send_json(200, conversation_stats())
            return

        if parsed.path == "/api/export":
            self.handle_export_get(parsed.query)
            return

        return super().do_GET()

    def do_POST(self):
        if self.path == "/api/chat":
            self.handle_chat_post()
            return

        if self.path == "/api/notes":
            self.handle_note_post()
            return

        self._send_json(404, {"error": "Not found"})

    def handle_chat_post(self):
        try:
            payload = self.read_json_body()
            messages = normalize_messages(payload.get("messages") or [])
            conversation_id = payload.get("conversation_id")

            if not messages:
                self._send_json(400, {"error": "A non-empty messages array is required."})
                return

            conversation_id = ensure_conversation(conversation_id)

            latest = messages[-1]
            if latest["role"] == "user":
                save_message(conversation_id, "user", latest["text"])

            result = handle_chat(messages)
            save_message(
                conversation_id,
                "assistant",
                result["reply"],
                meta={
                    "tool_events": result["tool_events"],
                    "memory_hits": result["memory_hits"],
                },
            )
            self._send_json(
                200,
                {
                    "conversation_id": conversation_id,
                    "reply": result["reply"],
                    "tool_events": result["tool_events"],
                    "memory_hits": result["memory_hits"],
                    "knowledge_hits": result.get("knowledge_hits", []),
                    "stats": conversation_stats(),
                    "model": result.get("model", DEFAULT_MODEL),
                },
            )
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
        except RuntimeError as exc:
            message = str(exc)
            status_code = 500
            if message.startswith("Gemini API error (429):"):
                status_code = 429
            elif message.startswith("Gemini API error (401):"):
                status_code = 401
            self._send_json(status_code, {"error": message})
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})

    def handle_note_post(self):
        try:
            payload = self.read_json_body()
            content = payload.get("content", "")
            note = remember_note(content, source="manual")
            self._send_json(200, {"note": note, "stats": conversation_stats()})
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON body."})
        except RuntimeError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})

    def read_json_body(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw_body or "{}")

    def handle_export_get(self, query_string):
        try:
            params = urllib.parse.parse_qs(query_string)
            conversation_id = int((params.get("conversation_id") or [0])[0])
            export_format = (params.get("format") or ["markdown"])[0].lower()
            if conversation_id <= 0:
                self._send_json(400, {"error": "A valid conversation_id is required."})
                return
            if export_format not in {"markdown", "json"}:
                self._send_json(400, {"error": "format must be markdown or json."})
                return

            body_text, content_type, filename = build_conversation_export(conversation_id, export_format)
            self._send_bytes(200, body_text.encode("utf-8"), content_type, filename)
        except RuntimeError as exc:
            self._send_json(404, {"error": str(exc)})
        except Exception:
            self._send_json(500, {"error": "Unexpected server error."})


def main():
    global SSL_CONTEXT
    SSL_CONTEXT = build_ssl_context()
    init_db()
    seed_knowledge()
    load_defense_models()
    server = ThreadingHTTPServer((HOST, PORT), ChatHandler)
    print(f"Serving chatbot app at http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
