import json
import sys
from urllib import error, request


def main():
    url = "http://127.0.0.1:8000/api/state"
    try:
        with request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except error.URLError as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        raise SystemExit(1)

    required = ["conversations", "messages", "notes", "knowledge_docs"]
    missing = [key for key in required if key not in payload]
    if missing:
        print(f"healthcheck failed: missing keys {missing}", file=sys.stderr)
        raise SystemExit(1)

    print("healthcheck ok")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
