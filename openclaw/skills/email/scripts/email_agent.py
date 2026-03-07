#!/usr/bin/env python3
"""Gmail Email Agent — send and read emails via Gmail API with OAuth2."""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path

DEFAULT_TOKEN_PATH = Path.home() / ".config" / "gmail-token.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"


def load_credentials() -> dict:
    creds_path = os.environ.get("GMAIL_CREDENTIALS_FILE", "").strip()
    if not creds_path:
        print("Error: GMAIL_CREDENTIALS_FILE environment variable not set.", file=sys.stderr)
        print("See SKILL.md for Google Cloud setup instructions.", file=sys.stderr)
        sys.exit(2)
    path = Path(creds_path).expanduser()
    if not path.exists():
        print(f"Error: Credentials file not found: {path}", file=sys.stderr)
        sys.exit(2)
    data = json.loads(path.read_text())
    # Handle both "installed" and "web" credential types
    return data.get("installed") or data.get("web") or data


def token_path() -> Path:
    return Path(os.environ.get("GMAIL_TOKEN_FILE", str(DEFAULT_TOKEN_PATH))).expanduser()


def save_token(token_data: dict) -> None:
    tp = token_path()
    tp.parent.mkdir(parents=True, exist_ok=True)
    tp.write_text(json.dumps(token_data))


def load_token() -> dict | None:
    tp = token_path()
    if tp.exists():
        return json.loads(tp.read_text())
    return None


def http_post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def authorize(creds: dict) -> str:
    """Get a valid access token, refreshing or doing full OAuth flow as needed."""
    token_data = load_token()

    # Try to use existing token
    if token_data and token_data.get("access_token"):
        # Try refresh if we have a refresh token
        if token_data.get("refresh_token"):
            try:
                refreshed = http_post_form(
                    "https://oauth2.googleapis.com/token",
                    {
                        "client_id": creds["client_id"],
                        "client_secret": creds["client_secret"],
                        "refresh_token": token_data["refresh_token"],
                        "grant_type": "refresh_token",
                    },
                )
                refreshed.setdefault("refresh_token", token_data["refresh_token"])
                save_token(refreshed)
                return refreshed["access_token"]
            except urllib.error.HTTPError:
                pass  # Fall through to full auth flow

    # Full OAuth2 flow — local HTTP server captures the redirect
    import http.server
    import threading
    import webbrowser

    redirect_port = 8095
    redirect_uri = f"http://localhost:{redirect_port}"
    auth_code_result: list[str] = []
    auth_error: list[str] = []

    class _OAuthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            code = params.get("code", [""])[0]
            error = params.get("error", [""])[0]
            if code:
                auth_code_result.append(code)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h2>Authorization successful!</h2><p>You can close this tab.</p></body></html>")
            else:
                auth_error.append(error or "unknown error")
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><body><h2>Authorization failed</h2><p>{error}</p></body></html>".encode())

        def log_message(self, format, *args):
            pass  # Suppress request logs

    auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode(
            {
                "client_id": creds["client_id"],
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(SCOPES),
                "access_type": "offline",
                "prompt": "consent",
            }
        )
    )

    server = http.server.HTTPServer(("localhost", redirect_port), _OAuthHandler)
    server.timeout = 120  # 2 minute timeout for user to authorize

    print(f"\nOpening browser for Gmail authorization...", file=sys.stderr)
    print(f"If the browser doesn't open, visit:\n{auth_url}\n", file=sys.stderr)
    webbrowser.open(auth_url)

    # Wait for the OAuth redirect callback
    while not auth_code_result and not auth_error:
        server.handle_request()
    server.server_close()

    if auth_error:
        print(f"Authorization failed: {auth_error[0]}", file=sys.stderr)
        sys.exit(1)

    code = auth_code_result[0]

    token_resp = http_post_form(
        "https://oauth2.googleapis.com/token",
        {
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        },
    )
    save_token(token_resp)
    return token_resp["access_token"]


def gmail_request(access_token: str, endpoint: str, method: str = "GET", body: dict | None = None) -> dict:
    url = f"{GMAIL_API}/{endpoint}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {access_token}")
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gmail API error ({e.code}): {error_body}") from e


def send_email(access_token: str, to: str, subject: str, body: str, cc: str = "", bcc: str = "") -> dict:
    msg = MIMEText(body)
    msg["To"] = to
    msg["Subject"] = subject
    if cc:
        msg["Cc"] = cc
    if bcc:
        msg["Bcc"] = bcc

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
    return gmail_request(access_token, "messages/send", method="POST", body={"raw": raw})


def list_messages(access_token: str, query: str = "", max_results: int = 10) -> list[dict]:
    params = {"maxResults": str(max_results)}
    if query:
        params["q"] = query
    endpoint = "messages?" + urllib.parse.urlencode(params)
    resp = gmail_request(access_token, endpoint)
    messages = resp.get("messages", [])

    results = []
    for msg_stub in messages:
        msg = gmail_request(access_token, f"messages/{msg_stub['id']}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date")
        headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
        results.append({
            "id": msg["id"],
            "threadId": msg.get("threadId", ""),
            "snippet": msg.get("snippet", ""),
            "from": headers.get("From", ""),
            "subject": headers.get("Subject", ""),
            "date": headers.get("Date", ""),
            "labelIds": msg.get("labelIds", []),
        })
    return results


def read_message(access_token: str, message_id: str) -> dict:
    msg = gmail_request(access_token, f"messages/{message_id}?format=full")
    headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}

    # Extract body text
    body_text = ""
    payload = msg.get("payload", {})

    def extract_text(part: dict) -> str:
        if part.get("mimeType", "").startswith("text/plain"):
            data = part.get("body", {}).get("data", "")
            if data:
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
        for sub in part.get("parts", []):
            result = extract_text(sub)
            if result:
                return result
        return ""

    body_text = extract_text(payload)

    return {
        "id": msg["id"],
        "threadId": msg.get("threadId", ""),
        "from": headers.get("From", ""),
        "to": headers.get("To", ""),
        "subject": headers.get("Subject", ""),
        "date": headers.get("Date", ""),
        "body": body_text,
        "snippet": msg.get("snippet", ""),
        "labelIds": msg.get("labelIds", []),
    }


def output(data, pretty: bool = False) -> None:
    if pretty:
        if isinstance(data, list):
            for i, item in enumerate(data, 1):
                print(f"\n--- Message {i} ---")
                for k, v in item.items():
                    if k == "body":
                        print(f"  {k}:\n{v}")
                    elif k == "labelIds":
                        print(f"  {k}: {', '.join(v)}")
                    else:
                        print(f"  {k}: {v}")
        elif isinstance(data, dict):
            for k, v in data.items():
                if k == "body":
                    print(f"\n{k}:\n{v}")
                elif k == "labelIds":
                    print(f"{k}: {', '.join(v)}")
                else:
                    print(f"{k}: {v}")
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def main() -> int:
    ap = argparse.ArgumentParser(description="Gmail Email Agent — send and read emails via Gmail API.")
    ap.add_argument("--pretty", action="store_true", help="Human-readable output instead of JSON.")
    sub = ap.add_subparsers(dest="command", required=True)

    # send
    sp_send = sub.add_parser("send", help="Send an email.")
    sp_send.add_argument("--to", required=True, help="Recipient email address.")
    sp_send.add_argument("--subject", required=True, help="Email subject.")
    sp_send.add_argument("--body", required=True, help="Email body text.")
    sp_send.add_argument("--cc", default="", help="CC recipients.")
    sp_send.add_argument("--bcc", default="", help="BCC recipients.")

    # inbox
    sp_inbox = sub.add_parser("inbox", help="List inbox messages.")
    sp_inbox.add_argument("--max-results", type=int, default=10, help="Max messages to return.")

    # read
    sp_read = sub.add_parser("read", help="Read a specific message.")
    sp_read.add_argument("--message-id", required=True, help="Gmail message ID.")

    # search
    sp_search = sub.add_parser("search", help="Search emails.")
    sp_search.add_argument("--query", required=True, help="Gmail search query (same syntax as Gmail search bar).")
    sp_search.add_argument("--max-results", type=int, default=10, help="Max messages to return.")

    args = ap.parse_args()

    creds = load_credentials()
    access_token = authorize(creds)

    if args.command == "send":
        result = send_email(access_token, args.to, args.subject, args.body, args.cc, args.bcc)
        if args.pretty:
            print(f"Email sent successfully! Message ID: {result.get('id', 'unknown')}")
        else:
            output(result)

    elif args.command == "inbox":
        messages = list_messages(access_token, query="in:inbox", max_results=args.max_results)
        output(messages, args.pretty)

    elif args.command == "read":
        msg = read_message(access_token, args.message_id)
        output(msg, args.pretty)

    elif args.command == "search":
        messages = list_messages(access_token, query=args.query, max_results=args.max_results)
        output(messages, args.pretty)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
