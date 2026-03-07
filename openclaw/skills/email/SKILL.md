---
name: email
description: "Send and read emails via Gmail API with OAuth2. Compose, send, list inbox, read messages, and search emails from the terminal."
homepage: https://developers.google.com/gmail/api
metadata:
  {
    "openclaw":
      {
        "emoji": "📧",
        "requires": { "bins": ["python3"], "env": ["GMAIL_CREDENTIALS_FILE"] },
        "primaryEnv": "GMAIL_CREDENTIALS_FILE",
        "install":
          [
            {
              "id": "python-brew",
              "kind": "brew",
              "formula": "python",
              "bins": ["python3"],
              "label": "Install Python (brew)",
            },
          ],
      },
  }
---

# Gmail Email Agent

Send and read emails via the Gmail API using OAuth2 authentication.

## Google Cloud Setup (one-time)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select an existing one)
3. Enable the **Gmail API**:
   - Navigate to **APIs & Services > Library**
   - Search for "Gmail API" and click **Enable**
4. Create OAuth2 credentials:
   - Go to **APIs & Services > Credentials**
   - Click **Create Credentials > OAuth client ID**
   - Application type: **Desktop app**
   - Download the JSON file
5. Save the credentials file and set the env var:

```bash
# Save the downloaded JSON somewhere safe
mv ~/Downloads/client_secret_*.json ~/.config/gmail-credentials.json

# Set the environment variable
export GMAIL_CREDENTIALS_FILE=~/.config/gmail-credentials.json
```

6. Configure OAuth consent screen:
   - Go to **APIs & Services > OAuth consent screen**
   - Add your email as a test user (required while app is in "Testing" status)

## Run

First run will open a browser for OAuth consent. The token is cached at `~/.config/gmail-token.json`.

### Send an email

```bash
python3 {baseDir}/scripts/email_agent.py send \
  --to "recipient@example.com" \
  --subject "Hello from OpenClaw" \
  --body "This is a test email sent via the Gmail API."
```

### Send with CC/BCC

```bash
python3 {baseDir}/scripts/email_agent.py send \
  --to "recipient@example.com" \
  --cc "cc@example.com" \
  --bcc "bcc@example.com" \
  --subject "Team Update" \
  --body "Here's the latest update."
```

### List inbox messages

```bash
python3 {baseDir}/scripts/email_agent.py inbox
python3 {baseDir}/scripts/email_agent.py inbox --max-results 20
```

### Read a specific message

```bash
python3 {baseDir}/scripts/email_agent.py read --message-id <MESSAGE_ID>
```

### Search emails

```bash
python3 {baseDir}/scripts/email_agent.py search --query "from:boss@company.com subject:urgent"
python3 {baseDir}/scripts/email_agent.py search --query "is:unread" --max-results 5
```

## Output

All commands output JSON to stdout for easy parsing. Use `--pretty` for human-readable output.

```bash
python3 {baseDir}/scripts/email_agent.py inbox --pretty
python3 {baseDir}/scripts/email_agent.py read --message-id <ID> --pretty
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GMAIL_CREDENTIALS_FILE` | Yes | Path to OAuth2 client credentials JSON |
| `GMAIL_TOKEN_FILE` | No | Path to cached token (default: `~/.config/gmail-token.json`) |
