# Security Policy

ExitOne is a security-research tool. This policy covers vulnerabilities **in ExitOne itself** (the Go binary, its local LLM sidecar management, its Control Console, TUI, and stored investigation data) — not how you use it against a target.

## Supported versions

ExitOne does not yet cut tagged releases; only the `main` branch is supported. Please make sure a report reproduces against the latest commit on `main` before filing it.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a security vulnerability. Instead, use GitHub's private vulnerability reporting for this repository:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Include: the affected file/command, a minimal reproduction, and the impact (e.g., local privilege escalation, credential disclosure, path traversal, command injection into a rendered candidate).

You should get an initial response within a few days. Please give us a reasonable amount of time to address the issue before any public disclosure.

## What's in scope

- Credential handling (`internal/credential`) — masking, storage, and the `--reveal` flow.
- Anything that could execute an attacker-controlled string as a shell command *without* the explicit human-in-the-loop `accept` step ExitOne is designed around.
- The local LLM sidecar lifecycle (`internal/llm/server.go`) — e.g., unsafe handling of `EXITONE_LLM_URL`/`EXITONE_ALLOW_REMOTE_LLM`, or anything that could exfiltrate investigation context to a remote endpoint without the explicit opt-in.
- SQL injection or path traversal in evidence ingestion (`internal/parsers`, `internal/investigation`).
- The embedded TUI's PTY handling (`cmd/exitone/tui.go`) — e.g., escape-sequence or terminal-injection issues from rendering untrusted scan output.

## What's out of scope

- The fact that ExitOne, when explicitly directed by its operator, generates and can insert commands that are offensive-security tools by nature (port scans, exploitation guidance, etc.). That is the product's intended, human-in-the-loop purpose — see the README's scope statement.
- Vulnerabilities in third-party dependencies (`go.mod`) — please report those upstream; Dependabot keeps this repository's copies current.
