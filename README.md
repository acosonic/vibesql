# VibeSql

A single-file PHP MySQL query interface with AI-powered SQL generation via Claude.

## Features

- **AI query generation** — describe what you want in plain English, Claude writes the SQL
- **Schema sidebar** — browse all tables and columns of the selected database
- **SQL editor** — write and run queries directly, with keyboard shortcuts
- **Dark / light theme** — toggle in the header, persisted in localStorage
- **Secure credential storage** — host/user in localStorage, password/API key in sessionStorage only
- **CSRF protection** — all API calls validated server-side
- **SQL safety checks** — blocks `INTO OUTFILE`, `LOAD_FILE`, UDFs and other dangerous statements

## Requirements

- PHP 8.1+ with `mysqli` extension
- MySQL / MariaDB
- A web server (Apache, Nginx, or `php -S localhost:8080`)

## Setup

1. Drop `index.php` into any web-served directory
2. Open it in your browser
3. Enter your MySQL credentials and (optionally) an Anthropic API key in the settings modal

No composer, no npm, no build step — just one file.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Enter` in SQL editor | Run query |
| `Ctrl+Enter` in AI input | Generate SQL |
| `Escape` | Close settings modal |

## Security notes

- Passwords and API keys are stored in **sessionStorage** and are cleared when the browser tab closes
- All API requests include a session CSRF token — the endpoint rejects requests from other origins
- SQL execution uses `mysqli::query()` (single-statement only — no stacked queries)
