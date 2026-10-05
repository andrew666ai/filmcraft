# Security

FilmCraft is a local editor. This note covers the desktop control channel and the MCP bridge for personal use. It is not a hosted or multi-user service.

## Reporting

Contact the repository owner privately with the version, what you ran, and what happened. Do not include bearer tokens, project contents, or a public exploit.

## Control channel

`filmcraft --control <port>` (or `FILMCRAFT_CONTROL_PORT`) listens on `127.0.0.1` only. The first line on each connection must be:

```json
{"id": 1, "method": "auth", "params": {"token": "<64 lowercase hex characters>"}}
```

Methods are not dispatched until that handshake succeeds. A missing or wrong token closes the connection with `authentication required`. The token is 256 bits, compared without an early exit on the first mismatching byte.

Provide it with one of:

- `--control-token-file <path>` or `FILMCRAFT_CONTROL_TOKEN_FILE` — a private file. If it does not exist yet, the app creates it (mode `0600` on Unix) and does not print the token.
- `--control-token <64-hex>` or `FILMCRAFT_CONTROL_TOKEN` — the token itself. Prefer a file: command lines show up in the process list.
- neither — the app generates a token and prints it once on stderr. Do not commit that line or copy it into a ticket.

Do not pass a token and a token file together.

## MCP

Prefer stdio. `filmcraft-cli mcp` (headless, in-process) does not open a TCP port and does not use this token. Tools are unchanged.

`filmcraft-cli mcp --bridge 127.0.0.1:<port>` and `filmcraft-cli --bridge` talk to the desktop control server. They send the same `auth` handshake first, using `--control-token`, `--control-token-file`, or the environment variables above. The bridge refuses non-loopback addresses.

```sh
filmcraft --control 9876 --control-token-file ~/.config/filmcraft/control-token
FILMCRAFT_CONTROL_TOKEN_FILE=~/.config/filmcraft/control-token \
  filmcraft-cli mcp --bridge 127.0.0.1:9876
```

Starting the desktop app with no `--control` flag does not listen, and the window behaves as before.

## Budgets

Each control listener serves at most 16 connections. A request line may be at most 1 MiB. A reply may be at most 8 MiB; a larger reply is replaced with an error that keeps the request id (the edit may already have been applied). Connections use 30-second read and write timeouts. Failures use stable `error` strings: `authentication required`, `connection limit reached`, `request exceeds 1048576 bytes`.

## Limitations

An authenticated connection can call the full control surface, including commands, UI input, and `app.quit`. There is no capability list and no security audit log. Loopback TCP is not encrypted — do not tunnel or proxy it. Stdio MCP trusts the local process that spawns it. Token files should stay out of the repository and out of shell history.
