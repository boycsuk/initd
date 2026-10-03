# Backend

> **What this file is.** The public surface of the backend: every endpoint
> (path, method, request/response shape, status codes, auth), the shared error
> model, and the cross-endpoint conventions a client must know. It is the
> contract clients code against. Internal implementation details do NOT belong
> here.
>
> **What this file is NOT.** Not the visual contract (`ui.md` has screens and
> design tokens), not behavior in user terms (`user-stories.md` has what the
> user can do). This file answers "what can a client call, and what comes
> back".
>
> **How to keep it true (no tooling required).** Plain Markdown — maintain it
> by hand in any editor. With Claude Code, `/update-docs` updates it from the
> diff; without it (a sandboxed editor, a teammate), edit it directly. Update
> whenever an endpoint is added/removed/renamed, or its request/response shape,
> status codes, or auth requirement changes. **Coverage over depth:** every
> endpoint must appear, even as a one-liner; the list must be exhaustive even
> if each entry is shallow. A reader should be able to answer "what can this
> backend do?" without opening the source.

## Overview

<!-- One short paragraph. What is this backend, what does it serve, who
consumes it. Example:
"REST API serving the iOS app and the web client. All endpoints return
JSON. Auth is bearer-token (see `/auth/login`). Base URL in production:
https://api.example.com." -->

## Auth

<!-- How auth works at the protocol level: token type, where the token
goes (header / cookie), how it is obtained, how long it lives. Skip if
the backend is fully public. -->

## Endpoints

<!-- One section per endpoint. Keep each entry tight: path, method,
purpose in one sentence, request shape, response shape, notable error
cases. Group by resource if useful (### Users, ### Sessions, …). Remove
this placeholder block once real endpoints exist.

### `POST /auth/login`

Authenticates a user and returns a bearer token.

Request:
```json
{ "email": "string", "password": "string" }
```

Response 200:
```json
{ "token": "string", "expires_at": "ISO-8601" }
```

Errors:
- 401 — invalid credentials.
- 429 — too many attempts (rate-limited).
-->

## Error model

<!-- Shared response shape for errors across endpoints. Example:
All non-2xx responses return:
```json
{ "error": { "code": "string", "message": "string" } }
```
`code` is a stable machine-readable identifier; `message` is for humans
and may change. Clients should branch on `code`, not on `message`. -->

## Conventions

<!-- Cross-endpoint rules a consumer must know: pagination shape,
timestamp format, ID format, idempotency, rate limits. -->
