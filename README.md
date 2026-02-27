![bleh](/a7/bleh.png)

run compute as you wish

---

## Requirements

[Bun](https://bun.sh)

## Run

```sh
PASSPHRASE=your-secret bun run index.js
```

`PASSPHRASE` is used to reset your dashboard password if you forget it. `PORT` defaults to 3000.

Open `http://localhost:3000/__dashboard`, set a password, and start.

## Routes

Create an endpoint with a path (e.g. `/hello/:name`), method, and JS code. Your code receives:

- `req` — raw Request object
- `body` — parsed JSON or raw text
- `headers` — request headers
- `query` — URL query params
- `params` — path params (e.g. `{ name: "world" }`)
- `store` — persistent key-value store

Return any value → sent as JSON. Return a `Response` for full control.

```js
return { message: `hello ${params.name}` }
```

## Crons

Like routes but scheduled. Receives only `store`. Schedule format: `30s`, `5m`, `2h`, `1d`.

## Store

SQLite-backed key-value store, organized by collections. Available in routes and crons:

```js
store.set("col", "key", { any: "value" })
store.get("col", "key")
store.all("col")
store.delete("col", "key")
store.find("col", v => v.active === true)
```

Browse and manage collections in the dashboard under **Store**.

## Files

Upload files via the dashboard. Serve them at `/__u/:id`.

## Per-route options

- **CORS** — set allowed origin
- **Logging** — stores last 200 requests
- **Rate limiting** — by route or IP, with configurable window
