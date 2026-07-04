### `payloads/defaults/paths.json`

**`end_paths`** — appended to the end of the path:
```json
{ "id": "my-id", "value": "{{PATH}}/suffix", "desc": "what it does", "requires_raw": false }
```

**`mid_paths`** — full path replacement using template vars:
```json
{ "id": "my-id", "value": "/prefix/{{PATH_NOSLASH}}", "desc": "what it does", "requires_raw": true }
```

Available template vars:

| Token | Expands to |
|---|---|
| `{{PATH}}` | full path e.g. `/api/admin` |
| `{{PATH_NOSLASH}}` | path without leading slash e.g. `api/admin` |
| `{{PATH_CAP}}` | first char of first segment uppercased |
| `{{PATH_UPPER}}` | full path uppercased (no leading slash) |
| `{{PATH_URLESCAPED}}` | path percent-escaped via `url.PathEscape` |
| `{{PATH_FIRSTSLASH_DBL}}` | first internal slash doubled |
| `{{PATH_FIRSTSLASH_ENC}}` | first internal slash as `%2F` |

`requires_raw: true` — must be set whenever the payload contains any character Go's URL parser would normalize away: `%2e`, `%2f`, `..`, `;`, `#`, `\`, raw control bytes, anything that must survive on the wire unmodified. When in doubt, set it `true`.

**`raw_encoding_strategies`** — programmatic encoding of path segments, no `value` field, depth-driven:
```json
{ "id": "enc-last-char-d2", "desc": "what it does", "requires_raw": true, "depth": 2 }
```
The `id` prefix must match one of the strategy names the switch handles: `enc-last-char`, `enc-first-char`, `enc-last-segment`, `enc-full-path`, `enc-full-segment`. Depth 1/2/3 = single/double/triple encoding.

---

### `payloads/defaults/headers.json`

**`ip_headers`** — just a string, added to the IP × value matrix:
```json
"X-My-Header"
```

**`ip_values`** — just a string, tried against every IP header:
```json
"169.254.169.254"
```

**`port_headers`** / **`port_values`** — same, strings only.

**`override_headers`** — sends `GET /` with the path in the header value:
```json
{ "name": "X-My-URL", "value_is_path": true, "desc": "what it does" }
```
Or a fixed value instead:
```json
{ "name": "X-My-Header", "value": "127.0.0.1", "desc": "what it does" }
```

**`static_headers`** — single fixed name/value, sent as-is. Optional `source` for CVE attribution:
```json
{ "name": "Header-Name", "value": "header-value", "desc": "what it does", "source": "CVE-2025-XXXXX" }
```

**`user_agents`** — just a string:
```json
"MyScanner/1.0"
```

**`debug_params`** — appended as a query param, just a string (no leading `?`/`&`, that's handled automatically):
```json
"admin=true"
```

---

### `payloads/defaults/unicode.json`

**`normalize_pairs`** — ASCII char replaced with a Unicode lookalike the WAF won't match but the app normalizes back:
```json
{ "ascii": "s", "unicode": "\uFF53", "desc": "fullwidth latin small letter s" }
```

**`truncate_chars`** — a Unicode char whose low byte matches the target ASCII char (naive `char & 0xFF` stripping):
```json
{ "target_ascii": "/", "byte": "\u022F", "desc": "U+022F → 0x2F" }
```

**`apply_to_segments`** — path segment words that get the unicode treatment applied directly:
```json
"dashboard"
```

---

### `payloads/defaults/bytequirks.json`

**`frameworks`** — a framework block with raw byte values and where to inject them:
```json
{
  "name": "my-framework",
  "desc": "what quirk this exploits",
  "bytes": ["0x1C", "0x1D"],
  "positions": ["prefix", "segment"],
  "note": "optional context"
}
```
`positions`: `prefix` = prepend to the full path, `segment` = insert as a synthetic path segment before the last segment. Each byte is tried in both `raw` and `percent` encoded forms (controlled by the top-level `encode_forms` array).