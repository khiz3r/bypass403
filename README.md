# bypass403

A Go-based 403 bypass scanner that generates request variants across path, header, method, protocol, Unicode, and byte-quirk mutation modules.

## Features

- Path mutation payloads from configurable JSON payloads
- Header injection and override payloads
- Method and protocol trick fuzzing
- Unicode and byte-quirk bypass mutations
- Optional Wayback Machine path discovery
- Output to terminal and optional text file
- Status-code filtering (`-fc`) to hide noisy responses from the report
- Baseline check gates the whole scan: if the target isn't returning 403 to begin with, no bypass payloads are sent
- Default payload DB lookup in ~/.config/bypass403

## Installation

```bash
git clone https://github.com/khiz3r/bypass403.git
cd bypass403
go build -o bypass403 .
```

### Configure payloads directory

Create the default payloads directory and copy the bundled JSON payload files into it:

```bash
mkdir -p ~/.config/bypass403
cp payloads/defaults/*.json ~/.config/bypass403/
```

## Build

```bash
cd /home/max/Downloads/bypass403
go build -o bypass403 .
sudo cp bypass403 /usr/local/bin/ # Optional
```

## Usage

```bash
./bypass403 -u https://example.com/admin
```

### Command-line flags

- `-u` : Target URL. Required.
- `-t` : Number of concurrent worker threads. Default is `3`.
- `-d` : Delay between requests in milliseconds. Default is `500` ms.
- `-proxy` : Proxy URL to use for requests. If you pass `-proxy` without a value, the default proxy `http://127.0.0.1:8080` is used. You can also override it with any other proxy URL.
- `-k` : Skip TLS certificate verification.
- `-silent` : Print only the findings and suppress the banner.
- `-debug` : Show verbose request/response details.
- `-wayback` : Enable Wayback Machine path discovery.
- `-o` : Write the report output to a text file.
- `-fc` : Filter out response status codes from the report. Comma-separated, ranges supported (e.g. `-fc 404,400-410`).
- `-H` : Add a custom header. Repeat the flag to set multiple headers.

### Examples

```bash
./bypass403 -u https://example.com/admin
```

```bash
./bypass403 -u https://example.com/admin -d 500 -proxy http://127.0.0.1:8080 -o report.txt -silent
```

```bash
./bypass403 -u https://example.com/admin \
  -H "X-Test: 1" \
  -H "Cookie: a=b"
```

```bash
./bypass403 -u https://example.com/admin -fc 404,400-410
```

## Defaults

- Delay between requests: 500 ms
- Proxy: uses `http://127.0.0.1:8080` when `-proxy` is provided without a value
- Payload DB directory: `~/.config/bypass403`

## Payloads

The tool loads payload JSON files from the following locations, in order:

1. Explicit directory passed to the loader
2. `~/.config/bypass403`
3. `./payloads`
4. Embedded defaults

## Notes

- If you provide `-proxy` without a value, the default proxy target is used.
- You can override it with any custom proxy URL.
- Use `-o <file>` to save the report output to a text file.
- Before running any bypass payloads, the tool sends a single baseline request to the target. If that baseline doesn't come back `403`, the scan stops there with a warning — there's nothing to bypass on an endpoint that isn't already blocking you. This check runs even with `-silent`.
- `-fc` drops matching status codes from the report entirely (they aren't scored or counted toward HIGH/MEDIUM/LOW); the summary line shows how many were filtered.