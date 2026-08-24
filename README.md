# wappy

`wappy` is a fast CLI tool that finds the technologies used by websites and subdomains. It checks HTTP headers, cookies, and HTML with the [WappalyzerGo](https://github.com/projectdiscovery/wappalyzergo) fingerprint database.

## Install

With Go 1.25 or newer:

```sh
go install github.com/gokulapap/wappalyzer-cli/cmd/wappy@latest
```

Or build it from source:

```sh
git clone https://github.com/gokulapap/wappalyzer-cli.git
cd wappalyzer-cli
make install
```

## Quick start

```sh
wappy example.com
wappy app.example.com api.example.com -c 20
wappy -f subdomains.txt -o results.jsonl
subfinder -silent -d example.com | wappy --stdin -q
```

For hostnames, `wappy` tries HTTPS first and then HTTP. Full URLs keep their original scheme and path.

## Useful examples

```sh
wappy example.com --format json
wappy -f targets.txt --rate 5 --timeout 10s
wappy example.com -H 'X-API-Key: value'
wappy example.com --proxy http://127.0.0.1:8080
```

Output can be text, JSON, JSONL, or CSV. The file extension selects the format automatically when `--format` is not set.

## What it includes

- Fast scans with safe concurrency, rate limits, timeouts, and retries.
- Input from arguments, files, or stdin.
- Custom headers, proxies, TLS options, category filters, and fingerprint files.
- Stable result order and safe file writing.
- Clear exit codes for scripts and pipelines.

Run `wappy --help` for every option or `wappy categories` to list technology categories.

Exit codes: `0` for success, `1` when a target fails, `2` for invalid input, and `130` when interrupted.

## Development

```sh
make check
docker build -t wappy .
```

Only scan websites you own or have permission to test.
