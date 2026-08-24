# wappy

`wappy` finds the web technologies used by websites and subdomains. It is a fast Go CLI built for single targets, large lists, and shell pipelines.

It checks headers, cookies, HTML, the parsed DOM, inline scripts, and CSS. Deep mode can inspect more pages and linked assets.

It uses the [WappalyzerGo](https://github.com/projectdiscovery/wappalyzergo) fingerprint database and adds detection layers the library does not run by itself.

## Install

Use Go 1.25 or newer:

```sh
go install github.com/gokulapap/wappalyzer-cli/cmd/wappy@latest
```

Or build this checkout:

```sh
make install
```

## Use

```sh
wappy example.com
wappy app.example.com api.example.com -c 20
wappy -f subdomains.txt -o results.jsonl
subfinder -silent -d example.com | wappy --stdin -q
```

Hostnames try HTTPS first and then HTTP. Full URLs keep their scheme and path.

Use deeper checks when you need more coverage:

```sh
wappy example.com --deep
wappy example.com --deep --explain
```

`--deep` safely crawls up to five same-host pages and inspects linked scripts and styles.

Text, JSON, JSONL, and CSV output are supported. JSON and CSV include confidence, evidence, versions, categories, page counts, and partial scan warnings.

Useful controls:

```sh
wappy -f targets.txt --rate 5 --timeout 10s --retries 2
wappy example.com -H 'Authorization: Bearer token'
wappy example.com --proxy http://127.0.0.1:8080
wappy example.com --category CMS --min-confidence 80
```

Run `wappy --help` for all options and `wappy categories` for category names.

Exit codes are `0` for success, `1` when a target fails, `2` for invalid input, and `130` when interrupted.

## Develop

```sh
make check
docker build -t wappy .
```

Only scan websites you own or have permission to test.
