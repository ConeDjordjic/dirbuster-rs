# dirbuster-rs

A fast, concurrent, and feature-rich directory and file buster written in Rust.

## Demo

![dirbuster-rs in action](demo.gif)

*This isn't sped up footage, promise*

## Features

- **High Performance**: Multi-threaded scanning with configurable concurrency
- **Wildcard Detection**: Automatically detects and filters out wildcard responses
- **Flexible Authentication**: Support for basic auth, bearer tokens, and custom headers
- **Multiple Output Formats**: Export results in JSON, CSV, XML, or plain text
- **Evasion Techniques**: User-Agent rotation, IP header spoofing, and request delays
- **Smart Filtering**: Filter results by status codes, content length, response time, and word count

## Installation

### From Source

```bash
git clone https://github.com/ConeDjordjic/dirbuster-rs.git
cd dirbuster-rs
cargo build --release
```

The binary will be available at `target/release/dirbuster-rs`.

## Usage

### Basic Usage

```bash
dirbuster-rs -u https://example.com -w wordlist.txt
```

### Common Options

```bash
# Scan with 50 threads and show only successful results
dirbuster-rs -u https://example.com -w wordlist.txt -t 50 --only-success

# Enable wildcard detection and save results to JSON
dirbuster-rs -u https://example.com -w wordlist.txt --detect-wildcards --output-file results.json --output-format json

# Use authentication and custom headers
dirbuster-rs -u https://example.com -w wordlist.txt --bearer-token "your-token" --headers "X-Custom-Header:value"
```

### Advanced Features

```bash
# Enable evasion techniques
dirbuster-rs -u https://example.com -w wordlist.txt --rotate-user-agent --rotate-ip-headers --delay-min 100 --delay-max 500

# Filter results by size and response time
dirbuster-rs -u https://example.com -w wordlist.txt --filter-size "100-5000" --filter-time 2000

# Use a proxy
dirbuster-rs -u https://example.com -w wordlist.txt --proxy http://127.0.0.1:8080
```

## Command Line Options

| Option                    | Description                                         |
| ------------------------- | --------------------------------------------------- |
| `-u, --url`               | Target URL to scan                                  |
| `-w, --word-list`         | Path to wordlist file                               |
| `-t, --threads`           | Number of concurrent threads (default: 20)          |
| `--timeout`               | Request timeout in seconds (default: 5)             |
| `--only-success`          | Show only successful results (2xx status codes)     |
| `--detect-wildcards`      | Enable wildcard response detection                  |
| `--output-file`           | Save results to file                                |
| `--output-format`         | Output format: text, json, xml, csv (default: text) |
| `--resume`                | Resume scan from saved state file                   |
| `--save-state`            | Save scan progress to file                          |
| `--rotate-user-agent`     | Rotate User-Agent headers                           |
| `--rotate-ip-headers`     | Rotate IP-related headers                           |
| `--delay-min/--delay-max` | Request delay range in milliseconds                 |
| `--filter-codes`          | Filter out specific status codes                    |
| `--filter-size`           | Filter by content size range                        |
| `--filter-time`           | Filter by response time                             |
| `--basic-auth`            | Basic authentication (username:password)            |
| `--bearer-token`          | Bearer token for authentication                     |
| `--headers`               | Custom headers (key:value format)                   |
| `--proxy`                 | HTTP proxy URL                                      |

## Examples

### Directory Enumeration

```bash
dirbuster-rs -u https://example.com -w common.txt -t 50 --detect-wildcards --only-success
```

### API Endpoint Discovery

```bash
dirbuster-rs -u https://api.example.com -w api-endpoints.txt --bearer-token "your-api-token" --headers "Content-Type:application/json"
```

### Stealth Scanning

```bash
dirbuster-rs -u https://example.com -w wordlist.txt --rotate-user-agent --rotate-ip-headers --delay-min 500 --delay-max 1500
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
