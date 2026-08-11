# ddos-tool

> **Go-based network traffic testing and security research tool for authorized environments.**

`ddos-tool` is an interactive command-line network traffic-testing utility written in Go.

It provides multiple TCP, UDP, and HTTP traffic-generation methods, configurable concurrency, proxy management, multi-target testing, **subnet-based testing**, traffic statistics, result logging, network diagnostics, and system information.

The project is intended only for **authorized penetration testing, security research, network performance testing, education, and controlled laboratory environments**.

> ⚠️ **Only test systems and networks that you own or have explicit authorization to test.**

---

## Features

> ⚠️ These capabilities can generate substantial traffic. Define a written scope, approved test window, and conservative resource limits before running a test.

### Traffic Testing

The tool currently supports:

* UDP plain-payload testing
* UDP random-payload testing
* UDP spoof-source testing
* TCP SYN testing
* Multi-threaded TCP SYN testing
* TCP data testing
* Multi-threaded TCP data testing
* HTTP request testing
* Multi-target UDP testing
* **Subnet-based testing (NEW)**

Packet size, target port, duration, and concurrency can be configured through the interactive interface.

---

## Subnet Testing (NEW)

The tool now supports testing entire subnets in a single operation.

### How It Works

1. **Parse CIDR** - Convert `192.168.1.0/24` to a list of all IPs in the range
2. **Scan for Active Hosts** - Check which hosts are responsive on a specified port
3. **Attack All Active Hosts** - Launch concurrent tests against all discovered hosts

### Subnet Attack Configuration

```text
🌐 SUBNET ATTACK CONFIGURATION
================================

Enter CIDR (e.g., 192.168.1.0/24): 192.168.1.0/24
📌 Port to scan/attack (1-65535): 80
⏱️ Attack duration per host (seconds): 30
📦 Packet size (bytes, 1-65500): 1024
🧵 Max concurrent attacks (1-50): 20

⚔️ Attack Method:
1. UDP Plain
2. UDP Random
3. UDP Spoof
4. TCP SYN
5. TCP Data
```

### Subnet Attack Flow

```text
[*] 🌐 Starting subnet attack on 192.168.1.0/24
[*] 📊 CIDR 192.168.1.0/24 contains 254 IPs
[*] 🔍 Scanning 254 hosts on port 80...
[*] ✅ Active host found: 192.168.1.10:80
[*] ✅ Active host found: 192.168.1.20:80
[*] ✅ Active host found: 192.168.1.30:80
[+] ✅ Found 15 active hosts out of 254
[*] 🎯 Starting attack on 15 active hosts
[*] ⚔️ Attacking 192.168.1.10:80
[*] ⚔️ Attacking 192.168.1.20:80
[*] ✅ Completed attack on 192.168.1.10 (1/15)
[+] 🎉 Subnet attack completed! Attacked 15 hosts
```

### Subnet Attack Methods

| Method | Description |
|--------|-------------|
| UDP Plain | Fixed payload testing across subnet |
| UDP Random | Random payload testing across subnet |
| UDP Spoof | Spoofed source IP testing across subnet |
| TCP SYN | SYN connection testing across subnet |
| TCP Data | Data transmission testing across subnet |

### Configuration for Subnet Testing

The following settings can be adjusted in `config.json`:

```json
{
  "max_subnet_threads": 20,
  "scan_timeout": 1000
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `max_subnet_threads` | `20` | Max concurrent subnet attacks |
| `scan_timeout` | `1000` | Host scan timeout in milliseconds |

---

## TCP Testing

### TCP SYN

Two execution modes are available:

* Single-threaded
* Multi-threaded

The multi-threaded implementation uses configurable Go workers for concurrent connection testing.

### TCP Data

TCP data testing supports:

* Configurable payload size
* Persistent TCP connections
* Single-threaded execution
* Multi-threaded execution

The multi-threaded mode creates multiple concurrent workers and maintains statistics for transmitted data.

---

## UDP Testing

### UDP Plain

Generates UDP traffic using a fixed payload.

### UDP Random

Generates UDP traffic with randomly generated payload data.

### UDP Spoof

Generates UDP testing traffic using randomly generated source-address values.

The application provides these methods through the main testing menu and advanced features menu.

---

## HTTP Testing

HTTP testing supports:

* Configurable worker count
* HTTP GET requests
* Proxy-based requests
* Automatic proxy refresh
* Request statistics
* Error tracking

When proxy mode is enabled, workers obtain HTTP clients using the configured proxy pool.

---

## Proxy Management

`ddos-tool` provides several proxy-management options:

```text
1. Auto-load from Proxifly
2. Manual proxy input
3. Load from file
4. Disable proxies
```

Supported proxy types include:

* HTTP
* SOCKS4
* SOCKS5
* Mixed proxy lists

Proxy lists can be loaded from Proxifly's public proxy-list repository.

### Proxy Validation

The application can validate loaded proxies and identify working proxies based on connectivity and response time.

Proxy selection uses a round-robin mechanism when multiple proxies are available.

---

## Multi-Target Testing

The tool supports testing multiple targets in a single operation.

Targets can be entered as comma-separated addresses:

```text
192.168.1.10,192.168.1.20,192.168.1.30
```

The application launches a concurrent worker for each supplied target.

---

## Statistics

The built-in statistics system tracks:

* Packets sent
* Bytes sent
* Errors
* Test duration
* Packets per second

Example:

```text
==================================================
📊 Attack Statistics
Packets Sent: 15234
Bytes Sent: 15974304 (15.24 MB)
Errors: 0
Duration: 30s
Speed: 507.80 packets/second
==================================================
```

Statistics are maintained using synchronized counters and atomic operations where appropriate.

---

## Result Logging

Operational events can be stored in:

```text
attack_results.txt
```

Logged events include:

* Test start
* Test completion
* Proxy loading
* Proxy validation
* Target information
* Packet/request counts
* Subnet scan results
* Active host discovery

Results are timestamped before being added to the internal result log.

---

## Configuration

The application uses:

```text
config.json
```

If the file does not exist, a default configuration is automatically created.

### Default Configuration

```json
{
  "attack_timeout": 60,
  "thread_count": 10,
  "packet_size": 1024,
  "auto_refresh": true,
  "save_logs": true,
  "bypass_firewall": false,
  "max_subnet_threads": 20,
  "scan_timeout": 1000
}
```

### Configuration Options

| Option               | Default | Description                       |
| -------------------- | ------: | --------------------------------- |
| `attack_timeout`     |    `60` | Configured testing timeout        |
| `thread_count`       |    `10` | Number of concurrent workers      |
| `packet_size`        |  `1024` | Default packet size               |
| `auto_refresh`       |  `true` | Automatically refresh proxy lists |
| `save_logs`          |  `true` | Enable result logging             |
| `bypass_firewall`    | `false` | Configuration field               |
| `max_subnet_threads` |    `20` | Max concurrent subnet attacks     |
| `scan_timeout`       |  `1000` | Host scan timeout in milliseconds |

The application currently allows the thread count to be configured between 1 and 100.

---

## Pause & Resume

Running traffic tests can be paused and resumed through the application.

```text
⏸️ Attack paused. Press 'r' to resume.

▶️ Attack resumed.
```

The pause state is shared between testing workers through synchronized access.

---

## Network Diagnostics

The advanced menu includes network diagnostics.

Available diagnostics include:

* `ping`
* `traceroute`

The tool checks whether the relevant system utilities exist before attempting to execute them.

---

## System Information

The system-information feature can collect information such as:

* Operating system/kernel information
* Current user
* Current working directory
* Date/time
* System uptime

The commands are selected according to the host operating system.

---

## Shell Command

The advanced menu includes a shell-command interface.

Commands are executed through the host operating system's shell:

* `cmd /c` on Windows
* `sh -c` on Unix-like systems

> ⚠️ Only execute trusted commands. This feature provides direct command execution with the permissions of the running process.

---

## Interactive CLI

The application provides a menu-driven terminal interface:

```text
📋 Main Menu:

1. 🚀 Start Attack (Single Target)
2. 🌐 Subnet Attack (New!)
3. 🔧 Configure Proxy
4. 📊 View Statistics
5. 💾 Save Results
6. 🛠️ Advanced Features
7. 🧹 Validate Proxies
8. ⚙️ Config Settings
9. 📋 Show Authorization Guidelines
10. 🚪 Exit
```

The traffic-testing menu provides:

```text
=== Attack Configuration ===

1. UDP Flood
2. TCP SYN Flood
3. TCP Data Flood
4. HTTP Flood
5. UDP Spoof Flood
6. Multi-Target Attack
```

These menus are implemented directly in the application source.

---

## Authorization & Ethical Testing

Before entering the main application, the user must confirm authorization:

```text
Do you have proper authorization to test? (yes/no):
```

If authorization is not confirmed, the application exits.

The application also provides built-in ethical testing guidelines covering:

* Written authorization
* Authorized penetration testing
* Internal security assessments
* Educational testing
* Performance testing
* Bug-bounty scope
* Prohibited unauthorized use
* Responsible disclosure

---

## Installation

### Requirements

* Go 1.20 or newer
* Linux, macOS, or Windows
* Network connectivity for HTTP/proxy functionality

This repository currently does not include a `go.mod`; the commands below compile `main.go` directly.

Optional system utilities:

* `ping`
* `traceroute`

---

## Clone

```bash
git clone https://github.com/khalequzzaman17/ddos-tool.git

cd ddos-tool
```

---

## Build

Build the application as:

```bash
go build -o ddos-tool main.go
```

This produces:

```text
ddos-tool
```

---

## Run

Linux/macOS:

```bash
./ddos-tool
```

Or run directly using Go:

```bash
go run main.go
```

---

## Project Structure

```text
ddos-tool/
├── main.go
├── README.md
└── LICENSE
```

The project is currently a single-file Go program. There are no committed dependency, test, CI, or configuration files.

### Runtime Files

The application creates additional files when required:

```text
config.json
attack_results.txt
```

These files are generated locally and are not required to be committed to the repository.

#### `config.json`

Stores the application's runtime configuration, including:

* Thread count
* Packet size
* Proxy auto-refresh
* Result logging
* Attack timeout
* Max subnet threads
* Scan timeout

If `config.json` does not exist, the application automatically creates it with the default configuration.

#### `attack_results.txt`

Stores timestamped testing and operational results when the user chooses to save results.

These runtime files should not be committed to Git. If you run the tool locally, add them to your local `.gitignore`.

---

## Technology

Built with Go and the standard library.

Core packages include:

```text
bufio
crypto/rand
encoding/json
io
net
net/http
net/url
os
os/exec
runtime
strconv
strings
sync
sync/atomic
time
```

The project uses only the Go standard library. Go goroutines, mutexes, wait groups, and atomic counters handle concurrent testing and statistics collection.

---

## Use Cases

`ddos-tool` can be used in controlled environments for:

* Network stress testing
* Security research
* Authorized penetration testing
* Internal infrastructure testing
* Traffic-generation experiments
* Network resilience testing
* Subnet discovery and testing
* Educational demonstrations
* Laboratory research

---

## Recommended Lab Setup

For experimentation, use an isolated environment:

```text
┌──────────────────────┐
│   Test Controller    │
│      ddos-tool       │
└──────────┬───────────┘
           │
       Isolated LAN
           │
           ▼
┌──────────────────────┐
│     Test Target      │
│    VM / Lab Server   │
└──────────────────────┘
```

Use dedicated test infrastructure whenever possible.

---

## Security & Legal Notice

This software can generate substantial network traffic.

You are responsible for ensuring that every test is authorized and within the agreed testing scope.

Do not use this software against:

* Third-party systems without permission
* Public infrastructure without authorization
* Production systems outside an approved testing window
* Networks where traffic generation is prohibited
* Systems belonging to other individuals or organizations without explicit authorization

Unauthorized denial-of-service activity may cause service disruption and may violate applicable laws, contracts, or acceptable-use policies.

**The authorization prompt in the application does not itself grant permission to test a target. You must obtain authorization independently.**

---

## Responsible Disclosure

If an authorized assessment identifies a vulnerability:

1. Document the finding.
2. Preserve relevant evidence.
3. Report the issue to the system owner.
4. Provide reproducible technical details where appropriate.
5. Allow reasonable time for remediation.
6. Avoid public disclosure of sensitive information without authorization.

---

## Contributing

Contributions are welcome for legitimate security research and network-testing purposes.

Useful contributions include:

* Performance improvements
* Better statistics
* Improved configuration handling
* Better error handling
* Cross-platform improvements
* Testing and CI
* Documentation
* Safer laboratory workflows
* Code quality improvements
* Subnet scanning optimizations

### Development

Format the Go source before committing:

```bash
gofmt -w main.go
```

Build and verify:

```bash
go build -o ddos-tool main.go
```

---

## Disclaimer

This software is provided for security research, education, authorized testing, and controlled network-performance testing.

The author does not authorize or encourage unauthorized attacks or disruption of third-party systems.

The user is solely responsible for determining whether their use of this software is lawful and authorized.

The software is provided **"as is"**, without warranties of any kind.

---

## License

This project is distributed under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete terms.

---

## Author

**Khalequzzaman**

GitHub:
https://github.com/khalequzzaman17

Repository:
https://github.com/khalequzzaman17/ddos-tool

---

## ⭐ Support

If you find the project useful for legitimate research or authorized testing:

* ⭐ Star the repository
* 🐛 Report reproducible bugs
* 💡 Suggest improvements
* 🔧 Submit improvements through pull requests

---

> **Use responsibly. Test only with authorization.**
```

---

## 📋 Summary of Updates

| Section | Changes |
|---------|---------|
| **Features** | Added "Subnet-based testing (NEW)" |
| **New Section** | Subnet Testing with complete documentation |
| **Subnet Attack Flow** | Added example output |
| **Subnet Attack Methods** | Added table of methods |
| **Configuration** | Added `max_subnet_threads`, `scan_timeout` |
| **Configuration Options** | Added new rows for subnet settings |
| **Result Logging** | Added subnet scan results, active host discovery |
| **Main Menu** | Updated to show option 2 as Subnet Attack |
| **Use Cases** | Added "Subnet discovery and testing" |
| **Contributing** | Added "Subnet scanning optimizations" |
