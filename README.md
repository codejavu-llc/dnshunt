# dnshunt
⚡ Fast, Concurrent, Multi-Resolver DNS Resolver in Go
A massdns-style DNS resolution tool with cross-resolver verification, smart UDP/TCP handling, and a colorful live progress UI.

# ✨ Why dnshunt?
Most DNS resolvers either give you raw speed (massdns) or pretty output (dig), rarely both. dnshunt is built for bulk DNS reconnaissance and verification with a focus on correctness you can trust:
- 🔁 Cross-resolver verification — every target is queried against multiple resolvers, then the unique answers are merged. Catches DNS spoofing, regional differences, and lying resolvers.
- 🧠 Smart protocol selection — automatically uses TCP for record types prone to oversized responses (TXT, MX, CAA, SOA), so you never silently lose answers to UDP truncation.
- 📊 Real-time progress — live colorful progress bar with remaining-target count, success/failure tally, query rate, and ETA.
- 🪶 Single static binary — no Python, no dependencies on the host, no config files. Build it and ship it.
- 📁 Two output formats — human-readable text reports for quick reading, structured JSON for piping into other tools.

# Install & Usage
```bash
git clone https://github.com/codejavu-inc/dnshunt.git
cd dnshunt
go mod init dnshunt
go mod tidy
go build -o dnshunt
```

```bash
└─[$] ./dnshunt -h                                                                                                                                                                  [14:38:54]

   ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
   ██╔══██╗████╗  ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
   ██║  ██║██╔██╗ ██║███████╗███████║██║   ██║██╔██╗ ██║   ██║   
   ██║  ██║██║╚██╗██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   
   ██████╔╝██║ ╚████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   
   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   
         ⚡ Fast Concurrent DNS Resolver ⚡
              Made with ♥ by CodejaVu Team
   ─────────────────────────────────────────────────────

USAGE:
  dnshunt [options]

OPTIONS:
  -r         <file>     File containing DNS resolver IPs (one per line)
  -R         <list>     Single or multiple resolver IPs (e.g. 1.1.1.1,8.8.8.8)
  -l         <file>     Target list (subdomains/domains/IPs/hostnames)
  -t         <type>     DNS record type: A, AAAA, CNAME, TXT, MX, PTR, CAA, NS, SOA
  -c         <int>      Concurrency level (default: 100)
  -timeout   <ms>       Query timeout in milliseconds (default: 3000)
  -rc        <int>      Number of resolvers per target (default: 5)
  -tcp                  Use TCP instead of UDP for queries
  -v                    Verbose output
  -o         <file>     Output file (auto-detects .json or .txt)
  -h                    Show this help message

EXAMPLES:
  # Basic A record resolution
  dnshunt -l domains.txt -R 1.1.1.1,8.8.8.8 -t A

  # Use a resolver file with high concurrency
  dnshunt -l targets.txt -r resolvers.txt -t TXT -c 500 -o results.json

  # TCP queries with 7 resolvers per target
  dnshunt -l hosts.txt -R 8.8.8.8 -t MX -tcp -rc 7 -v

────────────────────────────────────────────────────────────
              Made by CodejaVu Team

```
