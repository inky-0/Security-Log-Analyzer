# Security Log Analyzer

A mini-SIEM tool that parses security logs and detects threats.

## Features

- Parses Apache, Nginx, SSH, Windows Event, syslog, and firewall logs
- Detects SQL injection, XSS, path traversal, and command injection
- Identifies brute force attacks and port scans
- Flags known malicious IPs
- Generates JSON, CSV, and HTML reports

## Installation

```bash
git clone https://github.com/yourusername/Security-Log-Analyzer.git
cd Security-Log-Analyzer
```

No dependencies required.

## Usage

```bash
# Run demo with sample attack data
python main.py --demo

# Analyze a log file
python main.py -f /var/log/auth.log

# Analyze directory of logs
python main.py -d /var/log/

# Generate reports
python main.py -f access.log -o report.json
python main.py -f access.log --html report.html
```

## Sample Output

```
============================================================
  ANALYSIS SUMMARY
============================================================
  Lines Processed:    26
  Security Events:    35
  Critical Events:    6
  High Severity:      7
============================================================

🔴 [CRITICAL] sql_injection
   Source: 10.0.0.50
   SQL injection attempt detected

🟠 [HIGH] path_traversal
   Source: 203.0.113.100
   Path traversal attempt: /../../../etc/passwd
```

## License

MIT