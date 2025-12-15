import sys
import os
import argparse
import tempfile
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from helper import (
    LogParser,
    AttackPatternDatabase,
    IPReputationDatabase,
    BehaviorAnalyzer,
    ReportGenerator,
    SecurityEvent,
    EventType,
    ThreatLevel,
    ThreatIntelligence
)


class SecurityLogAnalyzer:
    
    def __init__(self):
        self.log_parser = LogParser()
        self.attack_patterns = AttackPatternDatabase()
        self.ip_reputation = IPReputationDatabase()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.events: List[SecurityEvent] = []
        self.parsed_logs: List[dict] = []
        self.stats = {
            "lines_processed": 0,
            "lines_parsed": 0,
            "lines_failed": 0,
            "events_generated": 0
        }
    
    def load_log_file(self, filepath: str) -> int:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        lines_loaded = 0
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                self.stats["lines_processed"] += 1
                parsed = self.log_parser.parse_line(line)
                
                if parsed and parsed.get("log_type") != "unknown":
                    self.parsed_logs.append(parsed)
                    self.stats["lines_parsed"] += 1
                    lines_loaded += 1
                else:
                    self.stats["lines_failed"] += 1
        
        return lines_loaded
    
    def load_log_directory(self, dirpath: str, extensions: List[str] = None) -> int:
        if extensions is None:
            extensions = ['.log', '.txt', '.json']
        
        total_loaded = 0
        
        for root, dirs, files in os.walk(dirpath):
            for filename in files:
                if any(filename.endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, filename)
                    try:
                        loaded = self.load_log_file(filepath)
                        total_loaded += loaded
                        print(f"  Loaded {loaded} entries from {filename}")
                    except Exception as e:
                        print(f"  Error loading {filename}: {e}")
        
        return total_loaded
    
    def analyze_parsed_log(self, log_entry: dict) -> List[SecurityEvent]:
        events = []
        
        source_ip = log_entry.get("source_ip")
        timestamp = log_entry.get("timestamp", datetime.now())
        raw_log = log_entry.get("raw_log", "")
        username = log_entry.get("username")
        path = log_entry.get("path", "")
        user_agent = log_entry.get("user_agent", "")
        method = log_entry.get("method")
        status = log_entry.get("status")
        log_type = log_entry.get("log_type")
        
        if source_ip:
            self.behavior_analyzer.record_request(
                source_ip, timestamp, path,
                log_entry.get("destination_port")
            )
            
            reputation = self.ip_reputation.check_ip_reputation(source_ip)
            if reputation.is_malicious:
                events.append(SecurityEvent(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    event_type=EventType.ANOMALOUS_BEHAVIOR,
                    threat_level=ThreatLevel.HIGH,
                    description=f"Request from known malicious IP: {', '.join(reputation.threat_types)}",
                    raw_log=raw_log,
                    username=username,
                    request_path=path,
                    additional_data={"reputation": reputation.threat_types}
                ))
        
        if log_type in ["sshd", "auth_log"]:
            events.extend(self._analyze_auth_log(log_entry, timestamp, raw_log))
        
        if log_type in ["apache_combined", "apache_common", "nginx", "json"]:
            events.extend(self._analyze_web_log(log_entry, timestamp, raw_log))
        
        if log_type == "firewall":
            events.extend(self._analyze_firewall_log(log_entry, timestamp, raw_log))
        
        if log_type == "windows_event":
            events.extend(self._analyze_windows_log(log_entry, timestamp, raw_log))
        
        return events
    
    def _analyze_auth_log(self, log_entry: dict, timestamp: datetime, 
                          raw_log: str) -> List[SecurityEvent]:
        events = []
        action = log_entry.get("action", "").lower()
        message = log_entry.get("message", "").lower()
        source_ip = log_entry.get("source_ip")
        username = log_entry.get("username")
        
        is_failure = any(word in action or word in message 
                        for word in ["failed", "invalid", "error", "denied", "rejected"])
        is_success = any(word in action or word in message 
                        for word in ["accepted", "success", "opened", "authenticated"])
        
        if username and source_ip:
            self.behavior_analyzer.record_login_attempt(
                username, timestamp, source_ip, is_success
            )
        
        if is_failure:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.AUTHENTICATION_FAILURE,
                threat_level=ThreatLevel.LOW,
                description=f"Authentication failure for user '{username}' from {source_ip}",
                raw_log=raw_log,
                username=username
            ))
        
        if "root" in str(username).lower() and is_failure:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.PRIVILEGE_ESCALATION,
                threat_level=ThreatLevel.HIGH,
                description=f"Failed root login attempt from {source_ip}",
                raw_log=raw_log,
                username=username
            ))
        
        suspicious_users = ["admin", "administrator", "test", "guest", "user", "oracle", "postgres", "mysql"]
        if username and username.lower() in suspicious_users and is_failure:
            events[-1].threat_level = ThreatLevel.MEDIUM
            events[-1].description += " (common username targeted)"
        
        return events
    
    def _analyze_web_log(self, log_entry: dict, timestamp: datetime,
                         raw_log: str) -> List[SecurityEvent]:
        events = []
        source_ip = log_entry.get("source_ip")
        path = log_entry.get("path", "")
        user_agent = log_entry.get("user_agent", "")
        method = log_entry.get("method", "")
        status = log_entry.get("status")
        
        full_request = f"{method} {path}"
        
        is_sqli, sqli_patterns = self.attack_patterns.check_sql_injection(path)
        if is_sqli:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.SQL_INJECTION,
                threat_level=ThreatLevel.CRITICAL,
                description=f"SQL injection attempt detected in request path",
                raw_log=raw_log,
                request_path=path,
                http_method=method,
                http_status=status,
                user_agent=user_agent,
                additional_data={"matched_patterns": sqli_patterns[:3]}
            ))
        
        is_xss, xss_patterns = self.attack_patterns.check_xss(path)
        if is_xss:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.XSS_ATTEMPT,
                threat_level=ThreatLevel.HIGH,
                description=f"Cross-site scripting attempt detected",
                raw_log=raw_log,
                request_path=path,
                http_method=method,
                http_status=status,
                user_agent=user_agent,
                additional_data={"matched_patterns": xss_patterns[:3]}
            ))
        
        is_traversal, traversal_patterns = self.attack_patterns.check_path_traversal(path)
        if is_traversal:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.PATH_TRAVERSAL,
                threat_level=ThreatLevel.HIGH,
                description=f"Path traversal attempt detected: {path[:100]}",
                raw_log=raw_log,
                request_path=path,
                http_method=method,
                http_status=status,
                user_agent=user_agent,
                additional_data={"matched_patterns": traversal_patterns[:3]}
            ))
        
        is_cmdi, cmdi_patterns = self.attack_patterns.check_command_injection(path)
        if is_cmdi:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.COMMAND_INJECTION,
                threat_level=ThreatLevel.CRITICAL,
                description=f"Command injection attempt detected",
                raw_log=raw_log,
                request_path=path,
                http_method=method,
                http_status=status,
                user_agent=user_agent,
                additional_data={"matched_patterns": cmdi_patterns[:3]}
            ))
        
        is_sensitive, sensitive_patterns = self.attack_patterns.check_sensitive_file_access(path)
        if is_sensitive:
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=EventType.SENSITIVE_FILE_ACCESS,
                threat_level=ThreatLevel.MEDIUM,
                description=f"Attempt to access sensitive file: {path[:100]}",
                raw_log=raw_log,
                request_path=path,
                http_method=method,
                http_status=status,
                user_agent=user_agent
            ))
        
        if user_agent:
            is_malicious_ua, ua_patterns = self.attack_patterns.check_malicious_user_agent(user_agent)
            if is_malicious_ua:
                events.append(SecurityEvent(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    event_type=EventType.SUSPICIOUS_USER_AGENT,
                    threat_level=ThreatLevel.MEDIUM,
                    description=f"Suspicious user agent detected: {user_agent[:100]}",
                    raw_log=raw_log,
                    request_path=path,
                    http_method=method,
                    http_status=status,
                    user_agent=user_agent,
                    additional_data={"matched_tools": ua_patterns}
                ))
        
        if status and status >= 400:
            threat_level = ThreatLevel.INFO
            if status == 401 or status == 403:
                threat_level = ThreatLevel.LOW
            elif status >= 500:
                threat_level = ThreatLevel.LOW
            
            if not events:
                events.append(SecurityEvent(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    event_type=EventType.UNKNOWN,
                    threat_level=threat_level,
                    description=f"HTTP {status} response for {method} {path[:50]}",
                    raw_log=raw_log,
                    request_path=path,
                    http_method=method,
                    http_status=status,
                    user_agent=user_agent
                ))
        
        return events
    
    def _analyze_firewall_log(self, log_entry: dict, timestamp: datetime,
                              raw_log: str) -> List[SecurityEvent]:
        events = []
        action = log_entry.get("action", "")
        source_ip = log_entry.get("source_ip")
        dest_ip = log_entry.get("destination_ip")
        dest_port = log_entry.get("destination_port")
        protocol = log_entry.get("protocol")
        
        if action == "DROP" or action == "REJECT":
            threat_level = ThreatLevel.INFO
            
            high_risk_ports = [22, 23, 3389, 445, 139, 1433, 3306, 5432, 27017]
            if dest_port in high_risk_ports:
                threat_level = ThreatLevel.LOW
            
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=dest_ip,
                destination_port=dest_port,
                event_type=EventType.UNKNOWN,
                threat_level=threat_level,
                description=f"Firewall {action}: {protocol} from {source_ip} to {dest_ip}:{dest_port}",
                raw_log=raw_log,
                additional_data={"protocol": protocol, "action": action}
            ))
        
        return events
    
    def _analyze_windows_log(self, log_entry: dict, timestamp: datetime,
                             raw_log: str) -> List[SecurityEvent]:
        events = []
        event_id = log_entry.get("event_id")
        level = log_entry.get("level", "")
        message = log_entry.get("message", "")
        source_ip = log_entry.get("source_ip")
        username = log_entry.get("username")
        
        security_event_ids = {
            4625: (EventType.AUTHENTICATION_FAILURE, ThreatLevel.LOW, "Failed login attempt"),
            4624: (EventType.AUTHENTICATION_SUCCESS, ThreatLevel.INFO, "Successful login"),
            4648: (EventType.AUTHENTICATION_SUCCESS, ThreatLevel.LOW, "Explicit credential login"),
            4672: (EventType.PRIVILEGE_ESCALATION, ThreatLevel.MEDIUM, "Special privileges assigned"),
            4720: (EventType.CONFIGURATION_CHANGE, ThreatLevel.MEDIUM, "User account created"),
            4722: (EventType.CONFIGURATION_CHANGE, ThreatLevel.LOW, "User account enabled"),
            4723: (EventType.CONFIGURATION_CHANGE, ThreatLevel.LOW, "Password change attempt"),
            4724: (EventType.CONFIGURATION_CHANGE, ThreatLevel.MEDIUM, "Password reset attempt"),
            4725: (EventType.CONFIGURATION_CHANGE, ThreatLevel.LOW, "User account disabled"),
            4726: (EventType.CONFIGURATION_CHANGE, ThreatLevel.MEDIUM, "User account deleted"),
            4728: (EventType.CONFIGURATION_CHANGE, ThreatLevel.HIGH, "Member added to security group"),
            4732: (EventType.CONFIGURATION_CHANGE, ThreatLevel.HIGH, "Member added to local group"),
            4756: (EventType.CONFIGURATION_CHANGE, ThreatLevel.HIGH, "Member added to universal group"),
            4768: (EventType.AUTHENTICATION_SUCCESS, ThreatLevel.INFO, "Kerberos TGT requested"),
            4769: (EventType.AUTHENTICATION_SUCCESS, ThreatLevel.INFO, "Kerberos service ticket requested"),
            4771: (EventType.AUTHENTICATION_FAILURE, ThreatLevel.LOW, "Kerberos pre-auth failed"),
            4776: (EventType.AUTHENTICATION_FAILURE, ThreatLevel.LOW, "Credential validation attempt"),
            7045: (EventType.CONFIGURATION_CHANGE, ThreatLevel.HIGH, "New service installed"),
        }
        
        if event_id in security_event_ids:
            event_type, threat_level, description = security_event_ids[event_id]
            events.append(SecurityEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                event_type=event_type,
                threat_level=threat_level,
                description=f"{description} (Event ID: {event_id})",
                raw_log=raw_log,
                username=username,
                additional_data={"event_id": event_id, "level": level}
            ))
        
        return events
    
    def run_analysis(self) -> None:
        print(f"\nAnalyzing {len(self.parsed_logs)} log entries...")
        
        for log_entry in self.parsed_logs:
            detected_events = self.analyze_parsed_log(log_entry)
            self.events.extend(detected_events)
            self.stats["events_generated"] += len(detected_events)
        
        print(f"Generated {self.stats['events_generated']} security events")
    
    def run_behavioral_analysis(self) -> dict:
        print("\nRunning behavioral analysis...")
        
        brute_force = self.behavior_analyzer.detect_brute_force()
        port_scans = self.behavior_analyzer.detect_port_scan()
        dos_attempts = self.behavior_analyzer.detect_dos_attack()
        enumeration = self.behavior_analyzer.detect_enumeration()
        
        for bf in brute_force:
            self.events.append(SecurityEvent(
                timestamp=bf["start_time"],
                source_ip=bf["source_ips"][0] if bf["source_ips"] else None,
                event_type=EventType.BRUTE_FORCE_ATTEMPT,
                threat_level=ThreatLevel.CRITICAL,
                description=f"Brute force attack detected: {bf['attempt_count']} attempts against user '{bf['username']}'",
                raw_log="",
                username=bf["username"],
                additional_data=bf
            ))
        
        for ps in port_scans:
            self.events.append(SecurityEvent(
                timestamp=datetime.now(),
                source_ip=ps["source_ip"],
                event_type=EventType.PORT_SCAN,
                threat_level=ThreatLevel.HIGH,
                description=f"Port scan detected: {ps['ports_scanned']} ports ({ps['scan_type']})",
                raw_log="",
                additional_data=ps
            ))
        
        for dos in dos_attempts:
            self.events.append(SecurityEvent(
                timestamp=dos["start_time"],
                source_ip=dos["source_ip"],
                event_type=EventType.DENIAL_OF_SERVICE,
                threat_level=ThreatLevel.CRITICAL,
                description=f"Potential DoS attack: {dos['requests_per_minute']} requests/min",
                raw_log="",
                additional_data=dos
            ))
        
        return {
            "brute_force": brute_force,
            "port_scans": port_scans,
            "dos_attempts": dos_attempts,
            "enumeration": enumeration
        }
    
    def generate_report(self, behavioral_results: dict) -> str:
        report = ReportGenerator.generate_summary(
            self.events,
            behavioral_results.get("brute_force", []),
            behavioral_results.get("port_scans", []),
            behavioral_results.get("dos_attempts", []),
            behavioral_results.get("enumeration", [])
        )
        
        return ReportGenerator.to_json(report)
    
    def generate_html_report(self, behavioral_results: dict) -> str:
        report = ReportGenerator.generate_summary(
            self.events,
            behavioral_results.get("brute_force", []),
            behavioral_results.get("port_scans", []),
            behavioral_results.get("dos_attempts", []),
            behavioral_results.get("enumeration", [])
        )
        
        return ReportGenerator.generate_html_report(report)
    
    def export_events_csv(self) -> str:
        return ReportGenerator.to_csv(self.events)
    
    def get_statistics(self) -> dict:
        return {
            **self.stats,
            "total_events": len(self.events),
            "critical_events": sum(1 for e in self.events if e.threat_level == ThreatLevel.CRITICAL),
            "high_events": sum(1 for e in self.events if e.threat_level == ThreatLevel.HIGH),
            "unique_ips": len(set(e.source_ip for e in self.events if e.source_ip)),
            "unique_users": len(set(e.username for e in self.events if e.username))
        }


def create_sample_logs() -> str:
    sample_logs = """192.168.1.100 - - [15/Dec/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
192.168.1.101 - - [15/Dec/2025:10:15:24 +0000] "GET /admin/config.php HTTP/1.1" 403 567 "-" "Mozilla/5.0"
10.0.0.50 - - [15/Dec/2025:10:15:25 +0000] "GET /search?q=1' OR '1'='1 HTTP/1.1" 200 890 "-" "Mozilla/5.0"
10.0.0.50 - - [15/Dec/2025:10:15:26 +0000] "GET /page?id=1; DROP TABLE users-- HTTP/1.1" 500 123 "-" "sqlmap/1.5"
203.0.113.100 - - [15/Dec/2025:10:15:27 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 234 "-" "curl/7.68.0"
203.0.113.100 - - [15/Dec/2025:10:15:28 +0000] "GET /api?cmd=;cat /etc/shadow HTTP/1.1" 403 345 "-" "nikto/2.1.6"
192.168.1.102 - - [15/Dec/2025:10:15:29 +0000] "POST /login HTTP/1.1" 401 456 "-" "Mozilla/5.0"
192.168.1.102 - - [15/Dec/2025:10:15:30 +0000] "GET /search?q=<script>alert('xss')</script> HTTP/1.1" 200 567 "-" "Mozilla/5.0"
45.33.32.156 - - [15/Dec/2025:10:15:31 +0000] "GET /.git/config HTTP/1.1" 404 678 "-" "dirbuster/1.0"
45.33.32.156 - - [15/Dec/2025:10:15:32 +0000] "GET /.env HTTP/1.1" 404 789 "-" "gobuster/3.1"
Dec 15 10:16:01 server1 sshd[12345]: Failed password for root from 192.168.1.200 port 22 ssh2
Dec 15 10:16:02 server1 sshd[12346]: Failed password for root from 192.168.1.200 port 22 ssh2
Dec 15 10:16:03 server1 sshd[12347]: Failed password for root from 192.168.1.200 port 22 ssh2
Dec 15 10:16:04 server1 sshd[12348]: Failed password for root from 192.168.1.200 port 22 ssh2
Dec 15 10:16:05 server1 sshd[12349]: Failed password for root from 192.168.1.200 port 22 ssh2
Dec 15 10:16:06 server1 sshd[12350]: Failed password for admin from 192.168.1.200 port 22 ssh2
Dec 15 10:16:07 server1 sshd[12351]: Invalid user test from 192.168.1.201 port 22
Dec 15 10:16:08 server1 sshd[12352]: Accepted password for ubuntu from 192.168.1.50 port 22 ssh2
2025-12-15 10:17:00 WARNING 4625 Security Failed login for user administrator from 10.0.0.100
2025-12-15 10:17:01 WARNING 4625 Security Failed login for user administrator from 10.0.0.100
2025-12-15 10:17:02 WARNING 4625 Security Failed login for user administrator from 10.0.0.100
2025-12-15 10:17:03 INFO 4624 Security Successful login for user admin from 10.0.0.50
2025-12-15 10:17:04 WARNING 4672 Security Special privileges assigned to admin
2025-12-15 10:17:05 WARNING 7045 Security New service installed: suspicious_service
{"timestamp": "2025-12-15T10:18:00Z", "source_ip": "172.16.0.100", "method": "GET", "path": "/api/users?id=1 UNION SELECT * FROM passwords", "status": 200, "user_agent": "Python-urllib/3.9"}
{"timestamp": "2025-12-15T10:18:01Z", "source_ip": "172.16.0.100", "method": "POST", "path": "/api/exec", "status": 500, "user_agent": "Python-urllib/3.9", "message": "Command injection attempt"}
"""
    return sample_logs


def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - SIEM-lite tool for detecting threats in log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f /var/log/auth.log
  python main.py -d /var/log/ -o report.json
  python main.py --demo
  python main.py -f access.log --html report.html --csv events.csv
        """
    )
    
    parser.add_argument("-f", "--file", help="Path to log file to analyze")
    parser.add_argument("-d", "--directory", help="Path to directory containing log files")
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("--html", help="Output file for HTML report")
    parser.add_argument("--csv", help="Output file for CSV events export")
    parser.add_argument("--demo", action="store_true", help="Run with sample log data for demonstration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if not any([args.file, args.directory, args.demo]):
        parser.print_help()
        print("\nError: Please specify a log file (-f), directory (-d), or use --demo mode")
        sys.exit(1)
    
    analyzer = SecurityLogAnalyzer()
    
    print("=" * 60)
    print("  SECURITY LOG ANALYZER")
    print("  Mini-SIEM Threat Detection Tool")
    print("=" * 60)
    
    if args.demo:
        print("\n[DEMO MODE] Using sample log data...")
        sample_data = create_sample_logs()
        
        temp_fd, temp_file = tempfile.mkstemp(suffix='.txt', prefix='sample_logs_')
        try:
            with os.fdopen(temp_fd, 'w') as f:
                f.write(sample_data)
            analyzer.load_log_file(temp_file)
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    elif args.file:
        print(f"\nLoading log file: {args.file}")
        try:
            loaded = analyzer.load_log_file(args.file)
            print(f"  Loaded {loaded} log entries")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif args.directory:
        print(f"\nLoading logs from directory: {args.directory}")
        loaded = analyzer.load_log_directory(args.directory)
        print(f"  Total: {loaded} log entries loaded")
    
    analyzer.run_analysis()
    behavioral_results = analyzer.run_behavioral_analysis()
    
    stats = analyzer.get_statistics()
    print("\n" + "=" * 60)
    print("  ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"  Lines Processed:    {stats['lines_processed']}")
    print(f"  Lines Parsed:       {stats['lines_parsed']}")
    print(f"  Security Events:    {stats['total_events']}")
    print(f"  Critical Events:    {stats['critical_events']}")
    print(f"  High Severity:      {stats['high_events']}")
    print(f"  Unique Source IPs:  {stats['unique_ips']}")
    print(f"  Unique Users:       {stats['unique_users']}")
    print("=" * 60)
    
    if args.output:
        report_json = analyzer.generate_report(behavioral_results)
        with open(args.output, 'w') as f:
            f.write(report_json)
        print(f"\nJSON report saved to: {args.output}")
    
    if args.html:
        report_html = analyzer.generate_html_report(behavioral_results)
        with open(args.html, 'w') as f:
            f.write(report_html)
        print(f"HTML report saved to: {args.html}")
    
    if args.csv:
        events_csv = analyzer.export_events_csv()
        with open(args.csv, 'w') as f:
            f.write(events_csv)
        print(f"CSV events exported to: {args.csv}")
    
    if not any([args.output, args.html, args.csv]):
        print("\n" + "-" * 60)
        print("  TOP FINDINGS")
        print("-" * 60)
        
        critical_events = [e for e in analyzer.events 
                         if e.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]
        critical_events.sort(key=lambda x: x.threat_level.value, reverse=True)
        
        if critical_events:
            for event in critical_events[:10]:
                level_indicator = "🔴" if event.threat_level == ThreatLevel.CRITICAL else "🟠"
                print(f"\n{level_indicator} [{event.threat_level.name}] {event.event_type.value}")
                print(f"   Source: {event.source_ip or 'N/A'}")
                print(f"   Time: {event.timestamp}")
                print(f"   {event.description[:80]}")
        else:
            print("\n  ✅ No critical or high severity events detected")
        
        if behavioral_results.get("brute_force"):
            print(f"\n⚠️  {len(behavioral_results['brute_force'])} brute force attack(s) detected!")
        
        if behavioral_results.get("port_scans"):
            print(f"⚠️  {len(behavioral_results['port_scans'])} port scanning attempt(s) detected!")
        
        print("\n" + "=" * 60)
        print("  Use -o, --html, or --csv to export detailed reports")
        print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())