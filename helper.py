import re
import json
import hashlib
import ipaddress
import math
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from enum import Enum
import csv
import io


class ThreatLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class EventType(Enum):
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHENTICATION_SUCCESS = "authentication_success"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    PORT_SCAN = "port_scan"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MALWARE_SIGNATURE = "malware_signature"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    SENSITIVE_FILE_ACCESS = "sensitive_file_access"
    CONFIGURATION_CHANGE = "configuration_change"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    UNKNOWN = "unknown"


@dataclass
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    event_type: EventType
    threat_level: ThreatLevel
    description: str
    raw_log: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    user_agent: Optional[str] = None
    request_path: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "event_type": self.event_type.value,
            "threat_level": self.threat_level.name,
            "threat_score": self.threat_level.value,
            "description": self.description,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "username": self.username,
            "user_agent": self.user_agent,
            "request_path": self.request_path,
            "http_method": self.http_method,
            "http_status": self.http_status,
            "additional_data": self.additional_data,
            "raw_log": self.raw_log
        }


@dataclass
class ThreatIntelligence:
    ip_address: str
    is_malicious: bool
    threat_types: List[str]
    confidence_score: float
    last_seen: Optional[datetime] = None
    source: str = "internal"


@dataclass
class AnalysisReport:
    start_time: datetime
    end_time: datetime
    total_events: int
    events_by_type: Dict[str, int]
    events_by_threat_level: Dict[str, int]
    top_source_ips: List[Tuple[str, int]]
    top_targeted_users: List[Tuple[str, int]]
    critical_events: List[SecurityEvent]
    brute_force_attempts: List[Dict]
    potential_port_scans: List[Dict]
    web_attacks: List[SecurityEvent]
    anomalies: List[Dict]
    recommendations: List[str]


class IPReputationDatabase:
    
    KNOWN_MALICIOUS_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]
    
    KNOWN_TOR_EXIT_NODES = [
        "185.220.100.0/24",
        "185.220.101.0/24",
        "185.220.102.0/24",
        "193.218.118.0/24",
        "195.176.3.0/24",
    ]
    
    KNOWN_THREAT_IPS = {
        "203.0.113.100": {"types": ["botnet", "spam"], "confidence": 0.95},
        "198.51.100.50": {"types": ["scanner", "bruteforce"], "confidence": 0.90},
        "192.0.2.200": {"types": ["malware_c2"], "confidence": 0.85},
        "45.33.32.156": {"types": ["scanner"], "confidence": 0.70},
        "185.220.101.1": {"types": ["tor_exit", "anonymizer"], "confidence": 0.99},
    }
    
    HIGH_RISK_COUNTRIES = {
        "RU": 0.3, "CN": 0.3, "KP": 0.5, "IR": 0.4,
        "NG": 0.25, "RO": 0.2, "UA": 0.2, "BY": 0.3
    }
    
    def __init__(self):
        self.custom_blocklist: Set[str] = set()
        self.custom_allowlist: Set[str] = set()
        self.ip_history: Dict[str, List[datetime]] = defaultdict(list)
    
    def check_ip_reputation(self, ip: str) -> ThreatIntelligence:
        if ip in self.custom_allowlist:
            return ThreatIntelligence(
                ip_address=ip,
                is_malicious=False,
                threat_types=[],
                confidence_score=0.0,
                source="allowlist"
            )
        
        if ip in self.custom_blocklist:
            return ThreatIntelligence(
                ip_address=ip,
                is_malicious=True,
                threat_types=["blocklisted"],
                confidence_score=1.0,
                source="blocklist"
            )
        
        if ip in self.KNOWN_THREAT_IPS:
            threat_info = self.KNOWN_THREAT_IPS[ip]
            return ThreatIntelligence(
                ip_address=ip,
                is_malicious=True,
                threat_types=threat_info["types"],
                confidence_score=threat_info["confidence"],
                source="threat_intel"
            )
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for tor_range in self.KNOWN_TOR_EXIT_NODES:
                if ip_obj in ipaddress.ip_network(tor_range, strict=False):
                    return ThreatIntelligence(
                        ip_address=ip,
                        is_malicious=True,
                        threat_types=["tor_exit_node"],
                        confidence_score=0.8,
                        source="tor_detection"
                    )
        except ValueError:
            pass
        
        return ThreatIntelligence(
            ip_address=ip,
            is_malicious=False,
            threat_types=[],
            confidence_score=0.0,
            source="not_found"
        )
    
    def add_to_blocklist(self, ip: str):
        self.custom_blocklist.add(ip)
    
    def add_to_allowlist(self, ip: str):
        self.custom_allowlist.add(ip)
    
    def record_ip_activity(self, ip: str, timestamp: datetime):
        self.ip_history[ip].append(timestamp)


class AttackPatternDatabase:
    
    SQL_INJECTION_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"union(.*)select",
        r"select(.*)from",
        r"insert(.*)into",
        r"drop(.*)table",
        r"delete(.*)from",
        r"update(.*)set",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION\s+SELECT",
        r"OR\s+1\s*=\s*1",
        r"OR\s+'1'\s*=\s*'1'",
        r";\s*DROP\s+TABLE",
        r"1'\s*OR\s*'1'\s*=\s*'1",
        r"admin'\s*--",
        r"' OR ''='",
        r"1 OR 1=1",
        r"' OR 'x'='x",
        r"WAITFOR\s+DELAY",
        r"BENCHMARK\s*\(",
        r"SLEEP\s*\(",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"vbscript:",
        r"onload\s*=",
        r"onerror\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"onfocus\s*=",
        r"onblur\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<svg[^>]*onload",
        r"<img[^>]*onerror",
        r"expression\s*\(",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
        r"document\.cookie",
        r"document\.write",
        r"\.innerHTML",
        r"eval\s*\(",
        r"fromCharCode",
        r"&#x[0-9a-fA-F]+;",
        r"&#[0-9]+;",
        r"%3Cscript",
        r"\x3cscript",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"%2e%2e%5c",
        r"\.\.%5c",
        r"%252e%252e%252f",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts",
        r"c:\\windows",
        r"c:/windows",
        r"/proc/self",
        r"/var/log",
        r"boot\.ini",
        r"win\.ini",
        r"system32",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r";\s*ls",
        r";\s*cat",
        r";\s*rm",
        r";\s*wget",
        r";\s*curl",
        r";\s*nc\s",
        r";\s*netcat",
        r"\|\s*ls",
        r"\|\s*cat",
        r"\|\s*bash",
        r"\|\s*sh\s",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"&&\s*\w+",
        r"\|\|\s*\w+",
        r"/bin/bash",
        r"/bin/sh",
        r"cmd\.exe",
        r"powershell",
        r"whoami",
        r"id\s*;",
        r"uname\s+-a",
        r"ping\s+-c",
        r"nslookup",
        r"dig\s+",
    ]
    
    SENSITIVE_FILES = [
        r"\.htaccess",
        r"\.htpasswd",
        r"\.git/",
        r"\.svn/",
        r"\.env",
        r"config\.php",
        r"config\.yml",
        r"database\.yml",
        r"settings\.py",
        r"wp-config\.php",
        r"\.aws/credentials",
        r"id_rsa",
        r"id_dsa",
        r"\.ssh/",
        r"\.bash_history",
        r"\.mysql_history",
        r"phpinfo",
        r"server-status",
        r"web\.config",
        r"applicationHost\.config",
    ]
    
    MALICIOUS_USER_AGENTS = [
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"masscan",
        r"dirbuster",
        r"gobuster",
        r"wfuzz",
        r"hydra",
        r"burpsuite",
        r"nessus",
        r"openvas",
        r"acunetix",
        r"w3af",
        r"havij",
        r"pangolin",
        r"python-requests",
        r"curl/",
        r"wget/",
        r"libwww-perl",
        r"java/",
        r"zmeu",
        r"morfeus",
        r"zollard",
        r"masscan",
    ]
    
    def __init__(self):
        self.compiled_sql = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self.compiled_xss = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.compiled_traversal = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self.compiled_cmdi = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self.compiled_sensitive = [re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_FILES]
        self.compiled_ua = [re.compile(p, re.IGNORECASE) for p in self.MALICIOUS_USER_AGENTS]
    
    def check_sql_injection(self, text: str) -> Tuple[bool, List[str]]:
        matches = []
        for pattern in self.compiled_sql:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return len(matches) > 0, matches
    
    def check_xss(self, text: str) -> Tuple[bool, List[str]]:
        matches = []
        for pattern in self.compiled_xss:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return len(matches) > 0, matches
    
    def check_path_traversal(self, text: str) -> Tuple[bool, List[str]]:
        matches = []
        for pattern in self.compiled_traversal:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return len(matches) > 0, matches
    
    def check_command_injection(self, text: str) -> Tuple[bool, List[str]]:
        matches = []
        for pattern in self.compiled_cmdi:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return len(matches) > 0, matches
    
    def check_sensitive_file_access(self, path: str) -> Tuple[bool, List[str]]:
        matches = []
        for pattern in self.compiled_sensitive:
            if pattern.search(path):
                matches.append(pattern.pattern)
        return len(matches) > 0, matches
    
    def check_malicious_user_agent(self, user_agent: str) -> Tuple[bool, List[str]]:
        matches = []
        for pattern in self.compiled_ua:
            if pattern.search(user_agent):
                matches.append(pattern.pattern)
        return len(matches) > 0, matches


class LogParser:
    
    APACHE_COMBINED_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )
    
    APACHE_COMMON_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\S+)'
    )
    
    NGINX_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )
    
    SSHD_PATTERN = re.compile(
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
        r'(?P<action>Failed|Accepted|Invalid|Disconnected|Connection closed)'
        r'.*?(?:from\s+(?P<ip>\d+\.\d+\.\d+\.\d+))?'
        r'(?:.*?user\s+(?P<user>\S+))?'
        r'(?:.*?port\s+(?P<port>\d+))?'
    )
    
    AUTH_LOG_PATTERN = re.compile(
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<service>\S+?)(?:\[\d+\])?:\s+'
        r'(?P<message>.+)$'
    )
    
    WINDOWS_EVENT_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<level>\S+)\s+'
        r'(?P<event_id>\d+)\s+'
        r'(?P<source>\S+)\s+'
        r'(?P<message>.+)$'
    )
    
    FIREWALL_PATTERN = re.compile(
        r'^(?P<timestamp>[^\s]+)\s+'
        r'(?P<action>ACCEPT|DROP|REJECT)\s+'
        r'(?P<protocol>\S+)\s+'
        r'SRC=(?P<src_ip>\S+)\s+'
        r'DST=(?P<dst_ip>\S+)\s+'
        r'.*?SPT=(?P<src_port>\d+)\s+'
        r'.*?DPT=(?P<dst_port>\d+)'
    )
    
    SYSLOG_PATTERN = re.compile(
        r'^<(?P<priority>\d+)>'
        r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<tag>\S+?)(?:\[\d+\])?:\s+'
        r'(?P<message>.+)$'
    )
    
    JSON_LOG_KEYS = {
        "timestamp": ["timestamp", "time", "@timestamp", "datetime", "date"],
        "source_ip": ["source_ip", "src_ip", "client_ip", "remote_addr", "ip", "clientIP"],
        "destination_ip": ["destination_ip", "dst_ip", "server_ip", "destIP"],
        "username": ["username", "user", "login", "account", "userName"],
        "action": ["action", "event", "type", "eventType"],
        "message": ["message", "msg", "description", "log"],
        "status": ["status", "status_code", "http_status", "response_code"],
        "method": ["method", "http_method", "request_method"],
        "path": ["path", "url", "uri", "request_uri", "request_path"],
        "user_agent": ["user_agent", "userAgent", "http_user_agent"],
    }
    
    def __init__(self):
        self.parsers = [
            ("apache_combined", self.parse_apache_combined),
            ("apache_common", self.parse_apache_common),
            ("nginx", self.parse_nginx),
            ("sshd", self.parse_sshd),
            ("auth_log", self.parse_auth_log),
            ("windows_event", self.parse_windows_event),
            ("firewall", self.parse_firewall),
            ("syslog", self.parse_syslog),
            ("json", self.parse_json),
        ]
    
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        formats = [
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d-%b-%Y %H:%M:%S",
        ]
        
        for fmt in formats:
            try:
                parsed = datetime.strptime(timestamp_str.strip(), fmt)
                if parsed.year == 1900:
                    parsed = parsed.replace(year=datetime.now().year)
                return parsed
            except ValueError:
                continue
        
        return datetime.now()
    
    def parse_apache_combined(self, line: str) -> Optional[Dict]:
        match = self.APACHE_COMBINED_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        return {
            "source_ip": groups["ip"],
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "username": groups["user"] if groups["user"] != "-" else None,
            "method": groups["method"],
            "path": groups["path"],
            "protocol": groups["protocol"],
            "status": int(groups["status"]),
            "size": int(groups["size"]) if groups["size"] != "-" else 0,
            "referer": groups["referer"] if groups["referer"] != "-" else None,
            "user_agent": groups["user_agent"],
            "log_type": "apache_combined"
        }
    
    def parse_apache_common(self, line: str) -> Optional[Dict]:
        match = self.APACHE_COMMON_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        return {
            "source_ip": groups["ip"],
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "username": groups["user"] if groups["user"] != "-" else None,
            "method": groups["method"],
            "path": groups["path"],
            "protocol": groups["protocol"],
            "status": int(groups["status"]),
            "size": int(groups["size"]) if groups["size"] != "-" else 0,
            "log_type": "apache_common"
        }
    
    def parse_nginx(self, line: str) -> Optional[Dict]:
        match = self.NGINX_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        return {
            "source_ip": groups["ip"],
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "username": groups["user"] if groups["user"] != "-" else None,
            "method": groups["method"],
            "path": groups["path"],
            "protocol": groups["protocol"],
            "status": int(groups["status"]),
            "size": int(groups["size"]),
            "referer": groups["referer"] if groups["referer"] != "-" else None,
            "user_agent": groups["user_agent"],
            "log_type": "nginx"
        }
    
    def parse_sshd(self, line: str) -> Optional[Dict]:
        match = self.SSHD_PATTERN.search(line)
        if not match:
            return None
        
        groups = match.groupdict()
        return {
            "source_ip": groups.get("ip"),
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "username": groups.get("user"),
            "action": groups["action"],
            "port": int(groups["port"]) if groups.get("port") else None,
            "hostname": groups.get("hostname"),
            "log_type": "sshd"
        }
    
    def parse_auth_log(self, line: str) -> Optional[Dict]:
        match = self.AUTH_LOG_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', groups["message"])
        user_match = re.search(r'user[=\s]+(\S+)', groups["message"], re.IGNORECASE)
        
        return {
            "source_ip": ip_match.group(1) if ip_match else None,
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "username": user_match.group(1) if user_match else None,
            "service": groups["service"],
            "message": groups["message"],
            "hostname": groups["hostname"],
            "log_type": "auth_log"
        }
    
    def parse_windows_event(self, line: str) -> Optional[Dict]:
        match = self.WINDOWS_EVENT_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', groups["message"])
        user_match = re.search(r'(?:user|account)[:\s]+(\S+)', groups["message"], re.IGNORECASE)
        
        return {
            "source_ip": ip_match.group(1) if ip_match else None,
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "username": user_match.group(1) if user_match else None,
            "event_id": int(groups["event_id"]),
            "level": groups["level"],
            "source": groups["source"],
            "message": groups["message"],
            "log_type": "windows_event"
        }
    
    def parse_firewall(self, line: str) -> Optional[Dict]:
        match = self.FIREWALL_PATTERN.search(line)
        if not match:
            return None
        
        groups = match.groupdict()
        return {
            "source_ip": groups["src_ip"],
            "destination_ip": groups["dst_ip"],
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "action": groups["action"],
            "protocol": groups["protocol"],
            "source_port": int(groups["src_port"]),
            "destination_port": int(groups["dst_port"]),
            "log_type": "firewall"
        }
    
    def parse_syslog(self, line: str) -> Optional[Dict]:
        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', groups["message"])
        
        return {
            "source_ip": ip_match.group(1) if ip_match else None,
            "timestamp": self.parse_timestamp(groups["timestamp"]),
            "priority": int(groups["priority"]),
            "hostname": groups["hostname"],
            "tag": groups["tag"],
            "message": groups["message"],
            "log_type": "syslog"
        }
    
    def parse_json(self, line: str) -> Optional[Dict]:
        try:
            data = json.loads(line.strip())
            if not isinstance(data, dict):
                return None
            
            result = {"log_type": "json"}
            
            for field, possible_keys in self.JSON_LOG_KEYS.items():
                for key in possible_keys:
                    if key in data:
                        value = data[key]
                        if field == "timestamp" and isinstance(value, str):
                            result[field] = self.parse_timestamp(value)
                        elif field == "status" and value:
                            result[field] = int(value)
                        else:
                            result[field] = value
                        break
            
            result["additional_data"] = {k: v for k, v in data.items() 
                                         if k not in sum(self.JSON_LOG_KEYS.values(), [])}
            
            return result if result.get("source_ip") or result.get("message") else None
            
        except (json.JSONDecodeError, TypeError):
            return None
    
    def parse_line(self, line: str) -> Optional[Dict]:
        line = line.strip()
        if not line:
            return None
        
        for parser_name, parser_func in self.parsers:
            result = parser_func(line)
            if result:
                result["raw_log"] = line
                return result
        
        return {
            "raw_log": line,
            "log_type": "unknown",
            "timestamp": datetime.now()
        }


class BehaviorAnalyzer:
    
    def __init__(self):
        self.ip_request_counts: Dict[str, List[datetime]] = defaultdict(list)
        self.user_login_attempts: Dict[str, List[Tuple[datetime, str, bool]]] = defaultdict(list)
        self.ip_port_access: Dict[str, Set[int]] = defaultdict(set)
        self.ip_path_access: Dict[str, List[str]] = defaultdict(list)
        self.hourly_patterns: Dict[str, Counter] = defaultdict(Counter)
        self.baseline_request_rate: float = 10.0
        self.baseline_unique_paths: int = 50
    
    def record_request(self, ip: str, timestamp: datetime, path: Optional[str] = None, 
                       port: Optional[int] = None):
        self.ip_request_counts[ip].append(timestamp)
        
        if path:
            self.ip_path_access[ip].append(path)
        
        if port:
            self.ip_port_access[ip].add(port)
        
        hour = timestamp.hour
        self.hourly_patterns[ip][hour] += 1
    
    def record_login_attempt(self, username: str, timestamp: datetime, ip: str, success: bool):
        self.user_login_attempts[username].append((timestamp, ip, success))
    
    def detect_brute_force(self, window_minutes: int = 5, threshold: int = 5) -> List[Dict]:
        brute_force_attempts = []
        
        for username, attempts in self.user_login_attempts.items():
            failed_attempts = [(ts, ip) for ts, ip, success in attempts if not success]
            
            if len(failed_attempts) < threshold:
                continue
            
            failed_attempts.sort(key=lambda x: x[0])
            
            for i in range(len(failed_attempts) - threshold + 1):
                window_start = failed_attempts[i][0]
                window_end = window_start + timedelta(minutes=window_minutes)
                
                attempts_in_window = [
                    (ts, ip) for ts, ip in failed_attempts[i:]
                    if ts <= window_end
                ]
                
                if len(attempts_in_window) >= threshold:
                    source_ips = set(ip for _, ip in attempts_in_window)
                    brute_force_attempts.append({
                        "username": username,
                        "start_time": window_start,
                        "end_time": attempts_in_window[-1][0],
                        "attempt_count": len(attempts_in_window),
                        "source_ips": list(source_ips),
                        "is_distributed": len(source_ips) > 1
                    })
                    break
        
        return brute_force_attempts
    
    def detect_port_scan(self, port_threshold: int = 10) -> List[Dict]:
        port_scans = []
        
        for ip, ports in self.ip_port_access.items():
            if len(ports) >= port_threshold:
                port_scans.append({
                    "source_ip": ip,
                    "ports_scanned": len(ports),
                    "port_list": sorted(list(ports))[:50],
                    "scan_type": self._classify_port_scan(ports)
                })
        
        return port_scans
    
    def _classify_port_scan(self, ports: Set[int]) -> str:
        common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080}
        
        if ports == common_ports or ports.issubset(common_ports):
            return "common_ports_scan"
        
        port_list = sorted(ports)
        if len(port_list) > 5:
            sequential = sum(1 for i in range(1, len(port_list)) 
                           if port_list[i] - port_list[i-1] == 1)
            if sequential > len(port_list) * 0.7:
                return "sequential_scan"
        
        if all(p < 1024 for p in ports):
            return "privileged_ports_scan"
        
        return "random_scan"
    
    def detect_dos_attack(self, window_seconds: int = 60, threshold: int = 100) -> List[Dict]:
        dos_attempts = []
        
        for ip, timestamps in self.ip_request_counts.items():
            if len(timestamps) < threshold:
                continue
            
            timestamps.sort()
            
            for i in range(len(timestamps)):
                window_start = timestamps[i]
                window_end = window_start + timedelta(seconds=window_seconds)
                
                count = sum(1 for ts in timestamps[i:] if ts <= window_end)
                
                if count >= threshold:
                    dos_attempts.append({
                        "source_ip": ip,
                        "start_time": window_start,
                        "requests_per_minute": count,
                        "total_requests": len(timestamps)
                    })
                    break
        
        return dos_attempts
    
    def detect_enumeration(self, unique_path_threshold: int = 100) -> List[Dict]:
        enumeration_attempts = []
        
        for ip, paths in self.ip_path_access.items():
            unique_paths = set(paths)
            
            if len(unique_paths) >= unique_path_threshold:
                pattern_analysis = self._analyze_path_patterns(paths)
                enumeration_attempts.append({
                    "source_ip": ip,
                    "unique_paths": len(unique_paths),
                    "total_requests": len(paths),
                    "patterns": pattern_analysis
                })
        
        return enumeration_attempts
    
    def _analyze_path_patterns(self, paths: List[str]) -> Dict:
        patterns = {
            "admin_paths": 0,
            "backup_files": 0,
            "config_files": 0,
            "numeric_enumeration": 0,
        }
        
        for path in paths:
            if re.search(r'/admin|/wp-admin|/administrator|/manager', path, re.I):
                patterns["admin_paths"] += 1
            if re.search(r'\.bak|\.backup|\.old|\.orig|\.copy', path, re.I):
                patterns["backup_files"] += 1
            if re.search(r'config|settings|\.env|\.ini|\.conf', path, re.I):
                patterns["config_files"] += 1
            if re.search(r'/\d+$|id=\d+|page=\d+', path):
                patterns["numeric_enumeration"] += 1
        
        return patterns
    
    def calculate_anomaly_score(self, ip: str) -> Tuple[float, List[str]]:
        anomalies = []
        score = 0.0
        
        requests = self.ip_request_counts.get(ip, [])
        if requests:
            time_span = (max(requests) - min(requests)).total_seconds()
            if time_span > 0:
                rate = len(requests) / (time_span / 60)
                if rate > self.baseline_request_rate * 5:
                    score += 0.3
                    anomalies.append(f"High request rate: {rate:.1f}/min")
        
        unique_paths = len(set(self.ip_path_access.get(ip, [])))
        if unique_paths > self.baseline_unique_paths * 2:
            score += 0.2
            anomalies.append(f"Unusual path diversity: {unique_paths} unique paths")
        
        ports = self.ip_port_access.get(ip, set())
        if len(ports) > 10:
            score += 0.25
            anomalies.append(f"Multiple port access: {len(ports)} ports")
        
        hourly = self.hourly_patterns.get(ip, Counter())
        if hourly:
            off_hours = sum(hourly.get(h, 0) for h in range(0, 6))
            total = sum(hourly.values())
            if total > 0 and off_hours / total > 0.5:
                score += 0.15
                anomalies.append("Majority of activity during off-hours")
        
        return min(score, 1.0), anomalies


class ReportGenerator:
    
    @staticmethod
    def generate_summary(events: List[SecurityEvent], 
                        brute_force: List[Dict],
                        port_scans: List[Dict],
                        dos_attempts: List[Dict],
                        enumeration: List[Dict]) -> AnalysisReport:
        
        if not events:
            return AnalysisReport(
                start_time=datetime.now(),
                end_time=datetime.now(),
                total_events=0,
                events_by_type={},
                events_by_threat_level={},
                top_source_ips=[],
                top_targeted_users=[],
                critical_events=[],
                brute_force_attempts=brute_force,
                potential_port_scans=port_scans,
                web_attacks=[],
                anomalies=[],
                recommendations=[]
            )
        
        def normalize_datetime(dt):
            if dt.tzinfo is not None:
                return dt.replace(tzinfo=None)
            return dt
        
        timestamps = [normalize_datetime(e.timestamp) for e in events]
        
        type_counter = Counter(e.event_type.value for e in events)
        level_counter = Counter(e.threat_level.name for e in events)
        ip_counter = Counter(e.source_ip for e in events if e.source_ip)
        user_counter = Counter(e.username for e in events if e.username)
        
        critical_events = [e for e in events if e.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]
        critical_events.sort(key=lambda x: x.threat_level.value, reverse=True)
        
        web_attacks = [e for e in events if e.event_type in [
            EventType.SQL_INJECTION, EventType.XSS_ATTEMPT, 
            EventType.PATH_TRAVERSAL, EventType.COMMAND_INJECTION
        ]]
        
        recommendations = ReportGenerator._generate_recommendations(
            events, brute_force, port_scans, dos_attempts, enumeration
        )
        
        return AnalysisReport(
            start_time=min(timestamps),
            end_time=max(timestamps),
            total_events=len(events),
            events_by_type=dict(type_counter),
            events_by_threat_level=dict(level_counter),
            top_source_ips=ip_counter.most_common(10),
            top_targeted_users=user_counter.most_common(10),
            critical_events=critical_events[:20],
            brute_force_attempts=brute_force,
            potential_port_scans=port_scans,
            web_attacks=web_attacks[:20],
            anomalies=dos_attempts + enumeration,
            recommendations=recommendations
        )
    
    @staticmethod
    def _generate_recommendations(events: List[SecurityEvent],
                                  brute_force: List[Dict],
                                  port_scans: List[Dict],
                                  dos_attempts: List[Dict],
                                  enumeration: List[Dict]) -> List[str]:
        recommendations = []
        
        if brute_force:
            recommendations.append(
                f"CRITICAL: {len(brute_force)} brute force attack(s) detected. "
                "Implement account lockout policies, enable MFA, and consider IP-based rate limiting."
            )
            
            distributed = [bf for bf in brute_force if bf.get("is_distributed")]
            if distributed:
                recommendations.append(
                    "WARNING: Distributed brute force attacks detected from multiple IPs. "
                    "Consider implementing CAPTCHA and progressive delays."
                )
        
        if port_scans:
            recommendations.append(
                f"ALERT: {len(port_scans)} port scanning attempt(s) detected. "
                "Review firewall rules and ensure only necessary ports are exposed."
            )
        
        if dos_attempts:
            recommendations.append(
                f"CRITICAL: {len(dos_attempts)} potential DoS attack(s) detected. "
                "Implement rate limiting, consider WAF deployment, and review CDN options."
            )
        
        if enumeration:
            recommendations.append(
                f"WARNING: {len(enumeration)} directory enumeration attempt(s) detected. "
                "Review directory listing settings and implement custom 404 pages."
            )
        
        sql_attacks = [e for e in events if e.event_type == EventType.SQL_INJECTION]
        if sql_attacks:
            recommendations.append(
                f"CRITICAL: {len(sql_attacks)} SQL injection attempt(s) detected. "
                "Audit application code for parameterized queries and implement WAF rules."
            )
        
        xss_attacks = [e for e in events if e.event_type == EventType.XSS_ATTEMPT]
        if xss_attacks:
            recommendations.append(
                f"HIGH: {len(xss_attacks)} XSS attempt(s) detected. "
                "Implement proper output encoding and Content Security Policy headers."
            )
        
        traversal_attacks = [e for e in events if e.event_type == EventType.PATH_TRAVERSAL]
        if traversal_attacks:
            recommendations.append(
                f"HIGH: {len(traversal_attacks)} path traversal attempt(s) detected. "
                "Validate and sanitize all file path inputs, implement chroot jails where applicable."
            )
        
        if not recommendations:
            recommendations.append(
                "No critical security issues detected. Continue monitoring and "
                "maintain regular security assessments."
            )
        
        return recommendations
    
    @staticmethod
    def to_json(report: AnalysisReport) -> str:
        return json.dumps({
            "summary": {
                "start_time": report.start_time.isoformat(),
                "end_time": report.end_time.isoformat(),
                "total_events": report.total_events,
                "events_by_type": report.events_by_type,
                "events_by_threat_level": report.events_by_threat_level,
            },
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in report.top_source_ips],
            "top_targeted_users": [{"user": user, "count": count} for user, count in report.top_targeted_users],
            "critical_events": [e.to_dict() for e in report.critical_events],
            "brute_force_attempts": report.brute_force_attempts,
            "port_scans": report.potential_port_scans,
            "web_attacks": [e.to_dict() for e in report.web_attacks],
            "anomalies": report.anomalies,
            "recommendations": report.recommendations,
        }, indent=2, default=str)
    
    @staticmethod
    def to_csv(events: List[SecurityEvent]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            "Timestamp", "Source IP", "Event Type", "Threat Level",
            "Description", "Username", "Request Path", "HTTP Status"
        ])
        
        for event in events:
            writer.writerow([
                event.timestamp.isoformat(),
                event.source_ip,
                event.event_type.value,
                event.threat_level.name,
                event.description,
                event.username or "",
                event.request_path or "",
                event.http_status or ""
            ])
        
        return output.getvalue()
    
    @staticmethod
    def generate_html_report(report: AnalysisReport) -> str:
        critical_count = report.events_by_threat_level.get("CRITICAL", 0)
        high_count = report.events_by_threat_level.get("HIGH", 0)
        
        overall_status = "CRITICAL" if critical_count > 0 else "WARNING" if high_count > 0 else "NORMAL"
        status_color = "#dc3545" if overall_status == "CRITICAL" else "#ffc107" if overall_status == "WARNING" else "#28a745"
        
        start_ts = report.start_time
        end_ts = report.end_time
        if start_ts.tzinfo is not None:
            start_ts = start_ts.replace(tzinfo=None)
        if end_ts.tzinfo is not None:
            end_ts = end_ts.replace(tzinfo=None)
        
        events_rows = ""
        for event in report.critical_events[:15]:
            level_color = {
                "CRITICAL": "#dc3545",
                "HIGH": "#fd7e14",
                "MEDIUM": "#ffc107",
                "LOW": "#17a2b8",
                "INFO": "#6c757d"
            }.get(event.threat_level.name, "#6c757d")
            
            event_ts = event.timestamp
            if event_ts.tzinfo is not None:
                event_ts = event_ts.replace(tzinfo=None)
            
            events_rows += f"""
            <tr>
                <td>{event_ts.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td>{event.source_ip or 'N/A'}</td>
                <td>{event.event_type.value}</td>
                <td style="color: {level_color}; font-weight: bold;">{event.threat_level.name}</td>
                <td>{event.description[:100]}...</td>
            </tr>"""
        
        recommendations_html = "".join(f"<li>{rec}</li>" for rec in report.recommendations)
        
        top_ips_html = "".join(
            f"<tr><td>{ip}</td><td>{count}</td></tr>" 
            for ip, count in report.top_source_ips[:5]
        )
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .status-badge {{ display: inline-block; padding: 10px 20px; border-radius: 5px; color: white; font-weight: bold; font-size: 18px; background: {status_color}; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card h3 {{ margin: 0; color: #666; font-size: 14px; }}
        .summary-card .value {{ font-size: 36px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #007bff; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .recommendations {{ background: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; }}
        .recommendations li {{ margin: 10px 0; }}
        .timestamp {{ color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Log Analysis Report</h1>
        <p class="timestamp">Analysis Period: {start_ts.strftime('%Y-%m-%d %H:%M')} to {end_ts.strftime('%Y-%m-%d %H:%M')}</p>
        
        <div style="margin: 20px 0;">
            <span class="status-badge">Overall Status: {overall_status}</span>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Events</h3>
                <div class="value">{report.total_events}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Events</h3>
                <div class="value" style="color: #dc3545;">{critical_count}</div>
            </div>
            <div class="summary-card">
                <h3>High Severity</h3>
                <div class="value" style="color: #fd7e14;">{high_count}</div>
            </div>
            <div class="summary-card">
                <h3>Brute Force Attempts</h3>
                <div class="value">{len(report.brute_force_attempts)}</div>
            </div>
        </div>
        
        <h2>Top Suspicious IPs</h2>
        <table>
            <tr><th>IP Address</th><th>Event Count</th></tr>
            {top_ips_html}
        </table>
        
        <h2>Critical Security Events</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Event Type</th>
                <th>Severity</th>
                <th>Description</th>
            </tr>
            {events_rows}
        </table>
        
        <h2>Recommendations</h2>
        <div class="recommendations">
            <ul>{recommendations_html}</ul>
        </div>
        
        <p class="timestamp">Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</body>
</html>"""
        
        return html