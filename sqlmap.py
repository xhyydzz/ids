"""
SQL注入实时检测系统
核心功能：
1. 网络流量嗅探（80/443端口）
2. SQL注入特征规则匹配
3. sqlmap工具指纹识别
4. 基于时间窗口的频率分析
5. 分级告警日志记录
"""

# ==================== 基础库导入 ====================
import json
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import sniff, TCP, IP, Raw
from scapy.error import Scapy_Exception
from urllib.parse import parse_qs, urlparse
from threading import Thread


# ==================== 状态管理器 ====================
"""
    IP行为状态跟踪器
    功能：
    - 滑动时间窗口计数
    - 阈值告警触发
    - 防重复告警机制
    """
# ==================== 主检测引擎 ====================
class SQLInjectionStateManager:
    """跟踪每个源IP的SQL注入行为，计算事件频率并触发告警"""

    def __init__(self, time_window=300, threshold=5):
        """
        :param time_window: 时间窗口(秒)，默认为5分钟
        :param threshold: 触发告警的阈值(次数)
        """
        self.time_window = time_window
        self.threshold = threshold

        # 存储结构: {ip: [(timestamp, event_type), ...]}
        self.event_store = defaultdict(list)

        # 告警计数器，避免重复告警
        self.alerted_ips = defaultdict(int)

    def add_event(self, ip, event_type="SQLi_Attempt"):
        """记录一个新事件"""
        now = datetime.now()
        self.event_store[ip].append((now, event_type))
        self.cleanup_old_events(ip)
        return self.check_alert_condition(ip)

    def cleanup_old_events(self, ip):
        """移除超出时间窗口的旧事件"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.time_window)

        # 保留时间窗口内的事件
        self.event_store[ip] = [
            (ts, et) for (ts, et) in self.event_store[ip]
            if ts > cutoff
        ]

    def get_event_count(self, ip, event_type=None):
        """获取指定IP在时间窗口内的事件计数"""
        self.cleanup_old_events(ip)

        if event_type:
            return sum(1 for (ts, et) in self.event_store[ip] if et == event_type)
        return len(self.event_store[ip])

    def check_alert_condition(self, ip):
        """检查是否需要触发告警"""
        count = self.get_event_count(ip)

        # 如果超过阈值且最近没有告警过
        if count >= self.threshold and self.alerted_ips.get(ip, 0) < count:
            self.alerted_ips[ip] = count
            return True
        return False

    def get_all_suspicious_ips(self):
        """获取所有可疑IP及其事件计数"""
        return {
            ip: self.get_event_count(ip)
            for ip in self.event_store
            if self.get_event_count(ip) > 0
        }


class SQLInjectionDetector:
    def __init__(self):
        self.rules = self.load_rules("sqlmap_detection_rules.json")
        self.state_manager = SQLInjectionStateManager(
            time_window=300,  # 5分钟窗口
            threshold=5  # 5次尝试触发告警
        )
        self.whitelist = {'*.*.*.*'}  # 服务器IP白名单
        self.sqlmap_fingerprints = [
            {"pattern": re.compile(r'sqlmap/[0-9.]+', re.I), "type": "UA Signature"},
            {"pattern": re.compile(r'libinjection', re.I), "type": "Detection Library"},
            {"pattern": re.compile(r'\b__[a-z0-9]{32}\b', re.I), "type": "Temporary Table Pattern"},
            {"pattern": re.compile(r'benchmark\([0-9]{6,}', re.I), "type": "Stress Testing"},
            {"pattern": re.compile(r'union select [a-z0-9,]+\bfrom information_schema\b', re.I),
             "type": "Database Probing"}
        ]
        self.sqlmap_param_patterns = [
            {"pattern": re.compile(r'[\?&][a-z0-9_]+=[0-9]{6,}'), "type": "Long Numeric Parameter"},
            {"pattern": re.compile(r'[\?&][a-z0-9_]+=~[a-z0-9]+'), "type": "Special Character Parameter"},
            {"pattern": re.compile(r'/\*![0-9]{5}', re.I), "type": "MySQL Version Comment"},
            {"pattern": re.compile(r'\(select\b.*?\bfrom\b', re.I), "type": "Nested Subquery"}
        ]
        self.running = True  # 控制监控线程的标志

    def load_rules(self, filename):
        try:
            with open(filename, "r", encoding='utf-8') as file:
                data = json.load(file)

            for rule in data["sqlmap_detection_rules"]:
                # 预处理所有匹配条件
                if "url_contains" in rule["conditions"]:
                    rule["url_patterns"] = [
                        {"pattern": re.compile(re.escape(kw), re.I), "original": kw}
                        for kw in rule["conditions"]["url_contains"]
                    ]

                if "user_agent" in rule["conditions"]:
                    if isinstance(rule["conditions"]["user_agent"], list):
                        rule["ua_patterns"] = [
                            {"pattern": re.compile(re.escape(ua), re.I), "original": ua}
                            for ua in rule["conditions"]["user_agent"]
                        ]

                if "post_body_contains" in rule["conditions"]:
                    rule["post_patterns"] = [
                        {"pattern": re.compile(re.escape(kw), re.I), "original": kw}
                        for kw in rule["conditions"]["post_body_contains"]
                    ]

            return data["sqlmap_detection_rules"]
        except Exception as e:
            print(f"[!] Rule loading error: {str(e)}")
            return []

    def is_whitelisted(self, ip):
        return ip in self.whitelist

    def check_sqlmap_fingerprints(self, payload):
        """检测sqlmap专用指纹并返回匹配详情"""
        matches = []
        for fp in self.sqlmap_fingerprints:
            if fp["pattern"].search(payload):
                matches.append({
                    "type": "SQLMAP Fingerprint",
                    "detail": f"{fp['type']} (Pattern: {fp['pattern'].pattern})",
                    "matched": fp["pattern"].search(payload).group()
                })

        for pp in self.sqlmap_param_patterns:
            if pp["pattern"].search(payload):
                matches.append({
                    "type": "SQLMAP Parameter Pattern",
                    "detail": f"{pp['type']} (Pattern: {pp['pattern'].pattern})",
                    "matched": pp["pattern"].search(payload).group()
                })

        return matches if matches else None

    # ==================== 辅助方法 ====================
    def extract_http_info(self, payload):
        """提取HTTP请求信息"""
        try:
            http_info = {
                'method': '',
                'path': '',
                'headers': {},
                'body': '',
                'content_type': '',
                'query': ''
            }

            lines = payload.split('\r\n')
            if not lines:
                return None

            # 解析请求行
            request_line = lines[0].split()
            if len(request_line) >= 2:
                http_info['method'] = request_line[0]
                url_parts = urlparse(request_line[1])
                http_info['path'] = url_parts.path
                http_info['query'] = url_parts.query

            # 解析头信息
            body_start = False
            for line in lines[1:]:
                if not line.strip():
                    body_start = True
                    continue

                if not body_start:
                    header = line.split(':', 1)
                    if len(header) == 2:
                        key = header[0].strip()
                        value = header[1].strip()
                        http_info['headers'][key] = value
                        if key.lower() == 'content-type':
                            http_info['content_type'] = value.split(';')[0].strip()
                else:
                    http_info['body'] += line

            return http_info
        except Exception as e:
            print(f"[!] HTTP parsing error: {str(e)}")
            return None

    def analyze_rule_match(self, rule, http_info):
        """分析请求与规则的匹配情况"""
        matches = []
        conditions = rule.get("conditions", {})

        # User-Agent检查
        if hasattr(rule, 'ua_patterns'):
            ua = http_info['headers'].get('User-Agent', '')
            for pattern in rule.ua_patterns:
                if match := pattern["pattern"].search(ua):
                    matches.append({
                        "condition": "User-Agent",
                        "matched": match.group(),
                        "pattern": pattern["original"],
                        "rule_field": "user_agent"
                    })

        # URL路径检查
        if hasattr(rule, 'url_patterns'):
            for pattern in rule.url_patterns:
                if match := pattern["pattern"].search(http_info['path'] + '?' + http_info['query']):
                    matches.append({
                        "condition": "URL Path",
                        "matched": match.group(),
                        "pattern": pattern["original"],
                        "rule_field": "url_contains"
                    })

        # POST数据检查
        if hasattr(rule, 'post_patterns') and http_info['body']:
            for pattern in rule.post_patterns:
                if match := pattern["pattern"].search(http_info['body']):
                    matches.append({
                        "condition": "POST Data",
                        "matched": match.group(),
                        "pattern": pattern["original"],
                        "rule_field": "post_body_contains"
                    })

        # Content-Type检查
        if "content_type" in conditions and http_info['content_type']:
            if http_info['content_type'] in conditions["content_type"]:
                matches.append({
                    "condition": "Content-Type",
                    "matched": http_info['content_type'],
                    "pattern": "|".join(conditions["content_type"]),
                    "rule_field": "content_type"
                })

        return matches if matches else None

    def handle_packet(self, packet):
        try:
            # 基本包检查
            if not packet.haslayer(TCP) or not packet.haslayer(IP) or not packet.haslayer(Raw):
                return

            raw_payload = bytes(packet[Raw].load)
            if b'\x00' in raw_payload[:10]:  # 跳过二进制数据
                return

            src_ip = packet[IP].src
            if self.is_whitelisted(src_ip):
                return

            payload = raw_payload.decode('utf-8', errors='ignore')
            if not payload.strip():
                return

            # 提取HTTP信息
            http_info = self.extract_http_info(payload)
            if not http_info:
                return

            # 1. 检查SQLMap特定指纹
            if fp_matches := self.check_sqlmap_fingerprints(payload):
                self.state_manager.add_event(src_ip, "SQLMAP_Fingerprint")
                self.log_sqlmap_alert(src_ip, payload, fp_matches)
                return

            # 2. 检查预定义规则
            triggered_rules = []
            for rule in self.rules:
                if matches := self.analyze_rule_match(rule, http_info):
                    triggered_rules.append({
                        "rule": rule,
                        "matches": matches,
                        "severity": rule["severity"]
                    })

            # 3. 状态管理: 记录事件并检查告警条件
            if triggered_rules:
                event_type = f"{triggered_rules[0]['severity']}_{triggered_rules[0]['rule']['rule_id']}"
                if self.state_manager.add_event(src_ip, event_type):
                    self.log_frequency_alert(src_ip, event_type)
                self.log_rule_alert(src_ip, payload, triggered_rules)

        except Exception as e:
            print(f"[!] Packet processing error: {str(e)}")

    def log_frequency_alert(self, ip, event_type):
        """记录频率告警"""
        count = self.state_manager.get_event_count(ip, event_type)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert_msg = [
            f"\n[{timestamp}] FREQUENCY ALERT - Repeated SQLi Attempts",
            f"Source IP: {ip}",
            f"Event Type: {event_type}",
            f"Count in time window: {count}",
            "=" * 60
        ]

        full_msg = "\n".join(alert_msg)
        print(full_msg)
        with open('frequency_alerts.log', 'a') as f:
            f.write(full_msg + "\n")

    # ==================== 日志系统 ====================
    def log_sqlmap_alert(self, src_ip, payload, matches):
        """记录sqlmap专属指纹告警"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = [
            f"\n[{timestamp}] CRITICAL - SQLMAP Scanning Detected",
            f"Source IP: {src_ip}",
            "Matched SQLMAP Fingerprints:"
        ]

        for match in matches:
            alert_msg.append(f"  • {match['type']}: {match['detail']}")
            alert_msg.append(f"    Matched content: {match['matched']}")

        alert_msg.extend([
            "Partial request content:",
            payload[:500],
            "=" * 60
        ])

        full_msg = "\n".join(alert_msg)
        print(full_msg)

        with open('sqlmap_alerts.log', 'a', encoding='utf-8') as f:
            f.write(full_msg + "\n")

    def log_rule_alert(self, src_ip, payload, triggered_rules):
        """记录规则触发告警"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for rule_data in triggered_rules:
            rule = rule_data["rule"]
            matches = rule_data["matches"]

            alert_msg = [
                f"\n[{timestamp}] {rule['severity'].upper()} - Rule Triggered",
                f"Rule ID: {rule['rule_id']}",
                f"Description: {rule['description']}",
                f"Source IP: {src_ip}",
                "Match Conditions:"
            ]

            for match in matches:
                alert_msg.append(
                    f"  • Condition Type: {match['condition']} | "
                    f"Rule Field: {match['rule_field']} | "
                    f"Pattern: {match['pattern']} | "
                    f"Matched Value: {match['matched']}"
                )

            alert_msg.extend([
                "Partial request content:",
                payload[:500],
                "=" * 60
            ])

            full_msg = "\n".join(alert_msg)
            print(full_msg)

            with open('sql_rules_alerts.log', 'a', encoding='utf-8') as f:
                f.write(full_msg + "\n")

    def monitor_state(self):
        """定期监控并打印当前状态"""
        while self.running:
            time.sleep(60)
            suspicious_ips = self.state_manager.get_all_suspicious_ips()
            if suspicious_ips:
                print("\n[Current Suspicious IPs]")
                for ip, count in suspicious_ips.items():
                    print(f"{ip}: {count} events in last 5 minutes")

    def stop(self):
        """停止监控线程"""
        self.running = False


# ==================== 主程序 ====================
def main():
    detector = SQLInjectionDetector()
    banner = """
    ███████╗ ██████╗ ██╗
    ██╔════╝██╔═══██╗██║
    ███████╗██║   ██║██║
    ╚════██║██║   ██║██║
    ███████║╚██████╔╝███████╗
    ╚══════╝ ╚═════╝ ╚══════╝
    SQL Injection Detection System
    """
    print(banner)
    print(f"Loaded {len(detector.rules)} detection rules")
    print(f"SQLMAP specific fingerprints: {len(detector.sqlmap_fingerprints)}")
    print("Starting network traffic monitoring...\n")

    try:
        sniff(filter="tcp and (port 80 or port 443)", prn=detector.handle_packet, store=0)
    except KeyboardInterrupt:
        print("\n[+] Detection system terminated normally")
    except Exception as e:
        print(f"[!] System error: {str(e)}")


if __name__ == "__main__":
    main()
