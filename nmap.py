import json
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, TCP, UDP, ICMP, IP, conf, get_if_addr


class NmapDetector:
    def __init__(self, rule_file):
        """
        Nmap扫描检测器初始化
        参数:
            rule_file: 包含检测规则的JSON文件路径
        """
        # 加载规则文件
        with open(rule_file, 'r') as f:
            # 从JSON文件中读取nmap扫描检测规则
            self.rules = json.load(f)["nmap_scan_detection_rules"]

        # 状态跟踪：用于检测高频流量
        # 使用defaultdict自动初始化每个源IP的状态记录
        self.state = defaultdict(lambda: {
            "count": 0,  # 数据包计数器
            "start_time": datetime.now()  # 开始计时时间
        })
        with open("nmap.log", "a",encoding="utf-8") as f:
            f.write(f"Nmap检测日志 - 开始时间: {datetime.now()}\n")

    def _log_alert(self, message):
        """
        统一的日志记录方法
        同时输出到控制台和日志文件
        """
        print(message)  # 控制台输出
        with open("nmap.log", "a",  encoding="utf-8") as f:  # 追加写入日志文件
            f.write(message + "\n")

    def _check_condition(self, pkt, condition):
        """
        检查单个数据包是否满足规则条件
        参数:
            pkt: 捕获的网络数据包
            condition: 匹配条件的字典
        返回:
            bool: 是否满足条件
        """
        # 协议匹配检查
        if "protocol" in condition and pkt.haslayer(IP):
            proto = condition["protocol"].lower()
            if proto == "tcp" and not pkt.haslayer(TCP):
                return False
            elif proto == "udp" and not pkt.haslayer(UDP):
                return False
            elif proto == "icmp" and not pkt.haslayer(ICMP):
                return False

        # TCP标志检查（例如规则中的"flags": "S"检测SYN扫描）
        if pkt.haslayer(TCP) and "flags" in condition:
            expected_flags = condition["flags"]
            actual_flags = pkt[TCP].flags
            if expected_flags and not (expected_flags in str(actual_flags)):
                return False

        # 源端口范围检查（例如"source_port": "> 30000"）
        if "source_port" in condition and pkt.haslayer(TCP):
            port = int(pkt[TCP].sport)
            condition_port = condition["source_port"]
            if isinstance(condition_port, str):
                if ">" in condition_port:  # 大于某端口的情况
                    min_port = int(condition_port.split(">")[1].strip())
                    if port <= min_port:
                        return False
                elif "-" in condition_port:  # 端口范围的情况
                    min_port, max_port = map(int, condition_port.split("-"))
                    if port < min_port or port > max_port:
                        return False
                else:  # 特定端口的情况
                    if port != int(condition_port):
                        return False

        # ICMP类型检查（例如规则中的"type": "8"检测ping扫描）
        if pkt.haslayer(ICMP) and "type" in condition:
            if str(pkt[ICMP].type) != condition["type"]:
                return False

        # 目标端口范围检查（例如"target_port_range": "1-1024"检测端口扫描）
        if "target_port_range" in condition and pkt.haslayer(TCP):
            port = pkt[TCP].dport
            port_range = condition["target_port_range"]
            min_port, max_port = map(int, port_range.split("-"))
            if port < min_port or port > max_port:
                return False

        return True  # 所有检查都通过

    def _process_packet(self, pkt):
        """处理数据包并记录日志"""
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        local_ip = get_if_addr(conf.iface)

        if src_ip == local_ip:
            return
        for rule in self.rules:
            if self._check_condition(pkt, rule["conditions"]):
                rule_id = rule["rule_id"]

                if rule_id not in self.state[src_ip]:
                    self.state[src_ip][rule_id] = {
                        "count": 0,
                        "start_time": datetime.now()
                    }
                state = self.state[src_ip][rule_id]
                state["count"] += 1
                rate_threshold = int(rule["conditions"].get("rate_threshold", 0))
                time_window = int(rule["conditions"].get("time_window", 60))
                elapsed_time = (datetime.now() - state["start_time"]).total_seconds()
                if elapsed_time == 0:
                    elapsed_time = 1
                if elapsed_time > time_window:
                    state["count"] = 1
                    state["start_time"] = datetime.now()
                elif state["count"] > rate_threshold:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert_msg = (
                        f"[{current_time}] 告警 - 规则 {rule['rule_id']} ({rule['description']}): "
                        f"检测到可疑行为，来源 IP: {src_ip}, 目的 IP: {dst_ip}, "
                        f"计数: {state['count']}, 速率: {state['count'] / elapsed_time:.2f} 包/秒"
                    )
                    self._log_alert(alert_msg)  # 使用统一的日志记录方法
                    state["count"] = 0
                    state["start_time"] = datetime.now()

    def start_monitor(self, interface="eth0"):
        """
        启动网络监控
        参数:
            interface: 网络接口名称(默认eth0)
        """
        # 从规则中提取需要监听的协议类型(去重)
        filter_protos = list(set(
            [r["conditions"].get("protocol", "").lower() for r in self.rules]
        ))

        # 构建BPF过滤规则字符串
        filter_str = " or ".join([f"{proto}" for proto in filter_protos if proto])

        # 添加IP层过滤
        if filter_str:
            filter_str = f"({filter_str}) and ip"
        else:
            filter_str = "ip"

        print(f"Starting Nmap scan detection on interface {interface}...")

        # 开始捕获网络数据包
        # iface: 指定网络接口
        # filter: 使用BPF过滤规则提高性能
        # prn: 指定数据包处理函数
        # store: 不存储数据包以节省内存
        sniff(iface=interface, filter=filter_str, prn=self._process_packet, store=0)


if __name__ == "__main__":
    # 实例化Nmap检测器，指定规则文件路径
    detector = NmapDetector("nmap_detection_rules.json")
    # 启动监控，指定网络接口
    # 注意：根据实际情况修改接口名称
    detector.start_monitor(interface="Intel(R) Wi-Fi 6 AX201 160MHz")
