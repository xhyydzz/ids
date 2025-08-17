"""
XSS攻击实时检测系统
原有功能保持不变，只增加日志记录功能
"""

import json
from datetime import datetime
from scapy.all import sniff, TCP, IP, Raw, Ether

# 全局规则变量
rules = None

def setup_logging():
    """初始化日志文件（仅添加的功能）"""
    with open("xss.log", "a",encoding='utf-8') as f:
        f.write(f"\n{'='*60}\nXSS检测服务启动 @ {datetime.now()}\n{'='*60}\n")

def log_alert(message, payload=None):
    """
    简化版的日志记录函数
    只记录告警信息，不记录payload样本
    """
    with open("xss.log", "a", encoding='utf-8') as f:
        f.write(message + "\n")

def load_rules(filename):
    """
    加载XSS检测规则配置文件
    :param filename: JSON规则文件路径
    :return: 规则列表
    """
    try:
        with open(filename, "r",encoding="utf-8") as file:
            data = json.load(file)
        print(f"成功加载 {len(data['xss_attack_detection_rules'])} 条XSS检测规则")
        return data["xss_attack_detection_rules"]
    except Exception as e:
        print(f"规则加载失败: {str(e)}")
        return []

def handle_packet(packet):
    """
    数据包处理回调函数
    :param packet: scapy捕获的网络数据包
    """
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = packet[Ether].src if packet.haslayer(Ether) else "Unknown"
            dst_ip = "Local Network"

        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")

            event = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "payload": payload,
                "timestamp": datetime.now(),
            }

            for rule in rules:
                if matches_conditions(rule["conditions"], event):
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    alert_msg = f"[{current_time}] 告警 - 规则 {rule['rule_id']} ({rule['description']}): 攻击源: {src_ip}, 目标服务器: {dst_ip}"
                    print(alert_msg)  # 原有控制台输出
                    log_alert(alert_msg, payload)  # 新增的日志记录

        except Exception as e:
            error_msg = f"数据包处理异常: {str(e)}"
            print(error_msg)
            log_alert(error_msg)

def matches_conditions(conditions, event):
    payload = event["payload"].lower()

    if "request_parameters_contain" in conditions:
        for keyword in conditions["request_parameters_contain"]:
            if keyword.lower() in payload:
                return True

    if "javascript_event_handlers" in conditions:
        for handler in conditions["javascript_event_handlers"]:
            if f"{handler}=" in payload:
                return True

    if "javascript_protocol" in conditions:
        for proto in conditions["javascript_protocol"]:
            if f"{proto}:" in payload:
                return True

    if "html_attributes" in conditions:
        for attr in conditions["html_attributes"]:
            if f"{attr}=" in payload:
                return True

    if "encoded_patterns" in conditions:
        for pattern in conditions["encoded_patterns"]:
            if pattern in payload:
                return True

    if "dom_xss_keywords" in conditions:
        for keyword in conditions["dom_xss_keywords"]:
            if keyword in payload:
                return True

    if "reflected_parameters" in conditions:
        params = payload.split("&")
        for param in params:
            if "=" in param:
                _, value = param.split("=", 1)
                if value and value in payload:
                    return True

    return False

def main():
    global rules
    setup_logging()  # 新增的日志初始化
    rules = load_rules("xss_attack_detection_rules.json")
    print("启动XSS攻击检测...")


    try:
        sniff(prn=handle_packet, store=0)
    except KeyboardInterrupt:
        print("\n检测服务已停止")
        log_alert("检测服务已手动停止")  # 新增的停止记录

if __name__ == "__main__":
    main()
