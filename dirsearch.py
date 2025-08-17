import json
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime
from collections import deque
import re


# 从 JSON 文件中加载规则
def load_rules(filename):
    """
    加载包含检测规则的JSON文件
    参数:
        filename: 规则文件路径
    返回:
        从JSON文件中解析出的规则列表
    """
    with open(filename, "r") as file:
        data = json.load(file)
    return data["dirsearch_detection_rules"]


# 规则匹配逻辑
def parse_http_payload(payload):
    """
    解析HTTP数据包的原始负载
    参数:
        payload: 原始网络数据包的负载部分
    返回:
        dict: 包含解析出的HTTP方法、路径和头部信息
              None: 如果解析失败
    """
    try:
        # 将二进制payload转为UTF-8字符串(忽略解码错误)
        payload_str = payload.decode("utf-8", errors="ignore").strip()
        if not payload_str:  # 空负载检查
            return None

        # 分割HTTP头部和主体(只取头部部分)
        headers_part = payload_str.split("\r\n\r\n", 1)[0]
        lines = headers_part.split("\r\n")  # 按行分割头部
        if not lines:  # 头部为空检查
            return None

        # 解析请求行 (格式: METHOD PATH PROTOCOL)
        request_line = lines[0].strip()
        # 使用正则安全分割请求行
        request_parts = re.split(r'\s+', request_line, 2)
        if len(request_parts) < 2:  # 无效请求行检查
            return None
        method, path = request_parts[0], request_parts[1]

        # 解析HTTP头部
        headers = {}
        for line in lines[1:]:
            if ": " in line:  # 只处理有效的头部行
                key, val = line.split(": ", 1)
                headers[key.strip()] = val.strip()

        return {
            "method": method.upper(),  # 方法统一转为大写
            "path": path,
            "headers": headers
        }
    except Exception as e:
        print(f"解析HTTP数据包错误: {str(e)}")
        return None


# 规则匹配函数
def matches_conditions(conditions, packet_info):
    """
    检查数据包是否匹配规则条件
    参数:
        conditions: 规则条件字典
        packet_info: 数据包解析信息
    返回:
        bool: 是否匹配规则条件
    """
    try:
        # User-Agent条件匹配
        if "user_agent" in conditions:
            user_agent_rule = conditions["user_agent"]
            user_agent_pkt = packet_info.get("user_agent", "")
            # 处理User-Agent规则可以是字符串或列表
            if isinstance(user_agent_rule, list):
                return any(ua.lower() in user_agent_pkt.lower() for ua in user_agent_rule)
            else:
                return user_agent_rule.lower() in user_agent_pkt.lower()

        # URL包含条件匹配
        if "url_contains" in conditions:
            url_rule = conditions["url_contains"]
            url_pkt = packet_info.get("url", "")
            return any(kw.lower() in url_pkt.lower() for kw in url_rule)

        # 扩展规则条件处理（按需补充）...

        return False
    except Exception as e:
        print(f"规则匹配错误: {str(e)}")
        return False


# 异常处理的包处理函数
def packet_handler(packet):
    try:
        if IP in packet and TCP in packet and Raw in packet:
            src_ip = packet[IP].src
            http_data = parse_http_payload(packet[Raw].load)
            if http_data:
                packet_info = {
                    "src_ip": src_ip,
                    "url": http_data["path"],
                    "http_method": http_data["method"],
                    "user_agent": http_data["headers"].get("User-Agent", "")
                }
                for rule in rules:
                    if matches_conditions(rule.get("conditions", {}), packet_info):
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        log_message = f"[{timestamp}] 检测到威胁 - {rule['rule_id']}: {src_ip} - {rule['description']}"
                        print(log_message)  # 输出到控制台

                        # 写入日志文件（追加模式）
                        with open("dirsearch.log", "a", encoding="utf-8") as log_file:
                            log_file.write(log_message + "\n")  # 换行符确保每条日志独立
    except Exception as e:
        error_msg = f"[{datetime.now()}] 处理数据包异常: {str(e)}"
        print(error_msg)
        with open("dirsearch.log", "a", encoding="utf-8") as log_file:
            log_file.write(error_msg + "\n")


# 主函数
def main():
    """
    程序主入口
    """
    global rules
    # 加载规则
    rules = load_rules("dirsearch_detection_rules.json")
    print("启动实时监控...")
    # 启动嗅探器: 只监控80和8080端口的TCP流量
    sniff(filter="tcp and (port 80 or port 8080)", prn=packet_handler, store=False)


if __name__ == "__main__":
    main()

