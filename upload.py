"""
文件上传安全监控系统
功能：
- 实时监控指定目录的文件上传行为
- 基于规则的多维度安全检测
- 自动隔离危险文件
- 可视化告警日志
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from watchdog.observers import Observer  # 文件系统监控库
from watchdog.events import FileSystemEventHandler  # 文件事件处理基类


def load_rules(filename):
    """
    从JSON配置文件中加载检测规则
    :param filename: 规则文件路径
    :return: 规则列表
    """
    try:
        with open(filename, "r", encoding='utf-8') as file:
            data = json.load(file)
        print(f"成功加载 {len(data['file_upload_attack_detection_rules'])} 条文件上传检测规则")
        return data["file_upload_attack_detection_rules"]
    except Exception as e:
        print(f"规则加载失败: {str(e)}")
        return []


def matches_conditions(conditions, file_info):
    """
    多条件匹配引擎
    :param conditions: 规则条件字典
    :param file_info: 文件信息字典
    :return: 是否触发规则(bool)
    """
    try:
        # ---- 文件扩展名检测 ----
        if "file_extension" in conditions:
            if any(file_info["file_name"].lower().endswith(ext.lower())
                   for ext in conditions["file_extension"]):
                return True

        # ---- 文件大小范围检测 ----
        if "file_size" in conditions:
            min_size = parse_size(conditions["file_size"].get("min_size", "200B"))
            max_size = parse_size(conditions["file_size"].get("max_size", "1GB"))
            return min_size <= file_info["file_size"] <= max_size

        # ---- MIME类型检测 ----
        if "mime_type" in conditions and file_info.get("mime_type"):
            if file_info["mime_type"] in conditions["mime_type"]:
                return True

        # ---- 重复文件检测 ----
        if "duplicate_file_hash" in conditions:
            threshold = conditions["duplicate_file_hash"].get("threshold", 1)
            if file_info["file_hash_count"] >= threshold:
                return True

        # ---- 空字节注入检测 ----
        if "null_bytes_in_filename" in conditions and conditions["null_bytes_in_filename"]:
            if any(c in file_info["file_name"] for c in ["\x00", "%00"]):
                return True

        # ---- 敏感目录检测 ----
        if "restricted_directories" in conditions:
            if any(dir_path in file_info["upload_directory"]
                   for dir_path in conditions["restricted_directories"]):
                return True

        # ---- 文件名长度检测 ----
        if "filename_length" in conditions:
            # 兼容新老版本格式
            if isinstance(conditions["filename_length"], dict):
                min_len = conditions["filename_length"].get("min_length", 0)
                max_len = conditions["filename_length"].get("max_length", 255)
            else:  # 旧版格式直接使用固定值
                min_len = conditions["filename_length"]
                max_len = 255
            return not (min_len <= len(file_info["file_name"]) <= max_len)

        # ---- 文件内容检测 ----
        if "content_patterns" in conditions:
            try:
                # 限制读取前500KB防止大文件处理问题
                with open(file_info["file_path"], "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(500 * 1024)
                return any(pattern in content for pattern in conditions["content_patterns"])
            except Exception as e:
                print(f"[!] 文件内容扫描失败: {str(e)}")

        return False
    except Exception as e:
        print(f"[!] 条件匹配出错: {str(e)}")
        return False


def parse_size(size_str):
    """
    解析带单位的文件大小字符串(如10MB)
    :param size_str: 大小字符串
    :return: 字节数(int)
    """
    units = {
        "KB": 1024,
        "MB": 1024 ** 2,
        "GB": 1024 ** 3
    }
    size_str = str(size_str).upper().strip()

    for unit, multiplier in units.items():
        if unit in size_str:
            return int(float(size_str.replace(unit, "")) * multiplier)
    return int(size_str)  # 无单位默认为字节


def handle_file_upload(file_path, upload_directory, mime_type=None, source_ip=None):
    """
    文件上传处理主流程
    :param file_path: 文件绝对路径
    :param upload_directory: 上传目录根路径
    :param mime_type: 可选MIME类型
    :param source_ip: 可选来源IP
    """
    try:
        if not os.path.exists(file_path):
            print(f"[!] 文件不存在: {file_path}")
            return

        # 提取文件信息
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_hash = calculate_file_hash(file_path)  # SHA256计算
        rel_path = os.path.relpath(file_path, upload_directory)

        # 构建文件信息字典
        file_info = {
            "file_name": file_name,
            "file_path": file_path,
            "file_size": file_size,
            "mime_type": (mime_type or get_mime_type(file_path)),
            "upload_directory": upload_directory,
            "relative_path": rel_path,
            "file_hash": file_hash,
            "source_ip": source_ip or "N/A",
            "file_hash_count": update_file_hash_count(file_hash),  # 更新哈希计数器
            "timestamp": datetime.now().isoformat()
        }

        # 执行规则匹配
        for rule in rules:
            if matches_conditions(rule["conditions"], file_info):
                log_alert(rule, file_info)  # 记录告警
                take_action(rule, file_info)  # 执行防御动作

    except Exception as e:
        print(f"[!] 文件处理错误: {str(e)}")


def get_mime_type(file_path):
    """使用mimetypes库猜测文件MIME类型"""
    import mimetypes
    mime, _ = mimetypes.guess_type(file_path)
    return mime or "application/octet-stream"  # 默认二进制类型


def calculate_file_hash(file_path, chunk_size=8192):
    """
    计算文件SHA256哈希值（分块处理大文件）
    :param file_path: 文件路径
    :param chunk_size: 读取块大小(默认8KB)
    :return: 哈希值字符串
    """
    import hashlib
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[!] 文件哈希计算失败: {str(e)}")
        return ""


# 全局哈希计数器（用于检测重复上传）
file_hash_counts = defaultdict(int)
file_hash_timestamps = defaultdict(list)
FILE_HASH_WINDOW = timedelta(minutes=5)  # 5分钟检测窗口


def update_file_hash_count(file_hash):
    """
    更新文件哈希出现次数（基于时间窗口）
    :param file_hash: 文件哈希值
    :return: 当前计数
    """
    now = datetime.now()
    # 清理过期记录（滑动窗口）
    file_hash_timestamps[file_hash] = [
        t for t in file_hash_timestamps[file_hash]
        if now - t < FILE_HASH_WINDOW
    ]
    file_hash_timestamps[file_hash].append(now)  # 添加新记录
    count = len(file_hash_timestamps[file_hash])
    file_hash_counts[file_hash] = count
    return count


def log_alert(rule, file_info):
    """
    生成结构化告警日志
    :param rule: 触发规则
    :param file_info: 文件信息
    """
    alert_msg = [
        f"\n[!] {datetime.now().isoformat()} 文件上传告警 ({rule['severity'].upper()})",
        f"规则ID: {rule['rule_id']}",
        f"描述: {rule['description']}",
        f"文件名: {file_info['file_name']}",
        f"文件大小: {file_info['file_size'] / 1024:.2f}KB",
        f"文件路径: {file_info['relative_path']}",
        f"哈希值: {file_info['file_hash'][:8]}...",
        f"MIME类型: {file_info['mime_type']}",
        "=" * 60
    ]
    print("\n".join(alert_msg))

    # 写入日志文件（追加模式）
    with open("file_upload_alerts.log", "a", encoding="utf-8") as f:
        f.write("\n".join(alert_msg) + "\n\n")


def take_action(rule, file_info):
    """
    根据规则严重级别执行响应动作
    :param rule: 触发规则
    :param file_info: 文件信息
    """
    # 动作映射表
    actions = {
        "critical": quarantine_file,  # 隔离文件
        "high": rename_file,  # 重命名文件
        "medium": log_only  # 仅记录
    }
    action = actions.get(rule.get("severity", "medium"), log_only)
    action(file_info)


def quarantine_file(file_info):
    """将危险文件移动到隔离区"""
    # 创建 quarantine 子目录
    quarantine_dir = os.path.join(os.path.dirname(file_info["upload_directory"]), "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)

    # 新文件名格式：哈希_原文件名
    new_path = os.path.join(quarantine_dir, f"{file_info['file_hash']}_{file_info['file_name']}")
    os.rename(file_info["file_path"], new_path)
    print(f"[!] 已隔离文件到: {new_path}")


def rename_file(file_info):
    """重命名可疑文件（添加blocked前缀）"""
    new_name = f"blocked_{file_info['file_hash'][:8]}_{file_info['file_name']}"
    new_path = os.path.join(os.path.dirname(file_info["file_path"]), new_name)
    os.rename(file_info["file_path"], new_path)
    print(f"[!] 已重命名文件为: {new_name}")


def log_only(file_info):
    """仅记录不处理（用于测试模式）"""
    print(f"[*] 已记录可疑文件: {file_info['file_name']}")


class FileUploadHandler(FileSystemEventHandler):
    """自定义文件系统事件处理器"""

    def __init__(self, upload_directory, rules):
        self.upload_directory = upload_directory
        self.rules = rules

    def on_created(self, event):
        """处理文件创建事件"""
        if not event.is_directory:  # 忽略目录创建
            handle_file_upload(event.src_path, self.upload_directory)


def monitor_uploads(upload_directory, rules):
    """
    启动文件监控守护进程
    :param upload_directory: 监控目录路径
    :param rules: 检测规则列表
    """
    observer = Observer()
    handler = FileUploadHandler(upload_directory, rules)
    observer.schedule(handler, upload_directory, recursive=True)  # 递归监控子目录
    observer.start()
    print(f"[*] 开始监控上传目录: {upload_directory}")
    try:
        while True:  # 保持主线程运行
            pass
    except KeyboardInterrupt:
        observer.stop()  # Ctrl+C停止监控
    observer.join()  # 等待观察者线程结束


def main():
    """主程序入口"""
    global rules
    rules = load_rules("file_upload_attack_detection_rules.json")  # 加载规则

    # 设置监控目录（示例使用PHP上传目录）
    upload_directory = os.path.abspath("D:/phpstudy_pro/WWW/upload/upload/")
    if not os.path.exists(upload_directory):
        os.makedirs(upload_directory)
        print(f"[*] 创建上传目录: {upload_directory}")

    monitor_uploads(upload_directory, rules)  # 启动监控


if __name__ == "__main__":
    main()
