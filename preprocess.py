import os
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP
from sklearn.model_selection import train_test_split

# ---------- 配置 ----------
PCAP_DIR = "./pcaps"
OUTPUT_DIR = "./processed_data"
MAX_PACKETS = 50
RANDOM_SEED = 42

# 拆分比例：7 : 1.5 : 1.5
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

APP_NAMES = {
    "elm": "饿了么",
    "tpp": "淘票票",
    "yk": "优酷",
    "tt": "头条",
    "dy": "抖音",
    "xg": "西瓜视频"
}

os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_flows(pcap_path):
    """提取双向流"""
    packets = rdpcap(pcap_path)
    flows = defaultdict(list)

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = tcp.sport
            dst_port = tcp.dport
            proto = ip.proto

            if src_ip > dst_ip or (src_ip == dst_ip and src_port > dst_port):
                flow_key = (dst_ip, src_ip, dst_port, src_port, proto)
                direction = 1
            else:
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                direction = 0

            flows[flow_key].append((len(pkt), direction))

    return list(flows.items())

def flow_to_fsnet_format(flow_packets):
    if len(flow_packets) < 5:  # 过滤太短的流
        return None
    packets = flow_packets[:MAX_PACKETS]
    status_seq = "\t".join(str(d) for _, d in packets)
    len_seq = "\t".join(str(length) for length, _ in packets)
    return f"{status_seq} ; {len_seq}"

def process_app(pcap_file, app_name):
    print(f"正在处理 {app_name} ({pcap_file})...")
    flows = extract_flows(pcap_file)
    print(f"  提取到 {len(flows)} 个流")

    records = []
    for _, packets in flows:
        line = flow_to_fsnet_format(packets)
        if line:
            records.append(line)
    print(f"  有效流数: {len(records)}")

    # ---------- 核心修改：先分出 30%，再从 30% 里对半分出验证和测试 ----------
    # 第一步：分出 70% 训练，剩下 30% 暂存
    train_records, temp_records = train_test_split(
        records, test_size=(VAL_RATIO + TEST_RATIO), random_state=RANDOM_SEED, shuffle=True
    )
    # 第二步：把 30% 对半分成 15% 验证 和 15% 测试
    val_records, test_records = train_test_split(
        temp_records, test_size=0.5, random_state=RANDOM_SEED, shuffle=True
    )

    # 保存三个文件
    with open(os.path.join(OUTPUT_DIR, f"{app_name}_train.num"), 'w') as f:
        f.write("\n".join(train_records))
    with open(os.path.join(OUTPUT_DIR, f"{app_name}_val.num"), 'w') as f:
        f.write("\n".join(val_records))
    with open(os.path.join(OUTPUT_DIR, f"{app_name}_test.num"), 'w') as f:
        f.write("\n".join(test_records))

    print(f"  ✅ 训练集: {len(train_records)}, 验证集: {len(val_records)}, 测试集: {len(test_records)}\n")

if __name__ == "__main__":
    print("开始预处理 (7:1.5:1.5 划分)...")
    for app in APP_NAMES.keys():
        pcap_file = os.path.join(PCAP_DIR, f"{app}.pcap")
        if os.path.exists(pcap_file):
            process_app(pcap_file, app)
        else:
            print(f"警告: 文件 {pcap_file} 不存在，跳过")
    print("预处理完成！")