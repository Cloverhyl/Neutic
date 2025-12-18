"""
项目名称：云平台上的加密 TLS 流量分类
姓名：黄宇琳
生成时间：2025-12-05  
"""
# scripts/extract_features.py
import numpy as np
import os
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
import datetime

def extract_features_from_flow(flow_pcap_path, max_packets=12):
    """从单个流pcap文件中提取特征序列"""
    try:
        packets = rdpcap(flow_pcap_path)
    except Exception as e:
        print(f"  读取文件失败 {flow_pcap_path}: {e}")
        return None

    len_seq, win_seq, flag_seq = [], [], []

    for i, pkt in enumerate(packets[:max_packets]):  # 只取前 max_packets 个包
        if IP in pkt:
            pkt_len = pkt[IP].len
            len_seq.append(pkt_len)

            if TCP in pkt:
                win_seq.append(pkt[TCP].window)
                flag_seq.append(pkt[TCP].flags.value)
            else:
                # 非TCP包用0填充
                win_seq.append(0)
                flag_seq.append(0)
        else:
            # 非IP包用0填充
            len_seq.append(0)
            win_seq.append(0)
            flag_seq.append(0)

    # 填充：如果流的包数不足max_packets，用0补全
    while len(len_seq) < max_packets:
        len_seq.append(0)
        win_seq.append(0)
        flag_seq.append(0)

    # 返回形状为 (3, 12) 的数组
    return np.array([len_seq, win_seq, flag_seq], dtype=np.int64)

def build_dataset(split_flows_dir):
    """遍历所有切割后的流，构建完整数据集"""
    X_list = []  # 特征列表
    y_list = []  # 标签列表

    # 遍历每个应用文件夹
    for app_name in sorted(os.listdir(split_flows_dir)):
        app_dir = os.path.join(split_flows_dir, app_name)
        if not os.path.isdir(app_dir):
            continue

        print(f"正在提取应用 '{app_name}' 的特征...")
        flow_count = 0

        # 遍历该应用的所有流文件
        for flow_file in sorted(os.listdir(app_dir)):
            if flow_file.endswith('.pcap'):
                flow_path = os.path.join(app_dir, flow_file)
                features = extract_features_from_flow(flow_path)

                if features is not None:
                    X_list.append(features)
                    y_list.append(app_name)  # 标签就是文件夹名
                    flow_count += 1

        print(f"  完成，共提取 {flow_count} 个流样本。")

    # 转换为Numpy数组
    X_array = np.array(X_list, dtype=np.int64)  # 形状: (总样本数, 3, 12)
    y_array = np.array(y_list)

    return X_array, y_array

if __name__ == "__main__":
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("="*50)
    print("项目名称：云平台上的加密 TLS 流量分类")
    print("姓名：黄宇琳")
    print(f"当前系统时间：{current_time}")
    print("="*50)
    
    split_flows_dir = "../data/split_flows"
    output_dir = "../data/processed"
    os.makedirs(output_dir, exist_ok=True)

    print("开始构建数据集...")
    X_data, y_labels = build_dataset(split_flows_dir)

    # 保存数据集
    np.save(os.path.join(output_dir, "X_data.npy"), X_data)
    np.save(os.path.join(output_dir, "y_labels.npy"), y_labels)

    print("\n" + "="*50)
    print("数据集构建完成！")
    print(f"特征数据 X_data 形状: {X_data.shape}")
    print(f"标签数据 y_labels 形状: {y_labels.shape}")
    print(f"标签类别: {np.unique(y_labels)}")

    # **重要：打印特征最大值，用于下一步配置模型**
    print("\n【请记下以下三个值，下一步配置需要】")
    print(f"包长最大值: {X_data[:, 0, :].max()}")
    print(f"窗口大小最大值: {X_data[:, 1, :].max()}")
    print(f"TCP标志最大值: {X_data[:, 2, :].max()}")
    print(f"\n数据已保存至: {output_dir}")