"""
项目名称：云平台上的加密 TLS 流量分类
姓名：黄宇琳
生成时间：2025-12-05  
"""
# scripts/split_flows.py
import os
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP
import datetime

def split_pcap(pcap_path, output_dir):
    """
    将一个pcap文件按网络流（五元组）切割成多个小pcap文件。
    """
    print(f"正在处理: {pcap_path}")
    packets = rdpcap(pcap_path)
    flows_dict = {}

    # 1. 按五元组（源IP、源端口、目的IP、目的端口、协议）对数据包进行分组
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            key = (pkt[IP].src, pkt[TCP].sport,
                   pkt[IP].dst, pkt[TCP].dport, 6)  # 6代表TCP协议
            if key not in flows_dict:
                flows_dict[key] = []
            flows_dict[key].append(pkt)

    # 2. 保存每个流
    app_name = os.path.splitext(os.path.basename(pcap_path))[0]  # 例如 ‘dy'
    app_output_dir = os.path.join(output_dir, app_name)
    os.makedirs(app_output_dir, exist_ok=True)

    saved_count = 0
    for i, flow_packets in enumerate(flows_dict.values()):
        # 可选：只保存包含足够多数据包的流，过滤掉极短的流
        if len(flow_packets) >= 4:
            flow_filename = os.path.join(app_output_dir, f"{app_name}_flow_{i:03d}.pcap")
            wrpcap(flow_filename, flow_packets)
            saved_count += 1
    print(f"  成功切割出 {saved_count} 个有效流，保存在 {app_output_dir}\n")
    return saved_count

if __name__ == "__main__":
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("="*50)
    print("项目名称：云平台上的加密 TLS 流量分类")
    print("姓名：黄宇琳")
    print(f"当前系统时间：{current_time}")
    print("="*50)
    
    # 路径配置
    raw_data_dir = "../data/raw_anon_pro"
    split_output_dir = "../data/split_flows"

    pcap_files = ["dy.pcap", "tt.pcap", "xg.pcap","tpp.pcap", "yk.pcap", "elm.pcap"]

    total_flows = 0
    


    for pcap_file in pcap_files:
        pcap_path = os.path.join(raw_data_dir, pcap_file)
        if os.path.exists(pcap_path):
            total_flows += split_pcap(pcap_path, split_output_dir)
        else:
            print(f"警告：未找到文件 {pcap_path}")

    print(f"所有文件处理完毕！总计生成 {total_flows} 个流文件。")