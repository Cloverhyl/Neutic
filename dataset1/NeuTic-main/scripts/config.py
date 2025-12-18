"""
项目名称：云平台上的加密 TLS 流量分类
姓名：黄宇琳
生成时间：2025-12-05  
"""

# scripts/config.py
import torch

class Config:
    """配置类，集中管理所有参数"""
    # === 数据参数 ===
    # 根据 extract_features.py 的输出设定下面三个值 
    len_vocab_size = 10010    # “包长最大值” + 少量余量（如+10）
    win_vocab_size = 65536   # “窗口大小最大值” + 1
    flag_vocab_size = 32     # “TCP标志最大值” + 1 (通常取2的幂)

    num_classes = 6          # 应用数：dy, tt, xg，yk，elm，tpp
    h = 12                   # 序列长度（取的包数）

    # === 模型结构参数 (与论文一致) ===
    d_word_vec = 512
    d = 512
    d_inner = 2048
    L = 2          # Self-Attention 层数
    n_head = 8
    d_k = 64
    d_v = 64
    dropout = 0.1

    # === 训练参数 (因为数据量小，必须调整以防过拟合) ===
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    batch_size = 32          # 论文是1024，我们数据小，必须调小
    learning_rate = 3e-4 
    num_epochs = 30          # 小数据可能很快收敛，不需要太多轮次
    train_ratio = 0.7        # 训练集比例
    val_ratio = 0.15         # 验证集比例
    # 测试集比例 = 1 - train_ratio - val_ratio

# 实例化配置对象
cfg = Config()