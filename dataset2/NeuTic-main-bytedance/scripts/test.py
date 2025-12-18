"""
项目名称：云平台上的加密 TLS 流量分类
姓名：黄宇琳
生成时间：2025-12-05  
"""
import numpy as np
X = np.load('./data/processed/X_data.npy')
y = np.load('./data/processed/y_labels.npy', allow_pickle=True)

# 检查全零样本
zero_samples = np.all(X == 0, axis=(1, 2))
print(f"【检查2-数据死亡】疑似无效（全零）样本数: {zero_samples.sum()} / {len(X)}")
if zero_samples.sum() > 0:
    print(f"   这些样本的标签是: {y[zero_samples]}")
    print("   如果过多，需要检查预处理脚本（01_split_flows.py）的切割逻辑。")

# 检查标签分布
unique, counts = np.unique(y, return_counts=True)
print(f"【检查3-标签分布】各类别样本数: {dict(zip(unique, counts))}")
print("   --> dy类别样本过少可能是其性能差的原因。")