"""
项目名称：云平台上的加密 TLS 流量分类
姓名：黄宇琳
生成时间：2025-12-05  
"""
# train.py
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset, random_split
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib
import datetime
matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
matplotlib.rcParams['axes.unicode_minus'] = False

# 导入我们自己的模块
from neutic.Models import NeuTic
from scripts.config import cfg

def load_and_split_data():
    """加载处理好的数据，并划分训练集、验证集、测试集"""
    X = np.load('./data/processed/X_data.npy')
    y = np.load('./data/processed/y_labels.npy', allow_pickle=True)

    # 将字符串标签映射为数字
    label_to_id = {label: idx for idx, label in enumerate(np.unique(y))}
    id_to_label = {idx: label for label, idx in label_to_id.items()}
    y_encoded = np.array([label_to_id[label] for label in y])

    # 转换为PyTorch张量
    X_tensor = torch.LongTensor(X)  # 形状: (N, 3, 12)
    y_tensor = torch.LongTensor(y_encoded)  # 形状: (N,)

    # 创建位置编码张量 (模型需要)：简单的 [0, 1, 2, ..., 11]
    pos_tensor = torch.arange(cfg.h).unsqueeze(0).repeat(X_tensor.size(0), 1)  # (N, 12)

    # 合并为一个数据集
    dataset = TensorDataset(X_tensor, pos_tensor, y_tensor)

    # 计算划分大小
    total_len = len(dataset)
    train_len = int(cfg.train_ratio * total_len)
    val_len = int(cfg.val_ratio * total_len)
    test_len = total_len - train_len - val_len

    # 随机划分
    train_set, val_set, test_set = random_split(
        dataset, [train_len, val_len, test_len],
        generator=torch.Generator().manual_seed(42)  # 设置随机种子保证结果可复现
    )

    print(f"数据加载完成，总共 {total_len} 个样本。")
    print(f"划分结果: 训练集 {train_len}, 验证集 {val_len}, 测试集 {test_len}")
    print(f"标签映射: {label_to_id}\n")

    return train_set, val_set, test_set, id_to_label

def train_one_epoch(model, loader, criterion, optimizer, device, epoch):  # 修改1：添加epoch参数
    """训练一个epoch"""
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0

    for batch_idx, (X_batch, pos_batch, y_batch) in enumerate(loader):  # 修改2：使用enumerate获取batch_idx
        # 将数据移至设备
        len_seq = X_batch[:, 0, :].to(device)  # 包长序列
        win_seq = X_batch[:, 1, :].to(device)  # 窗口序列
        flag_seq = X_batch[:, 2, :].to(device) # 标志序列
        src_seq = (len_seq, win_seq, flag_seq)
        pos_batch = pos_batch.to(device)
        y_batch = y_batch.to(device)

        # 前向传播
        optimizer.zero_grad()
        outputs = model(src_seq, pos_batch)
        loss = criterion(outputs, y_batch)

        # 反向传播
        loss.backward()
        
        # 在 loss.backward() 后，optimizer.step() 前插入
        total_norm = 0.0
        for name, param in model.named_parameters():
            if param.grad is not None:
                param_norm = param.grad.data.norm(2) # 计算该参数梯度的L2范数
                total_norm += param_norm.item() ** 2
                # 可选：打印每个层的梯度范数，定位问题层
                # if param_norm.item() < 1e-6:
                #     print(f'   [{name}] 梯度极小: {param_norm.item():.6f}')
        total_norm = total_norm ** 0.5
        #print(f'   [Epoch {epoch+1}, Batch {batch_idx}] 梯度总范数: {total_norm:.6f}')  # 现在epoch和batch_idx都已定义
        
        optimizer.step()

        # 统计
        total_loss += loss.item() * y_batch.size(0)
        _, predicted = torch.max(outputs, 1)
        total += y_batch.size(0)
        correct += (predicted == y_batch).sum().item()

    avg_loss = total_loss / total
    accuracy = 100.0 * correct / total
    return avg_loss, accuracy

def evaluate(model, loader, criterion, device, label_names):
    """在验证集或测试集上评估模型"""
    model.eval()
    total_loss = 0.0
    all_preds = []
    all_labels = []

    with torch.no_grad():
        for X_batch, pos_batch, y_batch in loader:
            len_seq = X_batch[:, 0, :].to(device)
            win_seq = X_batch[:, 1, :].to(device)
            flag_seq = X_batch[:, 2, :].to(device)
            src_seq = (len_seq, win_seq, flag_seq)
            pos_batch = pos_batch.to(device)
            y_batch = y_batch.to(device)

            outputs = model(src_seq, pos_batch)
            loss = criterion(outputs, y_batch)

            total_loss += loss.item() * y_batch.size(0)
            _, predicted = torch.max(outputs, 1)

            all_preds.extend(predicted.cpu().numpy())
            all_labels.extend(y_batch.cpu().numpy())

    avg_loss = total_loss / len(loader.dataset)
    accuracy = 100.0 * (np.array(all_preds) == np.array(all_labels)).sum() / len(all_labels)

    # 计算详细评估指标
    print("\n" + "="*60)
    print("详细分类报告:")
    print(classification_report(all_labels, all_preds, target_names=label_names, digits=4))

    # 绘制混淆矩阵
    cm = confusion_matrix(all_labels, all_preds)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=label_names, yticklabels=label_names)
    plt.ylabel('真实标签')
    plt.xlabel('预测标签')
    plt.title('混淆矩阵')
    plt.tight_layout()
    plt.savefig('./confusion_matrix.png')
    print("混淆矩阵已保存为 'confusion_matrix.png'")

    return avg_loss, accuracy, all_preds, all_labels

def main():
     # 控制台输出项目信息（动态获取当前时间）
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("="*60)
    print("项目名称：云平台上的加密 TLS 流量分类")
    print("姓名：黄宇琳")
    print(f"当前系统时间：{current_time}")
    print("="*60)
    
    print("开始 NeuTic 模型训练与验证")
    print(f"使用设备: {cfg.device}")
    print("="*60)
    print("="*60)
    print("开始 NeuTic 模型训练与验证")
    print(f"使用设备: {cfg.device}")
    print("="*60)

    # 1. 加载数据
    train_set, val_set, test_set, id_to_label = load_and_split_data()
    label_names = [id_to_label[i] for i in range(len(id_to_label))]

    train_loader = DataLoader(train_set, batch_size=cfg.batch_size, shuffle=True)
    val_loader = DataLoader(val_set, batch_size=cfg.batch_size, shuffle=False)
    test_loader = DataLoader(test_set, batch_size=cfg.batch_size, shuffle=False)

    # 2. 初始化模型
    model = NeuTic(
        n_src_vocab=(cfg.len_vocab_size, cfg.win_vocab_size, cfg.flag_vocab_size),
        h=cfg.h,
        grained=cfg.num_classes,
        d_word_vec=cfg.d_word_vec,
        d=cfg.d,
        d_inner=cfg.d_inner,
        L=cfg.L,
        n_head=cfg.n_head,
        d_k=cfg.d_k,
        d_v=cfg.d_v,
        dropout=cfg.dropout
    ).to(cfg.device)

    print(f"模型总参数量: {sum(p.numel() for p in model.parameters()):,}")

    # 3. 定义损失函数和优化器
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=cfg.learning_rate)

    # 4. 训练循环
    print("\n开始训练...")
    best_val_acc = 0.0
    best_model_state = None

    for epoch in range(cfg.num_epochs):
        # 训练一个epoch - 修改3：传入epoch参数
        train_loss, train_acc = train_one_epoch(model, train_loader, criterion, optimizer, cfg.device, epoch)

        # 在验证集上评估
        val_loss, val_acc, _, _ = evaluate(model, val_loader, criterion, cfg.device, label_names)

        print(f"Epoch [{epoch+1:02d}/{cfg.num_epochs}] | "
              f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}% | "
              f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}%")

        # 保存最佳模型
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            best_model_state = model.state_dict().copy()
            torch.save(best_model_state, './best_model.pth')
            print(f"   -> 保存新的最佳模型，验证准确率: {val_acc:.2f}%")

    # 5. 加载最佳模型并在测试集上最终评估
    print("\n" + "="*60)
    print("在测试集上进行最终评估...")
    model.load_state_dict(torch.load('./best_model.pth'))
    test_loss, test_acc, test_preds, test_labels = evaluate(
        model, test_loader, criterion, cfg.device, label_names
    )

    print(f"\n测试集结果 -> 损失: {test_loss:.4f}, 准确率: {test_acc:.2f}%")

    # 6. 核心成功判断（针对你的验证目标）
    print("\n" + "="*60)
    print("【复现成功与否的关键判断】")
    print(" 基础学习能力：测试准确率应显著高于随机猜测 (33.33%)。")
    print(f"   结果: {test_acc:.2f}% {'✅' if test_acc > 40.0 else '⚠️'}")

    # 7. 保存最终预测结果（可选）
    results = {
        'true_labels': test_labels,
        'pred_labels': test_preds,
        'label_mapping': id_to_label,
        'test_accuracy': test_acc
    }
    np.save('./test_results.npy', results)
    print(f"\n所有结果已保存。")

if __name__ == '__main__':
    main()