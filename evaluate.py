import os
import torch
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, ConfusionMatrixDisplay
from torch.utils.data import DataLoader
from model import FS_Net
from train import FlowDataset, APP_NAMES, DATA_DIR, MAX_SEQ_LEN, BATCH_SIZE, EMBED_DIM, HIDDEN_DIM, NUM_LAYERS

def evaluate():
    # 加载测试集
    test_dataset = FlowDataset(APP_NAMES, DATA_DIR, mode='test')
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    # 加载模型
    vocab_size = 65536
    model = FS_Net(vocab_size, EMBED_DIM, HIDDEN_DIM, len(APP_NAMES), NUM_LAYERS)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.load_state_dict(torch.load("fsnet_best_model.pth", map_location=device))
    model.to(device)
    model.eval()

    all_preds = []
    all_labels = []

    with torch.no_grad():
        for batch_seq, batch_labels in test_loader:
            batch_seq = batch_seq.to(device)
            outputs = model(batch_seq)
            preds = torch.argmax(outputs, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(batch_labels.numpy())

    # 计算指标
    acc = accuracy_score(all_labels, all_preds)
    report = classification_report(all_labels, all_preds, target_names=APP_NAMES, digits=4)
    cm = confusion_matrix(all_labels, all_preds)

    print("="*60)
    print(f"🎯 总体准确率: {acc:.4f} ({acc*100:.2f}%)")
    print("="*60)
    print("\n📊 详细分类报告:")
    print(report)
    print("="*60)
    print("📈 混淆矩阵 (行:真实, 列:预测):")
    print(cm)

    # 可视化混淆矩阵
    fig, ax = plt.subplots(figsize=(8, 6))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=APP_NAMES)
    disp.plot(cmap=plt.cm.Blues, ax=ax, values_format='d')
    plt.title(f"Confusion Matrix (Accuracy: {acc:.2%})")
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig("confusion_matrix.png", dpi=300)
    print("\n🖼️ 混淆矩阵图已保存为 confusion_matrix.png")
    plt.show()   # 如果你的环境支持显示

if __name__ == "__main__":
    evaluate()