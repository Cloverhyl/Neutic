import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from model import FS_Net

# ---------- 配置 ----------
DATA_DIR = "./processed_data"
APP_NAMES = ["elm", "tpp", "yk", "tt", "dy", "xg"]
MAX_SEQ_LEN = 12
BATCH_SIZE = 1024
EPOCHS = 100             # 最大训练轮次，但早停会提前结束
LEARNING_RATE = 1e-4
EMBED_DIM = 128
HIDDEN_DIM = 256
NUM_LAYERS = 2

# 早停参数
PATIENCE = 30             # 验证集准确率连续 30 轮不提升则停止

# ---------- 数据集类 (支持 train/val/test) ----------
class FlowDataset(Dataset):
    def __init__(self, app_names, data_dir, mode='train'):
        self.samples = []
        self.labels = []
        self.max_len = MAX_SEQ_LEN

        for label, app in enumerate(app_names):
            file_path = os.path.join(data_dir, f"{app}_{mode}.num")
            if not os.path.exists(file_path):
                print(f"警告: {file_path} 不存在")
                continue
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(';')
                    if len(parts) != 2:
                        continue
                    len_seq_str = parts[1].strip()
                    if not len_seq_str:
                        continue
                    len_seq = [int(x) for x in len_seq_str.split('\t') if x.strip()]
                    if not len_seq:
                        continue
                    if len(len_seq) > self.max_len:
                        len_seq = len_seq[:self.max_len]
                    else:
                        len_seq = len_seq + [0] * (self.max_len - len(len_seq))
                    self.samples.append(len_seq)
                    self.labels.append(label)

        print(f"加载 {mode} 集: {len(self.samples)} 个样本")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        return (torch.tensor(self.samples[idx], dtype=torch.long),
                torch.tensor(self.labels[idx], dtype=torch.long))

# ---------- 训练主函数 ----------
def train():
    # 1. 加载数据
    train_dataset = FlowDataset(APP_NAMES, DATA_DIR, mode='train')
    val_dataset = FlowDataset(APP_NAMES, DATA_DIR, mode='val')
    test_dataset = FlowDataset(APP_NAMES, DATA_DIR, mode='test')

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)  # 只用于看实时进展，不参与调参

    # 2. 初始化模型
    vocab_size = 65536
    model = FS_Net(vocab_size, EMBED_DIM, HIDDEN_DIM, len(APP_NAMES), NUM_LAYERS)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE)
    criterion = nn.CrossEntropyLoss()

    # 3. 早停与保存记录
    best_val_acc = 0.0
    counter = 0          # 记录验证集不提升的次数
    best_model_state = None

    print(f"开始训练，早停耐心值为 {PATIENCE} 轮...")

    for epoch in range(1, EPOCHS + 1):
        # --- 训练阶段 ---
        model.train()
        total_loss = 0
        for batch_seq, batch_labels in train_loader:
            batch_seq, batch_labels = batch_seq.to(device), batch_labels.to(device)
            optimizer.zero_grad()
            outputs = model(batch_seq)
            loss = criterion(outputs, batch_labels)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        avg_train_loss = total_loss / len(train_loader)

        # --- 验证阶段 (Validation) ---
        model.eval()
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for batch_seq, batch_labels in val_loader:
                batch_seq, batch_labels = batch_seq.to(device), batch_labels.to(device)
                outputs = model(batch_seq)
                pred = torch.argmax(outputs, dim=1)
                val_correct += (pred == batch_labels).sum().item()
                val_total += batch_labels.size(0)
        val_acc = val_correct / val_total

        # --- 测试阶段 (仅观察，不参与早停决策，保证测试集的纯洁性) ---
        test_correct = 0
        test_total = 0
        with torch.no_grad():
            for batch_seq, batch_labels in test_loader:
                batch_seq, batch_labels = batch_seq.to(device), batch_labels.to(device)
                outputs = model(batch_seq)
                pred = torch.argmax(outputs, dim=1)
                test_correct += (pred == batch_labels).sum().item()
                test_total += batch_labels.size(0)
        test_acc = test_correct / test_total

        print(f"Epoch {epoch}/{EPOCHS} | Loss: {avg_train_loss:.4f} | Val Acc: {val_acc:.4f} | Test Acc(仅观察): {test_acc:.4f}")

        # --- 早停判断 (基于验证集) ---
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            counter = 0
            best_model_state = model.state_dict()
            torch.save(best_model_state, "fsnet_best_model.pth")
            print(f"  ✅ 验证集准确率提升至 {best_val_acc:.4f}，模型已保存")
        else:
            counter += 1
            print(f"  ⚠️ 验证集准确率未提升 ({counter}/{PATIENCE})")
            if counter >= PATIENCE:
                print(f"🛑 早停触发！训练在第 {epoch} 轮结束。")
                break

    print(f"\n训练结束，最佳验证集准确率为: {best_val_acc:.4f}")
    print("最佳模型权重已保存为 fsnet_best_model.pth")
    print("\n接下来请运行 evaluate.py 对测试集进行最终评估")

if __name__ == "__main__":
    train()