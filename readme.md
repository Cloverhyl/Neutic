# FS-Net 加密流量分类实验 (6 应用分类)

本项目基于 FS-Net (Flow Sequence Network) 模型，对来自 6 个主流移动应用（饿了么、淘票票、优酷、今日头条、抖音、西瓜视频）的原始 pcap 数据包进行加密流量分类。

## 📖 项目背景
由于云平台泛域名证书（如 `*.alicdn.com`）导致传统基于证书的识别方法失效（如 MAAF），本项目采用 FS-Net 架构，将网络流转化为**包长度序列**与**方向序列**，利用深度学习（GRU + 编码器-解码器）自动提取流量行为特征，从而实现端到端的加密流量识别。

## 🗂 数据集对应关系
请将原始的 6 个 pcap 文件放入 `pcaps/` 文件夹，命名必须严格对应下表：

| 文件名 | 应用名称 | 英文缩写 |
| :--- | :--- | :--- |
| `elm.pcap` | 饿了么 | elm |
| `tpp.pcap` | 淘票票 | tpp |
| `yk.pcap` | 优酷 | yk |
| `tt.pcap` | 今日头条 | tt |
| `dy.pcap` | 抖音短视频 | dy |
| `xg.pcap` | 西瓜视频 | xg |

## ⚙️ 环境要求与安装
### 1. 基础环境
- Python 3.8 或 3.9
- 建议使用虚拟环境 (venv)

### 2.项目结构
先将原始 pcap 文件放入 `pcaps/` 文件夹，命名必须严格对应下表。

```
.
├── pcaps/                      # 存放原始 pcap 文件
│   ├── elm.pcap
│   ├── tpp.pcap
│   └── ...
├── processed_data/             # 预处理生成的序列文件 (自动生成)
│   ├── elm_train.num
│   ├── elm_val.num
│   └── elm_test.num
├── preprocess.py               # 预处理脚本
├── model.py                    # FS-Net 网络结构定义
├── train.py                    # 训练脚本 (含验证集与早停)
├── evaluate.py                 # 最终评估脚本 (仅运行一次)
├── check_env.py                # 环境依赖检查脚本
├── requirements.txt            # 依赖包清单
├── fsnet_best_model.pth        # 训练好的最佳模型权重 (生成)
├── confusion_matrix.png        # 混淆矩阵可视化图 (生成)
└── README.md                   # 指导文件
```



### 3. 执行程序
在项目根目录下执行：
```bash
pip install numpy pandas scipy matplotlib scikit-learn scapy torch tqdm
python preprocess.py
python train.py
python evaluate.py
```