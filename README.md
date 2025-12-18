# Neutic
This project focuses on the cutting-edge issue of encrypting TLS traffic classification on cloud platforms, and conducts research on the NeuTic method published in IEEE/ACM Transactions on Networking

"""

项目名称：云平台上的加密 TLS 流量分类

姓名：黄宇琳

生成时间：2025-12-05 

"""

## 项目说明

由于算力和时间复杂度等原因，仅进行了验证NeuTic在常规和特定场景下的整体分类准确率的实验。其他两个实验未进行验证①使用LIME工具解释NeuTic的决策依据，理解哪些特征更重要②证明NeuTic相对于其他前沿方法的优越性

每个NeuTic-main项目文件中包含源码、运行代码截图、训练过程（模型文件太大没有上传，数据集有需要的话自己重新采集，这里不再上传）

dataset1是验证NeuTic对六个应用的分类效果（字节和阿里各三个app），dataset2是验证Neutic对具有相同使用类别的移动应用的性能指标（来自同一家公司的三个应用）

数据集命名使用的是中文拼音首字母缩写，其中字节旗下数据集重复多次采集（抖音极速版、抖音火山版、抖音、头条、西瓜视频）对应关系：dy->抖音 dyhs->抖音火山版 dyjs->抖音极速版 tt->今日头条 xg->西瓜视频 elm->饿了么 yk->优酷2 tpp->淘票票 

## 项目结构

```python
复现代码/
├── dataset1/           # 两家公司六个app
│   └──  NeuTic-main/    #
└── dataset2		   # 每家公司3个应用分类
	├── NeuTic-main - alibaba    # 阿里集团
	└── NeuTic-main-bytedance   # 字节跳动
```

```python
NeuTic-main/
├── data/               # 原始数据和预处理后的数据
│   ├── processed/     # 处理后的 .npy 文件
│   ├── raw_anon_pro/           # 数据脱敏后的数据包pcap文件
│   └── split_flows/           # 流量切割后的pcap文件
├── neutic/            # 模型核心代码
│   ├── __init__.py
│   ├── Constants.py
│   ├── Models.py
│   ├── Layers.py
│   ├── SubLayers.py
│   └── Modules.py
├── photo             #运行代码时的部分截图
├── scripts/           # 数据处理脚本
│   ├── config.py			#模型配置文件
│   ├── split_flows.py		# 流量切割 
│   ├── extract_features.py	 #特征提取
│   └── test.py			# 测试脚本 
├── anonymize.py		#数据脱敏脚本
├── best_model.pth   #训练好模型权重文件 
├── confusion_matrix.png   #混淆矩阵 
├── epoch_details.txt   #每轮训练的结果 
├── requirements.txt   # 依赖库列表
├── test_results.npy   #测试集上的预测结果 
└── train.py           # 主训练脚本
```



## 项目执行顺序

```py
进入NeuTic-main目录下

pip install -r requirements.txt

cd scripts

python split_flows.py

python extract_features.py

进入scripts/config.py

将上一步记下的三个最大值，填入对应的 vocab_size 配置项。

  len_vocab_size = 10010  **# 改为实际的“包长最大值” + 少量余量（如+10）**

  win_vocab_size = 65536  **# 改为实际的“窗口大小最大值” + 1**

  flag_vocab_size = 32   **# 改为实际的“TCP标志最大值” + 1 (通常取2的幂)**

cd 上一级目录

python train.py
```



提交的数据包中模型已经训练好，直接输入以下指令验证即可。

（提交的训练模型文件是使用的原始数据集训练的，运行上面的代码是从头开始重新训练，数据脱敏后重新训练可能与提交的结果有一些出入；运行以下代码是直接验证已经训练好的模型，可以直接复现）

```
pip install -r requirements.txt

python train.py
```



## 数据集

### 数据隐私保护声明

本项目所涉及到的数据集均为真实的，由于个人隐私的考虑，本项目使用的网络流量数据不再上传，仅给出项目结构

### 来源

使用**PCAPdroid**在手机上进行抓包，关闭手机后台其他应用，

选择目标应用：

字节跳动：西瓜、头条、抖音极速版

阿里巴巴：优酷，饿了么，淘票票

### 划分

1. **比例**：按照 **7：1.5：1.5** 的比例，将总数据集划分为：
   - **训练集**：用于模型参数训练。
   - **验证集**：用于训练过程中的超参数调优和早停判断。
   - **测试集**：用于最终评估模型的泛化性能，在整个实验过程中**只使用一次**。

未采用交叉验证，而是把所有数据**一次性**随机分成三份（训练/验证/测试），用这一份固定的测试集得出最终准确率。

## 实验环境

- **CPU**

- **操作系统**：Windows 11

- **编程语言**：Python 3.10

- **核心框架**：PyTorch 2.9.1+cpu

- **关键依赖库**：

  torch>=1.9.0

  torchvision>=0.10.0

  numpy>=1.21.0

  scapy>=2.4.5

  pandas>=1.3.0

  scikit-learn>=0.24.0

  tqdm>=4.62.0

  pyyaml>=5.4.0

