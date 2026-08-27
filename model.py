import torch
import torch.nn as nn

class FS_Net(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim, num_classes, num_layers=2):
        """
        vocab_size: 包长度的最大可能值（这里设为65536，足够覆盖正常包长）
        embed_dim: 嵌入维度
        hidden_dim: GRU隐藏层维度
        num_classes: 分类数
        num_layers: GRU层数
        """
        super(FS_Net, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.encoder = nn.GRU(embed_dim, hidden_dim, num_layers,
                              batch_first=True, bidirectional=True)
        self.decoder = nn.GRU(embed_dim, hidden_dim, num_layers,
                              batch_first=True, bidirectional=True)
        # 分类器：拼接编码器和解码器的最终隐藏状态（双向所以乘以2，再乘以2因为两个GRU）
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 4, hidden_dim * 2),
            nn.ReLU(),
            nn.Linear(hidden_dim * 2, num_classes)
        )

    def forward(self, x):
        # x: (batch, seq_len) 包长度序列
        embedded = self.embedding(x)                     # (batch, seq_len, embed_dim)

        # 编码器
        enc_output, enc_hidden = self.encoder(embedded)  # enc_hidden: (num_layers*2, batch, hidden_dim)

        # 解码器（这里用同样的输入做重构，旨在获取更多特征，但实际分类只用编码器也行，FS-Net官方使用了重构损失，
        # 但为简化，我们仅用编码器特征。为了对齐论文，我们保留解码器但不对其进行重构监督）
        dec_output, dec_hidden = self.decoder(embedded)

        # 取编码器和解码器的最终隐藏状态（最后一层的前向和后向拼接）
        # enc_hidden形状: (num_layers*2, batch, hidden_dim)
        # 取最后两层（因为双向，最后两维是前向和后向）
        enc_final = torch.cat((enc_hidden[-2], enc_hidden[-1]), dim=1)  # (batch, hidden_dim*2)
        dec_final = torch.cat((dec_hidden[-2], dec_hidden[-1]), dim=1)  # (batch, hidden_dim*2)

        combined = torch.cat((enc_final, dec_final), dim=1)  # (batch, hidden_dim*4)
        logits = self.classifier(combined)
        return logits