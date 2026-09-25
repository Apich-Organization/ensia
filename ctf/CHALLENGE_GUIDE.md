# 赛题指引：Ensia Secure Cryptographic Enclave

- **目标二进制**：`./challenge_obf`
- **总分**：1000 pts
- **运行环境**：Linux x86_64

---

## 任务目标与分值分布

本题包含 4 个相互耦合的密码学验证阶段。逆向分析程序逻辑，依次恢复各阶段密钥输入，并最终解密内存中的 Flag：

| 阶段 | 关卡目标 (Objective) | 输入格式规范 (Format) | 分值 (Score) |
| :--- | :--- | :--- | :---: |
| **Stage 1** | 激活密钥 (Activation Key) | `XXXX-XXXX-XXXX-XXXX`（16 字符大写/小写/数字） | **150 pts** |
| **Stage 2** | 轨道校准坐标 (Calibration Coordinates) | 4 个 32 位无符号整数（空格分隔，如 `a b c d`） | **200 pts** |
| **Stage 3** | 动态 Feistel 口令 (Feistel Passphrase) | 16 字节 ASCII 字符串 | **200 pts** |
| **Stage 4** | 终端封印令牌 (Sealing Token) | 8 字符十六进制字符串 | **150 pts** |
| **Final** | 核心 Enclave 解锁 Flag | `ensia{...}` 完整字符串 | **300 pts** |
| **总计** | | | **1000 pts** |

---

## 验证与提交流程

1. **执行程序**：
   ```bash
   ./challenge_obf
   ```
2. **通关判定**：
   - 4 个阶段采用非线性状态累加（State-Coupled Vector），任一阶段输入错误均会导致后续秘钥流雪崩偏移与内存清零。
   - 全部输入正确时输出：
     ```text
     [+] Enclave Unlocked! Verification Complete.
     [+] Flag: ensia{...}
     ```
3. **得分规则**：
   - 比赛平台支持按 Stage 1 ~ Stage 4 恢复的原始密钥独立计分。
   - 最终提交成功解密输出的 `ensia{...}` 获得通关分值。
