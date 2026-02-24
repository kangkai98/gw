# AI 网关 Demo（PCAP -> 指标入库 -> Web 展示）

这个 demo 现在是**一条命令完成**：

1. 指定 pcap 文件。
2. 自动识别 AI 流（可选 `--ai-ip` 覆盖）。
3. 按 `--gap` 切分问答 entry。
4. 计算指标并写入 SQLite。
5. 自动拉起 Web 服务查看结果。

## 支持的指标（均带单位）

- 开始时间：相对 pcap 起点时间（s）
- TTFB（s）
- TTFT（s）
- Latency（s）
- TPOT（s/token）
- 输入/输出 token 数（count）

## 自动识别说明

- AI 流识别：
  - 若传入 `--ai-ip`，优先使用该 IP 匹配流。
  - 若未传入，先用 payload 中的 host/sni 关键词命中（如 qwen/dashscope、doubao/volcengine 等）；
  - 若仍无法命中，回退为 payload 字节最多的流。
- 来源识别：
  - 若传入 `--source`，直接使用；
  - 若未传入，按关键词自动识别；识别不到则标记 `auto:<server_ip>`。

## 快速运行

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 一条命令：导入 + 启动服务
python -m ai_gateway_demo --pcap sample_ai.pcap --gap 2 --port 8000
```

可选参数：

- `--source`：手工指定来源（可选）
- `--ai-ip`：手工指定 AI 服务器 IP（可选）
- `--gap`：问答切分阈值，默认 2 秒

打开 `http://127.0.0.1:8000`。

## 数据库

- SQLite 文件：`ai_gateway_demo.db`
- 表：`entries`
