# AI 网关 Demo（网页上传 PCAP + 可视化）

## 现在的使用方式

命令行只负责启动服务：

```bash
python -m ai_gateway_demo --port 8000
```

打开 `http://127.0.0.1:8000` 后可在网页完成：

- 上传 pcap 并入库
- 清空历史 entry
- 配置自建 AI 服务（IP + 小类名称）

## 指标定义（单位）

- 开始时间(真实)：`YYYY-MM-DD HH:MM:SS`
- 结束时间(真实)：`YYYY-MM-DD HH:MM:SS`
- 开始时间(相对)：`s`（相对 pcap 首包）
- TTFB / TTFT / Latency：`ms`
- TPOT：`ms/token`
- 所有时间型数值保留 1 位小数

## 分类规则

每条 entry 增加 `大类 + 小类`：

1. **自建AI**：命中网页中配置的服务端 IP，`小类=你配置的名称`
2. **三方AI**：命中关键词规则（例如 qwen api、doubao app、openai api）
3. **实验AI**：未配置且被算法识别为 AI 流，小类从 payload 中提取 host/sni/关键词

## 快速启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m ai_gateway_demo --port 8000
```
