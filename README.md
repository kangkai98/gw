# AI 网关 Demo（纯 Python 启动，无需 npm）

## 启动方式

只需 Python 依赖，不需要 npm：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m ai_gateway_demo --port 8000
```

打开 `http://127.0.0.1:8000`。

## 网页功能

- 仓库已移除未使用的 `frontend/` 脚手架代码，统一以 `ai_gateway_demo/templates` 页面为准
- 上传 pcap 并自动分析入库（无需手动 AI IP/阈值）
- 清空历史 request（会重置自增序号）
- 管理自建 AI 配置（新增/删除/清空，清空会重置序号）
- 图表展示：
  - AI 类别分布（环形图）
  - 时延均值对比（柱状图：TTFB/TTFT/Latency）
  - 输入输出 Token 分布（柱状图）
  - Request 数时间变化图（折线图）
- 支持按开始时间（真实时间）和 AI 大类进行筛选

## 指标说明

- `start_time_real` / `end_time_real`: 真实时间（`YYYY-MM-DD HH:MM:SS`）
- `start_time_rel_s`: 相对 pcap 起点时间（秒）
- `ttfb_ms` / `ttft_ms` / `latency_ms`: 毫秒，保留 1 位小数
- `tpot_ms_per_token`: 毫秒每 token，保留 1 位小数

## TTFB 与 TTFT 区分策略

- **TTFB**：从开始时间到“首个下行响应报文”
- **TTFT**：从开始时间到“首个含回答 token 的下行报文”
- 使用非负约束避免负值；并保证 `TTFT >= TTFB`。


## 流分类策略

- 先按“自建 AI 配置 IP”命中为 `自建AI`。
- 未命中时，若为 HTTPS 流则优先基于 TLS SNI 识别 `三方AI`（如 qwen/doubao/openai）。
- 其余流归为 `实验AI`，并尝试从 payload 中提取小类。


## 数据清洗规则

- 会剔除明显异常的 request：`latency <= 0`、`ttft <= 0`、`输入 token = 0` 或 `输出 token = 0`。
