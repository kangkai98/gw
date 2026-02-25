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

- 上传 pcap 并自动分析入库（无需手动 AI IP/阈值）
- 清空历史 entry（会重置自增序号）
- 管理自建 AI 配置（新增/删除/清空，清空会重置序号）
- 图表展示：
  - 按大类 Entry 分布（环形图）
  - 时延均值对比（柱状图：TTFB/TTFT/Latency）

## 指标说明

- `start_time_real` / `end_time_real`: 真实时间（`YYYY-MM-DD HH:MM:SS`）
- `start_time_rel_s`: 相对 pcap 起点时间（秒）
- `ttfb_ms` / `ttft_ms` / `latency_ms`: 毫秒，保留 1 位小数
- `tpot_ms_per_token`: 毫秒每 token，保留 1 位小数

## TTFB 与 TTFT 区分策略

- **TTFB**：从开始时间到“首个下行响应报文”
- **TTFT**：从开始时间到“首个含回答 token 的下行报文”
- 使用非负约束避免负值；并保证 `TTFT >= TTFB`。
