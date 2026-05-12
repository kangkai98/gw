# AI 网关 Demo（纯 Python 启动，无需 npm）

## 启动方式

只需 Python 依赖，不需要 npm：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m ai_gateway_demo --port 8000
# 可选：启动时自动在线监听（需要抓包权限）
python -m ai_gateway_demo --port 8000 --listen-interface eth0 --listen-interval 60 --listen-filter "tcp"
```

打开 `http://127.0.0.1:8000`。

## 网页功能

- 仓库已移除未使用的 `frontend/` 脚手架代码，统一以 `ai_gateway_demo/templates` 页面为准
- 上传 pcap 并自动分析入库（无需手动 AI IP/阈值）
- 在线监听网卡流量：可在配置页填写网卡名/BPF过滤表达式，或通过 CLI 参数启动；默认每 60 秒生成一个抓包窗口并自动分析入库
- 清空历史 request（会重置自增序号）
- 管理自建 AI 配置（新增/删除/清空，清空会重置序号）
- 图表展示：
  - AI 类别分布（环形图）
  - 时延均值对比（柱状图：TTFB/TTFT/Latency）
  - 输入输出 Token（柱状图）
  - Request 数时间变化图（折线图）
- 支持按开始时间（真实时间）和 AI 大类进行筛选

## 在线监听模式

在线模式通过 `tcpdump` 按周期生成抓包窗口，运行进程需要具备抓包权限（例如 Linux 下使用 root、`CAP_NET_RAW`/`CAP_NET_ADMIN`，或提前配置抓包权限）。

- 页面启动后进入“配置”页，在“在线监听”中填写网卡名（如 `eth0`、`en0`、`any`）、分析周期（默认 `60` 秒）和 BPF 过滤表达式（默认 `tcp`），点击“开始监听”。
- 服务端会每个周期生成一个 `captures/online_YYYYMMDD_HHMMSS.pcap` 文件，周期结束后立即复用现有解析逻辑入库，页面每 10 秒刷新一次监听状态与最新结果。
- 也可以通过命令行自动启动：`python -m ai_gateway_demo --listen-interface eth0 --listen-interval 60 --listen-filter "tcp port 443"`。
- “停止监听”会结束当前 tcpdump 进程，并保留已经生成的窗口文件。

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


## 识别与切分算法（重构版）

- **多 AI 流识别**：先对每条双向 TCP 流抽取特征（SNI/Host 关键词命中、上下行字节平衡、token-like 下行报文、HTTPS 指纹、自建IP命中等），再计算 AI 相关性分数。
- **动态阈值选流**：不再只选 1 条流，而是采用 `max(14, top_score * 0.35)` 作为动态门限，选出同一 pcap 中多条高置信 AI 流；若都不达标再回退到 top1。
- **一问一答切分**：在单条 AI 流内，先基于上行请求报文间隔的中位数自适应计算阈值（约 `2.2 * median_gap`，下限 1s），识别请求起点；再按起点区间聚合对应下行响应形成 turn。
- **防误识别清洗**：仅保留 `latency > 0`、`ttft > 0`、`input_tokens > 0`、`output_tokens > 0` 的条目（解析层与入库层双重校验）。
