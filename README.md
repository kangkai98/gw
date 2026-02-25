# AI 网关 Demo（纯 Python + 原生前端，无需 npm）

## 目标

- 命令行仅用于启动服务
- 网页完成 pcap 上传、记录清空、自建 AI 配置
- 无需 npm install，也能提供较“苹果风格”的界面
- 支持统计图表展示（分类分布环图 + 分类时延条形图）

## 启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m ai_gateway_demo --port 8000
```

打开：`http://127.0.0.1:8000`

## 页面功能

- 上传 PCAP：自动识别 AI 流并入库
- 清空 Entry：会重置数据库序号
- 自建 AI 配置：按 IP 维护小类映射；支持删除和一键清空（序号重置）

## 图表

- **分类分布环图**：按大类（自建AI/三方AI/实验AI）展示 Entry 数占比
- **时延条形图**：按大类展示 Avg TTFB / Avg TTFT / Avg Latency（ms）

## 指标

- 真实开始/结束时间：`YYYY-MM-DD HH:MM:SS`
- 相对开始时间：`s`
- TTFB / TTFT / Latency：`ms`（保留 1 位小数）
- TPOT：`ms/token`（保留 1 位小数）

### TTFB 与 TTFT 区分

- TTFB：开始到首个下行响应报文
- TTFT：开始到首个“含回答 token”的下行报文
- 防御逻辑：不会出现负值，并保证 `TTFT >= TTFB`
