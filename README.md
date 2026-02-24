# AI 网关 Demo

## 你现在可以这样用

命令行只负责拉起网页服务：

```bash
python -m ai_gateway_demo --port 8000
```

然后在网页里完成：

- 上传 pcap 并入库
- 清除历史记录
- 配置自建 AI（IP + 小类名称）

## 识别与分类规则

每条 entry 包含：

- 大类：`三方AI` / `自建AI` / `实验AI`
- 小类：
  - 三方AI：如 `qwen api`、`豆包 app`（由 payload 关键词识别）
  - 自建AI：来自网页配置（按服务端 IP 命中）
  - 实验AI：未配置但被算法识别为 AI 流，从 payload 抽取小类文本

## 时间与单位

每条 entry 同时保存：

- 真实开始时间：`start_time_dt`（年月日 时分秒毫秒）
- 真实结束时间：`end_time_dt`
- 相对开始时间：`start_time_s`（相对 pcap 起点，单位 s）
- TTFB / TTFT / Latency：单位 `ms`
- TPOT：单位 `ms/token`

以上时间指标统一保留 **1 位小数**（相对开始时间也是 1 位小数）。

## 页面功能

- 设计化控制台 UI
- 总览卡片：总 entry、总 token、RPS
- 按大类统计
- Entry 明细表（含真实开始/结束时间 + 相对开始时间）
