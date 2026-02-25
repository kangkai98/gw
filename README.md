# AI 网关 Demo（Web-First + React 前端）

## 启动方式

后端只负责启动 API 与静态资源服务：

```bash
python -m ai_gateway_demo --port 8000
```

前端使用 **React + TypeScript + TailwindCSS + Framer Motion**，首次需要构建：

```bash
cd frontend
npm install
npm run build
cd ..
python -m ai_gateway_demo --port 8000
```

## 网页可完成操作

- 上传 pcap 并自动分析入库（不再手工传 AI IP、不再手工传切分阈值）
- 清空历史 entry（会重置自增序号）
- 管理自建 AI 配置（新增/删除/清空，清空会重置序号）

## 指标说明

- `start_time_real` / `end_time_real`: 真实时间（`YYYY-MM-DD HH:MM:SS`）
- `start_time_rel_s`: 相对 pcap 起点时间（秒）
- `ttfb_ms` / `ttft_ms` / `latency_ms`: 毫秒，保留 1 位小数
- `tpot_ms_per_token`: 毫秒每 token，保留 1 位小数

### TTFB 与 TTFT 区分策略

- **TTFB**：从开始时间到“首个下行响应报文”
- **TTFT**：从开始时间到“首个含回答 token 的下行报文”
- 对报文时间做非负约束，避免负值；TTFT 不会小于 TTFB。

## 分类体系（大类/小类）

- **自建AI**：命中用户配置的服务端 IP，`小类=配置名称`
- **三方AI**：按关键词规则识别（例如 qwen api、doubao app、openai api）
- **实验AI**：算法识别出的 AI 流，且未在前两类命中；小类从 payload 提取 host/sni/关键词
