# SNIProbe — SNI 探针

## 简介

输入一个域名，自动跑完整检验——CDN 归属、TLS 1.3、X25519、证书 SAN 覆盖、连通性、握手延迟一次看全，最后给出一个综合结论，帮你提前排雷。

## 特性

- 6 步检测，自动输出综合判定（完美 / 可用 / 慎用 / 不可用）
- 自动区分 IPv4 / IPv6，本机无 IPv6 时会自动跳过 v6 测试，避免误报
- 支持防误报的 TLS 1.3 与 X25519 分开握手验证

## 依赖

标准 Linux 工具即可：`curl`、`openssl`、`getent`、`timeout`、`awk`、`grep`、`sed`。
（Debian/Ubuntu 建议：`apt install -y curl openssl net-tools`）

## 使用

### VPS 一键运行（无需下载，直接远程执行）

```bash
bash <(curl -sL https://raw.githubusercontent.com/lqlcj/SNIProbe/main/SNIProbe.sh)
```

VPS 上直接复制粘贴回车即可开始检测，不落地任何文件。

## 检测流程与判定

| 步骤 | 内容 | 判定角色 |
|------|------|---------|
| 1 | DNS 解析（IP 数量） | IP 超过 3 个时提示风险 |
| 2 | IP 归属查询（ipinfo.io） | 命中 CDN/云厂商黑名单 → 不可用 |
| 3 | TCP 443 通断（v4 全测，v6 视本机能力） | 有 IP 不通 → 慎用 |
| 4 | TLS 1.3 + X25519 + ALPN | TLS 1.3 / X25519 任一缺失 → 不可用（硬性要求） |
| 5 | 证书 SAN 是否覆盖该域名 | 未覆盖 → 可用但伪装稍弱 |
| 6 | TCP 握手延迟（3 次取最快） | 辅助参考 |

### 综合判定优先级

1. **不可用**：命中 CDN/云厂商黑名单，或不支持 TLS 1.3，或不支持 X25519
2. **慎用**：有 IP 443 不通（定时炸弹风险），或 IP 数量过多
3. **可用**：ALPN 非 h2，或证书 SAN 未覆盖域名
4. **完美**：全部硬指标通过，建议作为目标站点
