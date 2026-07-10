# Wocao Hub Routes

Wocao Hub 的独立静态路由发布仓库。

本仓库只发布供桌面客户端下载的版本化路由文件，不保存原始订阅地址、查询 Token、签名私钥或其他生产凭据。

## Planned public files

```text
public/
├── manifest.json
├── routes.enc
└── routes.sig
```

- `manifest.json`：版本、生成时间、有效期和文件哈希。
- `routes.enc`：加密后的路由数据。
- `routes.sig`：发布内容的 Ed25519 签名。

生成工具和自动更新工作流将在发布格式确定后加入。所有生产凭据只能通过 GitHub Actions Secrets 注入。
