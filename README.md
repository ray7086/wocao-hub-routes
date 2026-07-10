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

## Update workflow

`.github/workflows/update-routes.yml` 每四小时运行一次纯 Rust 发布器：

1. 通过 HTTPS 拉取上游订阅，最多跟随 5 次 HTTPS 跳转，并限制响应为 8MB。
2. 使用 XChaCha20-Poly1305 加密订阅正文。
3. 生成带版本、有效期和 SHA-256 的 `manifest.json`。
4. 使用 Ed25519 私钥签名清单。
5. 仅提交 `public/` 下的公开产物。

需要在仓库 Actions Secrets 中配置：

- `UPSTREAM_SUBSCRIPTION_URL`
- `ROUTE_ENCRYPTION_KEY_B64`
- `ROUTE_SIGNING_KEY_PEM`

私钥、原始订阅地址和解密密钥不得提交到 Git。本仓库公开的加密只能阻止直接浏览，不能对拥有官方客户端二进制的人员提供绝对保密。

## Artifact format

`routes.enc` 的二进制布局：

```text
8 bytes magic "WCRTE001"
24 bytes XChaCha20 nonce
remaining bytes ciphertext and authentication tag
```

固定附加认证数据为 `wocao-hub-routes/v1`。`routes.sig` 是对 `manifest.json` 原始字节的 Ed25519 Base64 签名；清单中的 `routeSha256` 绑定 `routes.enc`。
