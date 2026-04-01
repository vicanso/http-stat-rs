# http-stat-rs

模仿是最真诚的致敬。

纯 Rust 编写的**零依赖、单二进制**HTTP 诊断工具。一条命令可视化完整请求生命周期 — DNS 解析、TCP 连接、TLS 握手、服务端处理、内容传输 — 一目了然。参考了 [httpstat](https://github.com/davecheney/httpstat)。

![截图](./screenshot.png)

## 亮点

- **HTTP/1.1、HTTP/2 和 HTTP/3 (QUIC)** — 全面支持现代协议，一个参数即可切换
- **gRPC 健康检查** — 使用 `grpc://` 或 `grpcs://` 协议直接探测 gRPC 服务
- **多 IP 并发测试** — `--resolve` 同时测试多个 IP，结果按成功/失败排序
- **透明解压** — `--compressed` 自动解码 `gzip`、`br`、`zstd` 响应
- **自定义 DNS** — 指定 DNS 服务器 IP 或使用内置预设：`google`、`cloudflare`、`quad9`
- **TLS 证书检查** — verbose 模式展示完整证书链、密码套件、SAN 域名及有效期
- **curl 风格操作** — 熟悉的参数（`-H`、`-X`、`-d`、`-L`、`-k`、`-o`、`-4`/`-6`），无缝上手
- **极小体积** — release 构建采用 LTO + `opt-level=z` + strip，通常 < 5 MB

## 安装

### 预编译二进制

为 Windows、macOS 和 Linux 提供[预编译二进制文件](https://github.com/vicanso/http-stat-rs/releases)。

```bash
# Linux
curl -L https://github.com/vicanso/http-stat-rs/releases/latest/download/httpstat-linux-musl-$(uname -m).tar.gz | tar -xzf -
sudo mv httpstat /usr/local/bin/

# macOS
curl -L https://github.com/vicanso/http-stat-rs/releases/latest/download/httpstat-darwin-$(uname -m).tar.gz | tar -xzf -
sudo mv httpstat /usr/local/bin/
```

### 从源码安装

```bash
cargo install http-stat
```

## 使用示例

```bash
# 基础用法 — 通过 ALPN 自动协商 HTTP/2
httpstat https://www.cloudflare.com/

# HTTP/3 (QUIC) + 压缩响应
httpstat --http3 --compressed https://cloudflare-quic.com/

# 多 IP 并发测试，静默模式
httpstat --resolve=183.240.99.169,2409:8c54:870:310:0:ff:b0ed:40ac -s https://www.baidu.com/

# POST 请求，从文件读取请求体
httpstat -X POST -d @payload.json -H 'Content-Type: application/json' https://httpbin.org/post

# gRPC 健康检查
httpstat grpc://localhost:50051

# 详细模式 — 展示完整证书链和请求头
httpstat -v https://github.com

# 指定 DNS 服务器
httpstat --dns-servers=cloudflare https://example.com

# JSON 响应格式化输出
httpstat --pretty https://httpbin.org/get

# 设置超时时间
httpstat --timeout 5s https://example.com
```

## 选项

```
httpstat 以美观清晰的方式展示 curl(1) 的统计信息。

用法: httpstat [选项] [URL参数]

参数:
  [URL参数]  要请求的 URL

选项:
  -u, --url <URL>                  要请求的 URL（可选，可以作为最后一个参数提供）
  -H <HEADERS>                     设置 HTTP 头；可重复使用：-H 'Accept: ...' -H 'Range: ...'
  -4                               仅使用 IPv4 解析主机
  -6                               仅使用 IPv6 解析主机
  -k                               跳过 TLS 证书验证
  -o <OUTPUT>                      输出文件
  -L                               跟随 30x 重定向
  -X <METHOD>                      使用的 HTTP 方法（默认为 GET）
  -d, --data <DATA>                POST 或 PUT 请求的请求体；从文件读取使用 @filename
      --resolve <RESOLVE>          解析域名到指定 IP（例如 1.2.3.4,1.2.3.5）
      --compressed                 请求压缩响应：gzip, br, zstd
      --http3                      使用 HTTP/3
      --http2                      使用 HTTP/2
      --http1                      使用 HTTP/1.1
  -s                               静默模式，仅输出连接地址和结果
      --dns-servers <DNS_SERVERS>  指定 DNS 服务器，格式：8.8.8.8,8.8.4.4
  -v, --verbose                    详细模式
      --pretty                     格式化输出模式
      --timeout <TIMEOUT>          超时时间
  -h, --help                       显示帮助信息
  -V, --version                    显示版本信息
```

## 许可证

http-stat-rs 使用 MIT 许可证。详见 [LICENSE](LICENSE)。
