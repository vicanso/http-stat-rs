# http-stat-rs

模仿是最真诚的致敬。

纯 Rust 版本的 HTTP 统计工具，参考了 [httpstat](https://github.com/davecheney/httpstat)。

- 支持http1， http2 以及 http3
- 默认的alpn是 `h2, http/1.1`
- 支持多种压缩算法：`gzip, br, zstd`

![截图](./screenshot.png)

## 发布版本

为 Windows、macOS 和 Linux 提供[预编译二进制文件](https://github.com/vicanso/http-stat-rs/releases)。

## 安装

```
cargo install http-stat
```

## 使用方法
```
httpstat --http3 https://cloudflare-quic.com/
```

## 功能特性

```bash
httpstat 以美观清晰的方式展示 curl(1) 的统计信息。

用法: httpstat [选项] [URL参数]

参数:
  [URL参数]  要请求的 URL

选项:
  -u, --url <URL>          要请求的 URL（可选，可以作为最后一个参数提供）
  -H <HEADERS>             设置 HTTP 头；可重复使用：-H 'Accept: ...' -H 'Range: ...'
  -4                       仅使用 IPv4 解析主机
  -6                       仅使用 IPv6 解析主机
  -k                       跳过 TLS 证书验证
  -o <OUTPUT>              输出文件
  -L                       跟随 30x 重定向
  -X <METHOD>              使用的 HTTP 方法（默认为 GET）
  -d, --data <DATA>        POST 或 PUT 请求的请求体；从文件读取使用 @文件名
      --resolve <RESOLVE>  将主机解析到特定 IP 地址（格式：HOST:PORT:ADDRESS，例如 example.com:80:1.2.3.4）
      --http3              使用 HTTP/3
      --http2              使用 HTTP/2
  -h, --help               显示帮助信息
  -V, --version            显示版本信息
```

## 许可证

http-stats-rs 使用 MIT 许可证。详见 [LICENSE](LICENSE)。
