# http-stat-rs

Pure rust version of [httpstat](https://github.com/davecheney/httpstat).

![screenshot](./screenshot.png)


## Installation

```
cargo install http-stat
```

## Usage
```
httpstat https://www.baidu.com
```

## Features

```bash
Usage: httpstat [OPTIONS] [URL_ARG]

Arguments:
  [URL_ARG]  url to request

Options:
  -u, --url <URL>          URL to request (optional, can be provided as the last argument)
  -H <HEADERS>             set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'
  -4                       resolve host to ipv4 only
  -6                       resolve host to ipv6 only
  -k                       skip verify tls certificate
  -o <OUTPUT>              output file
  -L                       follow 30x redirects
  -X <METHOD>              HTTP method to use (default GET)
  -d, --data <DATA>        the body of a POST or PUT request; from file use @filename
      --resolve <RESOLVE>  Resolve host to specific IP address (format: HOST:PORT:ADDRESS, e.g. example.com:80:1.2.3.4)
  -h, --help               Print help
  -V, --version            Print version
```