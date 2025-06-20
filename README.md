# SSL验证工具 (SSL Verification Tool)

一款功能强大的SSL证书验证和HTTPS连接测试工具，用于检查服务器SSL/TLS配置、证书链、主机名验证等。

## 主要功能

- HTTPS连接验证
- SSL/TLS握手测试
- 证书链验证
- 主机名验证
- 多种输出格式支持(文本格式, JSON格式, YAML格式)

## 系统要求

- Java 11或更高版本
- 支持的操作系统: Windows, macOS, Linux

## 安装与构建

```bash
# 克隆项目
$ git clone <your-repo-url>
$ cd ssl

# 使用 Gradle 构建
$ ./gradlew clean build
```

## 目录结构

```
app/src/main/kotlin/org/example/
  SSLTest.kt                # 主入口
  SSLTestCommand.kt         # 命令行参数与调度
  SSLConnectionTesterImpl.kt# SSL连接测试核心逻辑
  model/                    # 数据模型
  exception/                # 异常定义
  formatter/                # 输出格式化器（TXT/JSON/YAML）
  cli/                      # 命令行相关
  listener/                 # 测试监听器
```

## 基础用法

```bash
# 基本SSL测试
./gradlew run --args="github.com --port 443 --format TXT"

# 指定输出文件
./gradlew run --args="github.com --port 443 --format JSON --output result.json"
```

## 输出格式
- TXT（彩色文本，适合终端）
- JSON
- YAML

## 开发说明

- **无依赖注入框架**，所有依赖直接 new，结构极简。
- 所有格式化器均在 `org.example.formatter` 包下，便于扩展。
- 主要业务逻辑集中在 `SSLTestCommand` 和 `SSLConnectionTesterImpl`。
- 代码均带有标准 Kotlin 文档注释，便于 IDE/工具提示。

## 贡献
欢迎提交 issue 或 PR！

## 命令行参数

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `<url>` | 要测试的HTTPS URL (位置参数) | 必填 |
| `-t, --timeout` | 连接超时（毫秒） | 5000 |
| `-r, --read-timeout` | 读取超时（毫秒） | 5000 |
| `-f, --follow-redirects` | 跟踪HTTP重定向 | false |
| `-k, --keystore` | 信任库文件路径 | 系统默认 |
| `-p, --keystore-password` | 信任库密码 (交互式) | - |
| `--client-certificate` | 客户端证书文件路径 | - |
| `--client-key` | 客户端私钥文件路径 | - |
| `--client-key-password` | 客户端私钥密码 (交互式) | - |
| `--client-certificate-format` | 客户端证书格式 (PEM, DER) | PEM |
| `-o, --output` | 输出文件路径 | - |
| `--format` | 输出格式 (文本格式, JSON格式, YAML格式) | 文本格式 |
| `-v, --verbose` | 显示详细输出 | false |
| `-c, --config` | 配置文件路径 (YAML/JSON) | - |

## 退出码

| 代码 | 描述 |
|------|------|
| 0 | 成功 |
| 1 | 无效参数 |
| 2 | SSL握手错误 |
| 3 | 连接错误 |
| 4 | 证书验证错误 |
| 5 | 主机名验证错误 |
| 6 | 配置错误 |
| 99 | 未预期的错误 |

## 输出示例

### 文本输出 (默认)

```
SSL Test Results for https://example.com
==================================================
连接状态: 成功
HTTP状态码: 200
协商的密码套件: TLS_AES_256_GCM_SHA384
协议版本: TLSv1.3
主机名验证: 通过

服务器证书链:
[1] 主体: CN=example.com, O=Example Inc, C=US
    颁发者: CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US
    有效期: 2023-01-15 至 2024-01-15
    指纹(SHA-256): 3A:40:F5:9E:84:2E:...

[2] 主体: CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US
    颁发者: CN=DigiCert Global Root CA, O=DigiCert Inc, OU=www.digicert.com, C=US
    有效期: 2021-04-14 至 2031-04-13
    指纹(SHA-256): 0A:35:48:7C:0C:3C:...
```

### JSON输出

```json
{
  "url": "https://example.com",
  "connectionStatus": "SUCCESS",
  "httpStatus": 200,
  "cipherSuite": "TLS_AES_256_GCM_SHA384",
  "tlsVersion": "TLSv1.3",
  "hostnameVerification": "PASSED",
  "certificateChain": [
    {
      "position": 1,
      "subject": "CN=example.com, O=Example Inc, C=US",
      "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
      "validFrom": "2023-01-15T00:00:00Z",
      "validTo": "2024-01-15T23:59:59Z",
      "fingerprintSHA256": "3A:40:F5:9E:84:2E:..."
    },
    {
      "position": 2,
      "subject": "CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
      "issuer": "CN=DigiCert Global Root CA, O=DigiCert Inc, OU=www.digicert.com, C=US",
      "validFrom": "2021-04-14T00:00:00Z",
      "validTo": "2031-04-13T23:59:59Z",
      "fingerprintSHA256": "0A:35:48:7C:0C:3C:..."
    }
  ]
}
```

## 常见问题解答

### Q: 如何测试需要客户端证书的服务器？
A: 使用 `--client-certificate` 和 `--client-key` 参数指定客户端证书和私钥。如果私钥有密码保护，可以使用 `--client-key-password` 参数。

### Q: 如何处理自签名证书或内部CA签发的证书？
A: 可以使用 `-k, --keystore` 参数指定包含这些证书的信任库。

## 许可证

本项目采用 MIT 许可证。详情请见 [LICENSE](LICENSE) 文件。
