# SSL验证工具 (SSL Verification Tool)

一款功能强大的SSL证书验证和HTTPS连接测试工具，用于检查服务器SSL/TLS配置、证书链、主机名验证等。

## 主要功能

- HTTPS连接验证
- SSL/TLS握手测试
- 证书链验证
- 主机名验证
- 客户端证书支持
- 详细的证书信息展示
- 多种输出格式支持(文本格式, JSON格式, YAML格式)

## 系统要求

- Java 11或更高版本
- 支持的操作系统: Windows, macOS, Linux

## 安装

### 使用预编译的二进制文件

从[发布页面](https://github.com/example/ssltest/releases)下载最新版本：

```bash
# 解压下载的文件
unzip ssltest-1.0.0.zip

# 赋予执行权限
chmod +x ssltest/bin/ssltest

# 运行程序
./ssltest/bin/ssltest https://example.com
```

### 从源码构建

```bash
# 克隆项目
git clone https://github.com/example/ssltest.git
cd ssltest

# 使用Maven构建
./mvnw clean package

# 运行构建后的程序
java -jar target/ssltest-1.0.0.jar https://example.com
```

## 基础用法

```bash
# 基本SSL测试
ssltest https://example.com

# 指定超时时间（毫秒）
ssltest https://example.com -t 5000 -r 5000

# 启用重定向跟踪
ssltest https://example.com -f
```

## 高级用法

### 自定义信任库

```bash
# 使用自定义信任库
ssltest https://example.com -k mycertificates.jks -p 
# 会提示输入信任库密码
```

### 客户端证书认证

```bash
# 使用客户端证书和私钥进行双向TLS认证
ssltest https://example.com --client-certificate client.pem --client-key client_key.pem

# 指定客户端证书格式
ssltest https://example.com --client-certificate client.der --client-key client_key.der --client-certificate-format DER

# 带密码的私钥
ssltest https://example.com --client-certificate client.pem --client-key client_key.pem --client-key-password
# 会提示输入私钥密码
```

### 输出控制

```bash
# 指定输出文件
ssltest https://example.com -o results.txt

# JSON 格式输出
ssltest https://example.com --format JSON

# YAML 格式输出
ssltest https://example.com --format YAML

# 详细输出模式
ssltest https://example.com -v
```

### 配置文件

可以将常用配置保存在YAML或JSON配置文件中：

```bash
# 使用配置文件
ssltest https://example.com -c myconfig.yml
```

配置文件示例 `myconfig.yml`:
```yaml
connectionTimeout: 10000
readTimeout: 10000
followRedirects: true
keystoreFile: "mycertificates.jks"
keystorePassword: "mysecret"
clientCertificateFile: "client.pem"
clientKeyFile: "client_key.pem"
clientKeyPassword: "keypass"
clientCertificateFormat: "PEM"
outputFile: "results.json"
format: "JSON"
verbose: true
```

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
