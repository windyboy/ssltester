# SSL验证工具

一款功能强大的SSL证书验证和HTTPS连接测试工具，用于检查服务器SSL/TLS配置、证书链、主机名验证等。

## 主要功能

- HTTPS连接验证
- SSL/TLS握手测试
- 证书链验证
- 主机名验证
- 客户端证书支持
- **深入的OCSP和CRL检查 (In-depth OCSP and CRL Checks):**
    - 利用Bouncy Castle库可靠解析证书中的AIA扩展以获取OCSP响应端点URI，以及解析CRL分发点URI。
    - 执行OCSP请求和CRL下载，以验证证书链中每个证书的吊销状态。
    - 为证书链中的每个证书显示详细的吊销状态（例如：GOOD, REVOKED, UNKNOWN）。
    - 在输出中指明吊销信息的来源（OCSP或CRL）以及UNKNOWN或REVOKED状态的原因。
    - 允许通过命令行参数 (`--check-ocsp=true/false`, `--check-crl=true/false`) 启用或禁用OCSP和CRL检查。
- 详细的证书信息展示
- 多种输出格式支持(TEXT, JSON, YAML)

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
ssltest https://example.com -k mycerts.jks -p 
# 会提示输入信任库密码
```

### 客户端证书认证

```bash
# 使用客户端证书和私钥进行双向TLS认证
ssltest https://example.com --client-cert client.pem --client-key client_key.pem

# 指定客户端证书格式
ssltest https://example.com --client-cert client.der --client-key client_key.der --client-cert-format DER

# 带密码的私钥
ssltest https://example.com --client-cert client.pem --client-key client_key.pem --client-key-password
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

### 证书验证选项

```bash
# 禁用OCSP检查
ssltest https://example.com --check-ocsp=false

# 禁用CRL检查
ssltest https://example.com --check-crl=false

# 禁用证书详细信息日志
ssltest https://example.com --log-cert-details=false
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
keystoreFile: "mycerts.jks"
keystorePassword: "mysecret"
clientCertFile: "client.pem"
clientKeyFile: "client_key.pem"
clientKeyPassword: "keypass"
clientCertFormat: "PEM"
outputFile: "results.json"
format: "JSON"
verbose: true
checkOCSP: true
checkCRL: true
logCertDetails: true
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
| `--client-cert` | 客户端证书文件路径 | - |
| `--client-key` | 客户端私钥文件路径 | - |
| `--client-key-password` | 客户端私钥密码 (交互式) | - |
| `--client-cert-format` | 客户端证书格式 (PEM, DER) | PEM |
| `-o, --output` | 输出文件路径 | - |
| `--format` | 输出格式 (TEXT, JSON, YAML) | TEXT |
| `-v, --verbose` | 显示详细输出 | false |
| `--log-cert-details` | 在日志中显示证书详细信息 | true |
| `-c, --config` | 配置文件路径 (YAML/JSON) | - |
| `--check-ocsp` | 是否检查OCSP | true |
| `--check-crl` | 是否检查CRL | true |

## 退出码

| 代码 | 描述 |
|------|------|
| 0 | 成功 |
| 1 | 无效参数 |
| 2 | SSL握手错误 |
| 3 | 连接错误 |
| 4 | 证书验证错误 (例如：证书链无效，证书过期，主机名不匹配，证书被吊销) |
| 5 | 主机名验证错误 |
| 6 | 配置错误 |
| 99 | 未预期的错误 |

## 输出示例

### 文本输出 (默认)

```
SSL Test Results for https://example.com
==================================================
→ 整体状态          : 成功
→ HTTP Status         : 200
→ Cipher Suite        : TLS_AES_256_GCM_SHA384
→ Hostname Verification: Passed
--------------------------------------------------
Server Certificate Chain (2 certificate(s)):

  Certificate [1]:
    Subject DN        : CN=example.com, O=Example Inc, C=US
    Issuer DN         : CN=Example Intermediate CA, O=Example Inc, C=US
    Serial Number     : 1A2B3C4D5E6F7890
    Version           : 3
    Valid From        : 2023-01-15 00:00:00 UTC
    Valid Until       : 2024-01-15 23:59:59 UTC
    Signature Algorithm: SHA256withRSA
    Public Key Alg.   : RSA
    Is Self-Signed    : false
    Is Expired        : false
    Is Not Yet Valid  : false
    Trust Status      : TRUSTED_BY_ROOT
    Revocation Status : GOOD
    OCSP Responder URL: http://ocsp.example.com/
    CRL Distrib. Points: [http://crl.example.com/intermediate.crl]
    Failure Reason    : None
    Subject Alternative Names:
        Type 2: example.com
        Type 2: www.example.com

  Certificate [2]:
    Subject DN        : CN=Example Intermediate CA, O=Example Inc, C=US
    Issuer DN         : CN=Example Root CA, O=Example Inc, C=US
    Serial Number     : 0102030405060708
    Version           : 3
    Valid From        : 2021-04-14 00:00:00 UTC
    Valid Until       : 2031-04-13 23:59:59 UTC
    Signature Algorithm: SHA256withRSA
    Public Key Alg.   : RSA
    Is Self-Signed    : false
    Is Expired        : false
    Is Not Yet Valid  : false
    Trust Status      : TRUSTED_BY_ROOT
    Revocation Status : GOOD
    OCSP Responder URL: http://ocsp.root.example.com/ (might be N/A for CAs)
    CRL Distrib. Points: [http://crl.root.example.com/root.crl]
    Failure Reason    : None
--------------------------------------------------
```

### JSON输出

```json
{
  "httpStatus": 200,
  "cipherSuite": "TLS_AES_256_GCM_SHA384",
  "hostnameVerified": true,
  "status": "success",
  "certificateChain": [
    {
      "subjectDN": "CN=example.com, O=Example Inc, C=US",
      "issuerDN": "CN=Example Intermediate CA, O=Example Inc, C=US",
      "version": 3,
      "serialNumber": "1A2B3C4D5E6F7890",
      "validFrom": "2023-01-15 00:00:00 UTC",
      "validUntil": "2024-01-15 23:59:59 UTC",
      "signatureAlgorithm": "SHA256withRSA",
      "publicKeyAlgorithm": "RSA",
      "subjectAlternativeNames": {
        "2": "www.example.com" 
      },
      "selfSigned": false,
      "expired": false,
      "notYetValid": false,
      "trustStatus": "TRUSTED_BY_ROOT",
      "revocationStatus": "GOOD",
      "ocspResponderUrl": "http://ocsp.example.com/",
      "crlDistributionPoints": ["http://crl.example.com/intermediate.crl"],
      "failureReason": null
    },
    {
      "subjectDN": "CN=Example Intermediate CA, O=Example Inc, C=US",
      "issuerDN": "CN=Example Root CA, O=Example Inc, C=US",
      "version": 3,
      "serialNumber": "0102030405060708",
      "validFrom": "2021-04-14 00:00:00 UTC",
      "validUntil": "2031-04-13 23:59:59 UTC",
      "signatureAlgorithm": "SHA256withRSA",
      "publicKeyAlgorithm": "RSA",
      "subjectAlternativeNames": null,
      "selfSigned": false,
      "expired": false,
      "notYetValid": false,
      "trustStatus": "TRUSTED_BY_ROOT",
      "revocationStatus": "UNKNOWN",
      "ocspResponderUrl": "http://ocsp.root.example.com/",
      "crlDistributionPoints": ["http://crl.root.example.com/root.crl"],
      "failureReason": "CRL request timed out"
    }
  ]
}
```

## 常见问题解答

### Q: 如何测试需要客户端证书的服务器？
A: 使用 `--client-cert` 和 `--client-key` 参数指定客户端证书和私钥。如果私钥有密码保护，可以使用 `--client-key-password` 参数。

### Q: 如何处理自签名证书或内部CA签发的证书？
A: 可以使用 `-k, --keystore` 参数指定包含这些证书的信任库。

### Q: OCSP或CRL检查花费太长时间，如何跳过？
A: 使用 `--check-ocsp=false` 和 `--check-crl=false` 参数禁用这些检查。

### Q: 如何将检测结果保存到文件？
A: 使用 `-o, --output` 参数指定输出文件路径，并可以用 `--format` 选择合适的输出格式。

## 许可证

本项目采用 MIT 许可证。详情请见 [LICENSE](LICENSE) 文件。
