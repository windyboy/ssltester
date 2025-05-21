# SSL验证工具

## 安装指南

### 系统要求
- Python 3.8+
- OpenSSL 1.1.1+
- 64位操作系统

### 快速安装
```bash
# 使用pip安装
pip install ssl-validator

# 或从源码安装
git clone https://github.com/example/ssl-validator.git
cd ssl-validator
pip install -e .
```

## 系统时间验证

本工具会自动检查您的系统时间并在发现异常时发出警告。准确的系统时间对于证书验证至关重要，不准确的系统时间可能导致:

- 有效证书被误判为已过期或未生效
- 过期证书被误判为有效
- 证书有效期显示异常（如显示未来日期）

### 同步系统时间

如果您看到关于证书日期异常的警告，请使用以下方法同步系统时间：

- **Windows**: 设置 > 时间和语言 > 日期和时间 > 自动设置时间
- **macOS**: 系统设置 > 日期与时间 > 自动设置日期与时间
- **Linux**: `sudo ntpdate pool.ntp.org`

## 主要功能

### 1. 证书有效性检查
- 验证证书是否由受信任的证书颁发机构(CA)签发
- 检查证书链完整性
- 验证证书是否已被吊销(CRL/OCSP)

### 2. 证书信息查看
- 查看证书详细信息（颁发者、主题、有效期等）
- 导出证书信息为多种格式

### 3. 安全配置分析
- TLS/SSL协议版本检测
- 密码套件强度评估
- 已知漏洞检测(如BEAST, POODLE, Heartbleed)

### 4. 支持的证书格式
- X.509 证书 (.crt, .pem, .cer)
- PKCS#12 证书 (.pfx, .p12)
- Java KeyStore (.jks)
- 自签名证书验证

### 5. 批量检测
- 多域名并行检测
- 批量证书导入与分析
- CSV/JSON报告导出

## 使用方法

### 命令行使用

```bash
# 检查网站证书
sslcheck example.com

# 指定端口
sslcheck example.com:443

# 详细模式
sslcheck -v example.com

# 导出证书
sslcheck --export cert.pem example.com
```

### 高级用法

```bash
# 自定义信任根证书
sslcheck --ca-file custom-ca.pem example.com

# 批量检查（从文件）
sslcheck --batch domains.txt --output report.json

# 完整证书链验证
sslcheck --full-chain example.com

# 证书透明度日志检查
sslcheck --ct-check example.com
```

### GUI模式

1. 打开应用程序
2. 在地址栏输入要检查的域名
3. 点击"验证"按钮
4. 查看结果报告

## 配置文件

可以通过配置文件定制工具行为:

```yaml
# ~/.sslcheck.yaml
output:
  format: json
  colored: true
  
validation:
  check_revocation: true
  min_key_size: 2048
  
connections:
  timeout: 5
  retries: 3
```

## 常见问题解答

### Q: 为什么工具显示证书不受信任，但浏览器显示安全？
A: 这可能是因为本工具和浏览器的受信任CA列表不同，或者浏览器有特殊例外规则。

### Q: 如何解决"证书链不完整"警告？
A: 服务器需要配置完整的证书链，包括中间证书。

### Q: 工具报告"证书已吊销"，如何处理？
A: 请联系证书颁发机构获取新证书，原证书可能因安全问题已被吊销。

### Q: 工具支持代理服务器吗？
A: 是的，可以通过 `--proxy` 参数或环境变量 `HTTPS_PROXY` 设置代理。

### Q: 如何在内网环境使用此工具？
A: 可以使用 `--offline` 模式，手动提供证书文件进行验证。

## 性能优化建议

对于大规模部署，推荐以下配置:
- 使用 `--workers N` 参数增加并行处理能力
- 启用结果缓存 `--cache-dir /path/to/cache`
- 对于频繁检查，使用 `--quick` 模式跳过耗时验证

## 反馈与支持

如有问题或建议，请提交issue或发送邮件到support@sslchecker.example.com.

## 许可证

本项目采用 MIT 许可证。详情请见 [LICENSE](LICENSE) 文件。
