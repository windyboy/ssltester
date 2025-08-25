# SSL Test Tool

一个简单而强大的SSL/TLS连接测试工具，用于验证网站SSL/TLS配置和证书链。

## ✨ 特性

- 🔒 HTTPS连接验证
- 🤝 SSL/TLS握手测试
- 📜 证书链验证和OCSP状态检查
- 🌐 主机名验证
- 📊 多种输出格式（文本、JSON、YAML、Emoji）
- ⏱️ 可配置的超时设置（连接、读取、握手）
- 🔄 智能重试机制（固定延迟、指数退避）
- ✅ 智能配置验证和一致性检查
- 🚨 详细的错误报告和分类（连接、握手、证书、超时、配置）
- 📈 性能指标收集和报告
- 🏗️ 结构化日志记录和上下文管理
- 🎯 类型安全的操作结果处理
- 🔧 模块化架构设计

## 🛠️ 系统要求

- Java 21 或更高版本
- 支持的操作系统：Windows、macOS、Linux

## 📦 安装和构建

```bash
# 克隆项目
$ git clone <your-repo-url>
$ cd ssl

# 使用Gradle构建
$ ./gradlew clean build

# 或者使用Taskfile（推荐）
$ task build
```

## 🚀 基本使用

```bash
# 基本SSL测试（默认端口443）
./gradlew run --args="github.com --format TXT"

# 使用自定义端口
./gradlew run --args="github.com --port 8443 --format JSON"

# 指定输出文件
./gradlew run --args="github.com --port 443 --format JSON --output result.json"

# 使用构建的JAR文件
java -jar app/build/libs/ssl-test-0.0.5-all.jar github.com --port 9443 --format YAML

# 使用Taskfile（推荐）
task run HOST=github.com PORT=443 FORMAT=JSON
```

## 🔧 高级配置选项

### 超时配置

```bash
# 连接超时（TCP连接建立）
--connect-timeout 5000

# 读取超时（数据读取）
--read-timeout 5000

# 握手超时（SSL握手）
--handshake-timeout 10000
```

### 验证选项

```bash
# 启用/禁用主机名验证
--enable-hostname-verification
--no-enable-hostname-verification

# 启用/禁用OCSP验证
--enable-ocsp-validation
--no-enable-ocsp-validation
```

### 重试机制

```bash
# 最大重试次数
--max-retries 3

# 重试延迟（毫秒）
--retry-delay 2000
```

### 完整示例

```bash
# 详细测试配置
./gradlew run --args="example.com \
  --port 8443 \
  --connect-timeout 10000 \
  --read-timeout 10000 \
  --handshake-timeout 15000 \
  --format JSON \
  --output detailed_test.json \
  --enable-hostname-verification \
  --enable-ocsp-validation \
  --max-retries 2 \
  --retry-delay 2000"
```

## 📊 输出格式

- **TXT** - 彩色文本输出，适合终端显示
- **JSON** - 结构化数据，适合程序处理
- **YAML** - 人类可读的结构化数据
- **EMOJI** - 基于表情符号的输出，提供快速视觉反馈

## 🔧 命令行参数

| 参数 | 描述 | 默认值 | 必需 |
|------|------|--------|------|
| `<host>` | 要测试SSL/TLS连接的目标主机 | - | 是 |
| `-p, --port` | 端口号 | 443 | 否 |
| `--connect-timeout` | 连接超时时间（毫秒） | 5000 | 否 |
| `--read-timeout` | 读取超时时间（毫秒） | 5000 | 否 |
| `--handshake-timeout` | SSL握手超时时间（毫秒） | 10000 | 否 |
| `-f, --format` | 输出格式（txt, json, yaml, emoji） | TXT | 否 |
| `-o, --output` | 输出文件路径 | - | 否 |
| `--enable-hostname-verification` | 启用主机名验证 | true | 否 |
| `--enable-ocsp-validation` | 启用OCSP验证 | true | 否 |
| `--max-retries` | 最大重试次数 | 1 | 否 |
| `--retry-delay` | 重试延迟（毫秒） | 1000 | 否 |

## 📋 退出码

| 代码 | 描述 |
|------|------|
| 0 | 成功 |
| 1 | 连接错误 |
| 2 | 无效参数 |
| 3 | 配置错误 |
| 4 | 证书验证错误 |
| 5 | 超时错误 |

## 🏗️ 架构特性

### 类型安全的结果处理
- `SSLTestResult` 密封类提供类型安全的操作结果
- 支持成功、失败、超时三种结果状态
- 消除空值返回，提供安全的访问方法

### 结构化日志记录
- `SSLTestContext` 提供统一的上下文管理
- `StructuredLogger` 实现一致的日志格式
- 支持会话ID、时间戳、性能指标等上下文信息

### 智能重试机制
- `RetryManager` 支持多种重试策略
- 固定延迟和指数退避重试
- 智能错误分类，避免重试无效错误

### 性能监控
- `PerformanceMetrics` 收集详细的性能数据
- 支持检查点和指标记录
- 生成性能报告和统计信息

### 配置验证
- `ConfigurationValidator` 提供全面的配置验证
- 支持超时范围、重试设置、文件路径等验证
- 一致性检查确保配置参数协调

## 💡 使用示例

```bash
# 测试网站的SSL证书（默认端口443）
./gradlew run --args="google.com"

# 使用自定义端口和超时
./gradlew run --args="github.com --port 8443 --connect-timeout 10000 --format json"

# 快速测试（较短超时）
./gradlew run --args="example.com --connect-timeout 2000 --read-timeout 2000 --handshake-timeout 3000"

# 详细测试（较长超时，启用所有验证）
./gradlew run --args="stackoverflow.com --connect-timeout 10000 --read-timeout 10000 --handshake-timeout 15000 --enable-ocsp-validation --max-retries 2"

# 保存结果到文件
./gradlew run --args="stackoverflow.com --port 443 --format yaml --output ssl_test.yaml"

# 使用Taskfile进行快速测试
task run HOST=google.com FORMAT=EMOJI
```

## 🧪 开发

```bash
# 运行测试
./gradlew test

# 构建JAR
./gradlew build

# 运行测试覆盖率报告
./gradlew jacocoTestReport

# 代码格式化和检查
./gradlew ktlintFormat ktlintCheck

# 使用Taskfile进行开发工作流
task check          # 运行所有质量检查
task test:coverage  # 运行测试覆盖率
```

## 🔍 错误处理

### 异常类型
- `ConnectionError` - 连接建立失败
- `HandshakeError` - SSL握手失败
- `CertificateError` - 证书验证失败
- `TimeoutError` - 各种超时情况
- `ConfigurationError` - 配置参数错误

### 错误上下文
- 详细的错误消息和原因
- 错误发生的时间和阶段
- 相关的配置参数和网络信息
- 建议的解决方案

## 📈 性能特性

### 指标收集
- 连接建立时间
- SSL握手持续时间
- 证书验证时间
- 总体测试时间
- 重试次数和延迟

### 优化特性
- 资源自动管理（使用Kotlin `use`函数）
- 协程支持异步操作
- 智能超时处理
- 内存高效的证书链处理

## 🐳 Docker支持

```bash
# 构建Docker镜像
docker build -t ssl-test .

# 运行Docker容器
docker run ssl-test google.com --format JSON
```

## 🤝 贡献

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🔄 更新日志

查看 [CHANGELOG.md](CHANGELOG.md) 了解详细的更新历史。

## 🧹 代码质量

### 代码清理成果
本项目经过全面的代码清理和优化，确保代码质量达到最高标准：

- **无冗余依赖**：所有声明的依赖项都在实际使用中
- **无未使用导入**：所有导入的类和方法都在代码中使用
- **无死代码**：没有未使用的类、方法或常量
- **无重复配置**：构建配置中移除了重复的JVM参数设置
- **代码风格一致**：符合ktlint规范，导入顺序正确

### 质量保证
- 使用 JaCoCo 进行测试覆盖率检查（目标：行覆盖率80%，分支覆盖率70%）
- 使用 ktlint 进行代码风格检查
- 所有测试通过，无编译错误
- 使用 Taskfile 进行自动化构建和测试

### 维护性
- 模块化架构设计，职责分离清晰
- 完整的异常处理体系
- 结构化日志记录
- 类型安全的结果处理
- 智能重试机制
