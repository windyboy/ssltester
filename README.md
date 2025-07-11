# SSL Test Tool

一个简单而强大的SSL/TLS连接测试工具，用于验证网站SSL/TLS配置和证书链。

## ✨ 特性

- 🔒 HTTPS连接验证
- 🤝 SSL/TLS握手测试
- 📜 证书链验证
- 🌐 主机名验证
- 📊 多种输出格式（文本、JSON、YAML、Emoji）
- ⏱️ 连接超时配置

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
java -jar app/build/libs/ssl-test-0.0.2-all.jar github.com --port 9443 --format YAML

# 使用Taskfile（推荐）
task run HOST=github.com PORT=443 FORMAT=JSON
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
| `-f, --format` | 输出格式（txt, json, yaml, emoji） | TXT | 否 |
| `-o, --output` | 输出文件路径 | - | 否 |

## 📋 退出码

| 代码 | 描述 |
|------|------|
| 0 | 成功 |
| 1 | 连接错误 |
| 2 | 无效参数 |

## 💡 使用示例

```bash
# 测试网站的SSL证书（默认端口443）
./gradlew run --args="google.com"

# 使用自定义端口
./gradlew run --args="github.com --port 8443 --format json"

# 使用自定义超时时间
./gradlew run --args="example.com --port 9443 --connect-timeout 10000"

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
