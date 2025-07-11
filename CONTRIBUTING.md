# 贡献指南

感谢您对SSL Test Tool项目的关注！我们欢迎所有形式的贡献。

## 开发环境设置

### 前提条件

- Java 21 或更高版本
- Gradle 8.14 或更高版本
- Git

### 本地开发设置

1. **克隆仓库**
   ```bash
   git clone <your-repo-url>
   cd ssl
   ```

2. **检查环境**
   ```bash
   task bootstrap
   ```

3. **构建项目**
   ```bash
   task build
   ```

4. **运行测试**
   ```bash
   task test
   ```

## 开发工作流

### 1. 创建功能分支

```bash
git checkout -b feature/your-feature-name
```

### 2. 进行更改

- 编写代码
- 添加测试用例
- 更新文档

### 3. 运行质量检查

```bash
# 运行所有检查
task check

# 或者分别运行
task lint      # 代码检查
task test      # 运行测试
task build     # 构建项目
```

### 4. 提交更改

```bash
git add .
git commit -m "feat: add your feature description"
```

### 5. 推送并创建Pull Request

```bash
git push origin feature/your-feature-name
```

## 代码规范

### Kotlin代码规范

- 使用ktlint进行代码格式化
- 遵循Kotlin官方编码约定
- 使用有意义的变量和函数名
- 添加适当的注释

### 提交信息规范

我们使用[Conventional Commits](https://www.conventionalcommits.org/)规范：

- `feat:` - 新功能
- `fix:` - 修复bug
- `docs:` - 文档更新
- `style:` - 代码格式调整
- `refactor:` - 代码重构
- `test:` - 测试相关
- `chore:` - 构建过程或辅助工具的变动

### 测试要求

- 所有新功能必须包含测试用例
- 测试覆盖率应保持在80%以上
- 运行测试：`task test:coverage`

## 项目结构

```
app/src/main/kotlin/org/example/
├── SSLTest.kt                    # 主入口点
├── SSLTestCommand.kt             # 命令行处理
├── DefaultSSLConnectionTester.kt # SSL连接测试
├── CertificateValidator.kt       # 证书验证
├── model/                        # 数据模型
├── exception/                    # 异常定义
├── formatter/                    # 输出格式化器
├── factory/                      # 工厂模式
├── cli/                         # 命令行相关
└── di/                          # 依赖注入
```

## 测试指南

### 运行测试

```bash
# 运行所有测试
task test

# 运行单元测试
task test:unit

# 运行集成测试
task test:int

# 运行CLI测试
task test:cli

# 生成覆盖率报告
task test:coverage
```

### 编写测试

- 使用JUnit 5和MockK
- 测试文件应放在对应的测试目录中
- 测试类名应以`Test`结尾
- 使用描述性的测试方法名

## 问题报告

### 报告Bug

请使用GitHub Issues报告bug，并包含以下信息：

- 操作系统和版本
- Java版本
- 重现步骤
- 预期行为
- 实际行为
- 错误日志（如果有）

### 功能请求

对于功能请求，请：

- 描述您想要的功能
- 解释为什么需要这个功能
- 提供使用场景示例

## 行为准则

我们致力于为每个人提供友好、安全和欢迎的环境。请：

- 尊重所有贡献者
- 保持专业和礼貌
- 接受建设性反馈
- 帮助他人学习和成长

## 许可证

通过贡献代码，您同意您的贡献将在MIT许可证下发布。

感谢您的贡献！🎉 