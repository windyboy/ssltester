# 更新日志

本文档记录了SSL Test Tool的所有重要更改。

## [0.0.3] - 2025-01-27

### 🧹 文档简化
- 删除复杂的API文档（API.md）
- 删除详细的部署指南（DEPLOYMENT.md）
- 删除依赖管理文档（DEPENDENCIES.md）
- 删除OWASP安全扫描相关配置和脚本
- 简化README.md，专注于工具核心功能
- 简化CONTRIBUTING.md，移除复杂的安全扫描和发布流程
- 简化Taskfile.yml，移除依赖管理和安全扫描任务
- 简化build.gradle.kts，移除OWASP依赖检查插件
- 简化gradle.properties，移除安全扫描配置
- 删除taskfiles目录下的复杂工具文件
- 删除scripts目录下的NVD API脚本

### 📚 文档改进
- 重新组织README.md结构，突出核心功能
- 简化贡献指南，专注于开发工作流程
- 更新CHANGELOG.md格式，提高可读性
- 移除不必要的复杂配置和说明

## [0.0.2] - 2025-01-27

### 🚀 新功能
- 实现SSL连接测试功能
- 添加多种输出格式支持（TXT、JSON、YAML、EMOJI）
- 实现证书链验证功能
- 添加主机名验证
- 支持连接超时配置
- 添加文件输出功能

### 🔧 改进
- 重构Taskfile.yml，提升清晰度和功能性
- 更新README和Taskfile，改进清晰度和功能性
- 清理格式化和增强输出处理
- 增强测试覆盖率和SSL测试功能
- 添加JaCoCo插件用于测试覆盖率
- 更新依赖项和Kotlin版本
- 添加CHANGELOG.md并更新Kotlin版本
- 更新Taskfile.yml以改进版本管理和命令格式化
- 更新Dockerfile并添加LICENSE文件
- 简化SSL测试和输出格式化
- 移除已弃用的文件和无用配置
- 更新Kotlin版本并重构SSL测试结构
- 升级Kotlin版本并重构SSL连接处理
- 增强SSL连接测试和输出格式化
- 实现Docker支持并增强任务管理
- 添加shadowJar任务并增强测试输出本地化
- 增强SSL证书详细信息的文本输出格式化
- 改进证书类型检测和输出格式化
- 更新SSL测试框架和配置
- 使用URL端口进行SSL连接
- 实现主机名验证
- 更新构建配置并增强SSL测试框架
- 增强SSL证书验证和管理
- 从配置和文档中移除OCSP和CRL检查
- 更新构建配置并移除已弃用的类
- 解决合并冲突并清理项目结构
- 添加Taskfile用于构建和GitHub发布自动化
- 移除CertificateValidator类和相关逻辑
- 增强SSLTestException并更新依赖项
- 更新依赖项并改进结果格式化
- 移除SSLTestConfig类和相关CLI选项
- 使用PKIX和撤销增强证书验证
- 更新依赖项并记录SSLTestConfig
- 改进证书验证和依赖项管理
- 移除SSLTestConfig和SSLTestExceptionTest类
- 移除CertificateValidatorTest以简化测试套件
- 改进证书验证和主机名匹配

### 🐛 修复
- 修正握手时间并更新测试配置
- 更新握手时间并增强输出格式化
- 移除过时的测试输出文件并更新.gitignore
- 更新.gitignore以包含测试输出文件
- 修复gitbutler问题

### 🧹 清理
- 移除已弃用的文件和无用配置
- 移除cert_analyzer.py，不再需要
- 从requirements.txt中移除pyOpenSSL依赖
- 移除SecurityStrengthAnalyzerTest以简化测试套件
- 移除CertificateValidator类和相关逻辑
- 移除SSLTestConfig类和相关CLI选项
- 移除SSLTestConfig和SSLTestExceptionTest类
- 移除CertificateValidatorTest以简化测试套件

### 📚 文档
- 更新README和Taskfile，改进清晰度和功能性
- 添加CHANGELOG.md并更新Kotlin版本
- 更新Taskfile.yml以改进版本管理和命令格式化
- 更新Dockerfile并添加LICENSE文件
- 更新依赖项并记录SSLTestConfig

### 🔒 安全
- 添加JaCoCo插件用于测试覆盖率
- 实现Docker支持并增强任务管理
- 添加Taskfile用于构建和GitHub发布自动化

## [0.0.1] - 2025-01-20

### 🚀 初始版本
- 项目初始化
- 基本SSL连接测试功能
- 命令行界面
- 基本输出格式化

---

## 版本说明

- **0.0.1**: 初始版本，包含基本功能
- **0.0.2**: 完整功能版本，包含SSL测试功能和多种输出格式支持
- **0.0.3**: 文档简化版本，专注于工具核心功能，移除复杂配置

## 贡献指南

请参考 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何为项目做出贡献。

