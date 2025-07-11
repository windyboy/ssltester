# 依赖管理指南

本文档介绍如何使用项目中的依赖更新功能来保持依赖库的最新版本。

## 概述

项目提供了多种方式来检查和更新依赖：

1. **Gradle 原生方式** - 使用 `dependencyUpdates` 插件
2. **脚本方式** - 使用自定义的 `update-dependencies.sh` 脚本
3. **Task 方式** - 使用 Taskfile.yml 中定义的任务

## 快速开始

### 检查过时的依赖

```bash
# 使用 Task
task deps-check

# 使用脚本
./scripts/update-dependencies.sh check

# 使用 Gradle 直接
./gradlew dependencyUpdates
```

### 交互式更新

```bash
# 使用脚本（推荐）
./scripts/update-dependencies.sh

# 或使用 Task
task deps-update-script
```

### 自动更新

```bash
# 使用脚本
./scripts/update-dependencies.sh update

# 或使用 Task
task deps-update-auto
```

## 详细说明

### 1. Gradle 原生方式

项目已配置了 `com.github.ben-manes.versions` 插件，提供以下功能：

- 检查稳定版本更新
- 生成详细的更新报告
- 排除预发布版本（alpha, beta, rc 等）

**配置位置**: `app/build.gradle.kts`

```kotlin
// Dependency updates configuration
tasks.dependencyUpdates {
    checkForGradleUpdate = true
    outputFormatter = "plain"
    outputDir = "build/dependencyUpdates"
    reportfileName = "report.txt"
    
    resolutionStrategy {
        componentSelection {
            all {
                val rejected = listOf("alpha", "beta", "rc", "cr", "m", "preview", "b", "ea")
                // ... 排除预发布版本
            }
        }
    }
}
```

### 2. 脚本方式

`scripts/update-dependencies.sh` 提供了更友好的交互式体验：

**功能特性**:
- 彩色输出和进度提示
- 交互式菜单选择
- 自动备份版本文件
- 详细的更新指导

**使用方式**:

```bash
# 交互式模式（默认）
./scripts/update-dependencies.sh

# 仅检查
./scripts/update-dependencies.sh check

# 自动更新
./scripts/update-dependencies.sh update

# 显示帮助
./scripts/update-dependencies.sh help
```

### 3. Task 方式

Taskfile.yml 中定义了多个相关任务：

| Task | 描述 | 命令 |
|------|------|------|
| `deps-check` | 检查过时依赖 | `task deps-check` |
| `deps-update` | 生成更新报告 | `task deps-update` |
| `deps-update-interactive` | 交互式更新 | `task deps-update-interactive` |
| `deps-update-script` | 使用脚本更新 | `task deps-update-script` |
| `deps-update-auto` | 自动更新 | `task deps-update-auto` |
| `deps-check-script` | 脚本检查 | `task deps-check-script` |

## 版本文件管理

### 版本目录文件

项目使用 `gradle/libs.versions.toml` 来集中管理依赖版本：

```toml
[versions]
picocli = "4.7.7"
jackson = "2.18.4"
slf4j = "2.0.17"
# ... 更多版本定义

[libraries]
picocli = { module = "info.picocli:picocli", version.ref = "picocli" }
# ... 更多库定义
```

### 更新流程

1. **检查更新**: 运行依赖检查命令
2. **查看报告**: 查看生成的更新报告
3. **备份文件**: 脚本会自动创建备份
4. **更新版本**: 手动编辑 `gradle/libs.versions.toml`
5. **测试构建**: 运行 `./gradlew build` 验证

### 示例更新流程

```bash
# 1. 检查当前状态
./scripts/update-dependencies.sh check

# 2. 查看报告
cat app/build/dependencyUpdates/report.txt

# 3. 交互式更新
./scripts/update-dependencies.sh

# 4. 编辑版本文件
vim gradle/libs.versions.toml

# 5. 测试更新
./gradlew build
```

## 最佳实践

### 1. 定期检查

建议每周或每月检查一次依赖更新：

```bash
# 添加到 crontab 或 CI/CD 流程
0 9 * * 1 cd /path/to/project && ./scripts/update-dependencies.sh check
```

### 2. 分阶段更新

- **开发环境**: 可以尝试最新版本
- **测试环境**: 使用稳定版本
- **生产环境**: 谨慎更新，充分测试

### 3. 更新策略

1. **小版本更新** (x.y.z): 通常安全，可以直接更新
2. **中版本更新** (x.y.z): 需要查看变更日志
3. **大版本更新** (x.y.z): 需要充分测试和迁移

### 4. 测试验证

更新依赖后，务必运行完整的测试套件：

```bash
# 运行所有测试
./gradlew test

# 运行构建
./gradlew build

# 运行集成测试
task test-integration
```

## 故障排除

### 常见问题

1. **插件版本冲突**
   ```bash
   # 清理并重新构建
   ./gradlew clean build
   ```

2. **版本解析失败**
   ```bash
   # 刷新依赖
   ./gradlew --refresh-dependencies
   ```

3. **脚本权限问题**
   ```bash
   # 添加执行权限
   chmod +x scripts/update-dependencies.sh
   ```

### 获取帮助

```bash
# 脚本帮助
./scripts/update-dependencies.sh help

# Task 帮助
task --list-all

# Gradle 帮助
./gradlew help --task dependencyUpdates
```

## 相关文件

- `gradle/libs.versions.toml` - 版本目录文件
- `scripts/update-dependencies.sh` - 更新脚本
- `Taskfile.yml` - Task 定义
- `app/build.gradle.kts` - Gradle 配置

## 贡献

如果您发现依赖更新相关的问题或有改进建议，请：

1. 检查现有问题
2. 创建新的 issue
3. 提交 pull request

---

*最后更新: 2024年* 