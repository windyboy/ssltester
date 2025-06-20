package org.example.model

/**
 * SSL 测试配置。
 * @property connectionTimeout 连接超时时间（毫秒）
 * @property format 输出格式
 * @property outputFile 输出文件路径（可选）
 */
data class SSLTestConfig(
    val connectionTimeout: Int = 5000,
    val format: OutputFormat = OutputFormat.TXT,
    val outputFile: String? = null,
)
