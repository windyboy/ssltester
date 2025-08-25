package org.example.logging

import org.example.model.OutputFormat
import java.time.Instant

/**
 * SSL测试上下文。
 * 用于结构化日志记录，提供一致的上下文信息。
 */
data class SSLTestContext(
    val host: String,
    val port: Int,
    val connectionTimeout: Int,
    val readTimeout: Int,
    val handshakeTimeout: Int,
    val format: OutputFormat,
    val outputFile: String?,
    val enableHostnameVerification: Boolean,
    val enableOCSPValidation: Boolean,
    val maxRetries: Int,
    val retryDelay: Long,
    val sessionId: String = generateSessionId(),
    val timestamp: Instant = Instant.now(),
) {
    companion object {
        /**
         * 生成会话ID。
         */
        private fun generateSessionId(): String = "ssl-test-${System.currentTimeMillis()}-${(0..9999).random()}"
    }

    /**
     * 获取连接标识符。
     */
    fun getConnectionId(): String = "$host:$port"

    /**
     * 获取超时配置摘要。
     */
    fun getTimeoutSummary(): String = "connect=${connectionTimeout}ms,read=${readTimeout}ms,handshake=${handshakeTimeout}ms"

    /**
     * 获取验证配置摘要。
     */
    fun getValidationSummary(): String = "hostname=$enableHostnameVerification,ocsp=$enableOCSPValidation"

    /**
     * 获取重试配置摘要。
     */
    fun getRetrySummary(): String = "max=$maxRetries,delay=${retryDelay}ms"

    /**
     * 转换为日志字段映射。
     */
    fun toLogFields(): Map<String, String> =
        mapOf(
            "sessionId" to sessionId,
            "host" to host,
            "port" to port.toString(),
            "connectionTimeout" to connectionTimeout.toString(),
            "readTimeout" to readTimeout.toString(),
            "handshakeTimeout" to handshakeTimeout.toString(),
            "format" to format.value,
            "outputFile" to (outputFile ?: "none"),
            "enableHostnameVerification" to enableHostnameVerification.toString(),
            "enableOCSPValidation" to enableOCSPValidation.toString(),
            "maxRetries" to maxRetries.toString(),
            "retryDelay" to retryDelay.toString(),
            "timestamp" to timestamp.toString(),
        )

    /**
     * 创建子上下文（用于重试）。
     */
    fun createRetryContext(retryAttempt: Int): SSLTestContext =
        copy(
            sessionId = "$sessionId-retry-$retryAttempt",
        )
}
