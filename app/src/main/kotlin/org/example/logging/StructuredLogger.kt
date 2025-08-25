package org.example.logging

import org.example.exception.SSLTestException
import org.example.model.SSLTestResult
import java.time.Duration

/**
 * 结构化日志记录器。
 * 提供一致的日志格式和上下文信息。
 */
class StructuredLogger {
    /**
     * 记录SSL测试开始。
     */
    fun logTestStart(context: SSLTestContext) {
        val message =
            buildString {
                append("Starting SSL test")
                append(" sessionId=${context.sessionId}")
                append(" host=${context.host}")
                append(" port=${context.port}")
                append(" timeouts=[${context.getTimeoutSummary()}]")
                append(" validation=[${context.getValidationSummary()}]")
                append(" retry=[${context.getRetrySummary()}]")
                append(" format=${context.format}")
                if (context.outputFile != null) {
                    append(" output=${context.outputFile}")
                }
            }
        println("[INFO] $message")
    }

    /**
     * 记录连接建立。
     */
    fun logConnectionEstablished(
        context: SSLTestContext,
        duration: Duration,
    ) {
        val message =
            "TCP connection established" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " duration=${duration.toMillis()}ms"
        println("[INFO] $message")
    }

    /**
     * 记录SSL握手开始。
     */
    fun logHandshakeStart(context: SSLTestContext) {
        val message =
            "Starting SSL handshake" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}"
        println("[INFO] $message")
    }

    /**
     * 记录SSL握手完成。
     */
    fun logHandshakeComplete(
        context: SSLTestContext,
        duration: Duration,
        protocol: String,
        cipherSuite: String,
    ) {
        val message =
            "SSL handshake completed" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " duration=${duration.toMillis()}ms" +
                " protocol=$protocol" +
                " cipherSuite=$cipherSuite"
        println("[INFO] $message")
    }

    /**
     * 记录证书验证开始。
     */
    fun logCertificateValidationStart(
        context: SSLTestContext,
        certificateCount: Int,
    ) {
        val message =
            "Starting certificate validation" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " certificateCount=$certificateCount"
        println("[INFO] $message")
    }

    /**
     * 记录证书验证完成。
     */
    fun logCertificateValidationComplete(
        context: SSLTestContext,
        duration: Duration,
        isValid: Boolean,
    ) {
        val message =
            "Certificate validation completed" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " duration=${duration.toMillis()}ms" +
                " isValid=$isValid"
        println("[INFO] $message")
    }

    /**
     * 记录测试成功。
     */
    fun logTestSuccess(
        context: SSLTestContext,
        result: SSLTestResult.Success,
    ) {
        val message =
            "SSL test completed successfully" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " totalDuration=${result.testDuration.toMillis()}ms" +
                " protocol=${result.connection.protocol}" +
                " cipherSuite=${result.connection.cipherSuite}"
        println("[INFO] $message")
    }

    /**
     * 记录测试失败。
     */
    fun logTestFailure(
        context: SSLTestContext,
        result: SSLTestResult.Failure,
    ) {
        val message =
            "SSL test failed" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " totalDuration=${result.testDuration.toMillis()}ms" +
                " errorType=${result.error.javaClass.simpleName}" +
                " errorMessage=${result.error.message}"
        println("[ERROR] $message")
    }

    /**
     * 记录测试超时。
     */
    fun logTestTimeout(
        context: SSLTestContext,
        result: SSLTestResult.Timeout,
    ) {
        val message =
            "SSL test timed out" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " totalDuration=${result.testDuration.toMillis()}ms" +
                " timeoutType=${result.timeoutType}" +
                " timeoutValue=${result.timeoutValue}ms"
        println("[WARN] $message")
    }

    /**
     * 记录重试尝试。
     */
    fun logRetryAttempt(
        context: SSLTestContext,
        attempt: Int,
        maxAttempts: Int,
        reason: String,
    ) {
        val message =
            "Retrying SSL test" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " attempt=$attempt" +
                " maxAttempts=$maxAttempts" +
                " reason=$reason"
        println("[INFO] $message")
    }

    /**
     * 记录重试成功。
     */
    fun logRetrySuccess(
        context: SSLTestContext,
        attempt: Int,
    ) {
        val message =
            "Retry successful" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " attempt=$attempt"
        println("[INFO] $message")
    }

    /**
     * 记录重试失败。
     */
    fun logRetryFailure(
        context: SSLTestContext,
        attempt: Int,
        maxAttempts: Int,
    ) {
        val message =
            "Retry failed" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " attempt=$attempt" +
                " maxAttempts=$maxAttempts"
        println("[WARN] $message")
    }

    /**
     * 记录配置验证错误。
     */
    fun logConfigurationError(
        context: SSLTestContext,
        error: SSLTestException.ConfigurationError,
    ) {
        val message =
            "Configuration validation failed" +
                " sessionId=${context.sessionId}" +
                " host=${context.host}" +
                " port=${context.port}" +
                " errorField=${error.configField}" +
                " expectedValue=${error.expectedValue}" +
                " actualValue=${error.actualValue}" +
                " errorMessage=${error.message}"
        println("[ERROR] $message")
    }

    /**
     * 记录性能指标。
     */
    fun logPerformanceMetrics(
        context: SSLTestContext,
        metrics: Map<String, Duration>,
    ) {
        val message =
            buildString {
                append("Performance metrics")
                append(" sessionId=${context.sessionId}")
                append(" host=${context.host}")
                append(" port=${context.port}")
                metrics.forEach { (key, duration) ->
                    append(" $key=${duration.toMillis()}ms")
                }
            }
        println("[DEBUG] $message")
    }

    companion object {
        /**
         * 创建默认的结构化日志记录器。
         */
        fun create(): StructuredLogger = StructuredLogger()
    }
}
