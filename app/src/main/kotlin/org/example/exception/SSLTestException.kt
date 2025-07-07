package org.example.exception

import java.time.Instant

/**
 * SSL 测试相关异常。
 * 包含握手错误、连接错误、配置错误等。
 */
sealed class SSLTestException(
    message: String,
    cause: Throwable? = null,
    open val timestamp: Instant = Instant.now(),
) : Exception(message, cause) {
    /**
     * SSL 握手错误。
     */
    data class HandshakeError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
        override val timestamp: Instant = Instant.now(),
    ) : SSLTestException(
            message,
            cause,
            timestamp,
        )

    /**
     * 连接错误。
     */
    data class ConnectionError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
        override val timestamp: Instant = Instant.now(),
    ) : SSLTestException(
            message,
            cause,
            timestamp,
        )

    /**
     * 配置错误。
     */
    data class ConfigurationError(
        override val message: String,
        override val cause: Throwable? = null,
        override val timestamp: Instant = Instant.now(),
    ) : SSLTestException(
            message,
            cause,
            timestamp,
        )

    /**
     * 证书验证错误。
     */
    data class CertificateError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
        override val timestamp: Instant = Instant.now(),
    ) : SSLTestException(
            message,
            cause,
            timestamp,
        )

    companion object {
        /**
         * 从异常生成对应的 SSLTestException。
         */
        fun fromException(
            e: Throwable,
            host: String? = null,
            port: Int? = null,
        ): SSLTestException =
            when (e) {
                is SSLTestException -> e
                is javax.net.ssl.SSLException ->
                    HandshakeError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "SSL Error: ${e.message}",
                        cause = e,
                    )
                is java.net.ConnectException ->
                    ConnectionError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "Connection Error: ${e.message}",
                        cause = e,
                    )
                is java.security.cert.CertificateException ->
                    CertificateError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "Certificate Error: ${e.message}",
                        cause = e,
                    )
                else ->
                    ConfigurationError(
                        message = "Unexpected Error: ${e.message}",
                        cause = e,
                    )
            }

        /**
         * 创建带有详细上下文的错误消息。
         */
        fun createDetailedMessage(
            baseMessage: String,
            host: String,
            port: Int,
            additionalInfo: String? = null,
        ): String =
            buildString {
                append(baseMessage)
                append(" for $host:$port")
                if (!additionalInfo.isNullOrBlank()) {
                    append(" - $additionalInfo")
                }
            }
    }
}
