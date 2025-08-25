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
        val protocol: String? = null,
        val cipherSuite: String? = null,
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
        val connectionType: ConnectionType = ConnectionType.UNKNOWN,
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
        val configField: String? = null,
        val expectedValue: String? = null,
        val actualValue: String? = null,
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
        val certificateField: String? = null,
        val validationType: ValidationType = ValidationType.UNKNOWN,
    ) : SSLTestException(
            message,
            cause,
            timestamp,
        )

    /**
     * 超时错误。
     */
    data class TimeoutError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
        override val timestamp: Instant = Instant.now(),
        val timeoutType: TimeoutType,
        val timeoutValue: Long,
    ) : SSLTestException(
            message,
            cause,
            timestamp,
        )

    /**
     * 连接类型枚举。
     */
    enum class ConnectionType {
        TCP_CONNECTION,
        SSL_HANDSHAKE,
        CERTIFICATE_VALIDATION,
        UNKNOWN,
    }

    /**
     * 验证类型枚举。
     */
    enum class ValidationType {
        HOSTNAME_VERIFICATION,
        CERTIFICATE_CHAIN,
        OCSP_VALIDATION,
        CRL_CHECK,
        UNKNOWN,
    }

    /**
     * 超时类型枚举。
     */
    enum class TimeoutType {
        CONNECTION_TIMEOUT,
        READ_TIMEOUT,
        HANDSHAKE_TIMEOUT,
        OCSP_TIMEOUT,
    }

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
                is javax.net.ssl.SSLHandshakeException ->
                    HandshakeError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "SSL Handshake failed: ${e.message}",
                        cause = e,
                    )
                is javax.net.ssl.SSLProtocolException ->
                    HandshakeError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "SSL Protocol error: ${e.message}",
                        cause = e,
                    )
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
                        message = "Connection refused: ${e.message}",
                        cause = e,
                        connectionType = ConnectionType.TCP_CONNECTION,
                    )
                is java.net.SocketTimeoutException ->
                    TimeoutError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "Connection timeout",
                        cause = e,
                        timeoutType = TimeoutType.CONNECTION_TIMEOUT,
                        // Will be set by caller
                        timeoutValue = 0L,
                    )
                is java.net.UnknownHostException ->
                    ConnectionError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "Unknown host: ${e.message}",
                        cause = e,
                        connectionType = ConnectionType.TCP_CONNECTION,
                    )
                is java.security.cert.CertificateException ->
                    CertificateError(
                        host = host ?: "unknown",
                        port = port ?: -1,
                        message = "Certificate validation failed: ${e.message}",
                        cause = e,
                        validationType = ValidationType.CERTIFICATE_CHAIN,
                    )
                is java.security.NoSuchAlgorithmException ->
                    ConfigurationError(
                        message = "Unsupported SSL algorithm: ${e.message}",
                        cause = e,
                        configField = "SSL_ALGORITHM",
                    )
                is java.security.KeyStoreException ->
                    ConfigurationError(
                        message = "SSL keystore configuration error: ${e.message}",
                        cause = e,
                        configField = "KEYSTORE",
                    )
                else ->
                    ConfigurationError(
                        message = "Unexpected error: ${e.message}",
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

        /**
         * 创建超时错误消息。
         */
        fun createTimeoutMessage(
            timeoutType: TimeoutType,
            host: String,
            port: Int,
            timeoutValue: Long,
        ): String =
            when (timeoutType) {
                TimeoutType.CONNECTION_TIMEOUT -> "Connection timeout after ${timeoutValue}ms for $host:$port"
                TimeoutType.READ_TIMEOUT -> "Read timeout after ${timeoutValue}ms for $host:$port"
                TimeoutType.HANDSHAKE_TIMEOUT -> "SSL handshake timeout after ${timeoutValue}ms for $host:$port"
                TimeoutType.OCSP_TIMEOUT -> "OCSP validation timeout after ${timeoutValue}ms for $host:$port"
            }
    }
}
