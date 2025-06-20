package org.example.exception

/**
 * SSL 测试相关异常。
 * 包含握手错误、连接错误、配置错误等。
 */
sealed class SSLTestException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /**
     * SSL 握手错误。
     */
    data class HandshakeError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
    ) : SSLTestException(
            message,
            cause,
        )

    /**
     * 连接错误。
     */
    data class ConnectionError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
    ) : SSLTestException(
            message,
            cause,
        )

    /**
     * 配置错误。
     */
    data class ConfigurationError(
        override val message: String,
        override val cause: Throwable? = null,
    ) : SSLTestException(
            message,
            cause,
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
                else ->
                    ConfigurationError(
                        message = "Unexpected Error: ${e.message}",
                        cause = e,
                    )
            }
    }
}
