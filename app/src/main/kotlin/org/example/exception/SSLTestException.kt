package org.example.exception

sealed class SSLTestException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    data class HandshakeError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
    ) : SSLTestException(
            message,
            cause,
        )

    data class ConnectionError(
        val host: String,
        val port: Int,
        override val message: String,
        override val cause: Throwable? = null,
    ) : SSLTestException(
            message,
            cause,
        )

    data class ConfigurationError(
        override val message: String,
        override val cause: Throwable? = null,
    ) : SSLTestException(
            message,
            cause,
        )

    companion object {
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
