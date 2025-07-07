package org.example

/**
 * SSL testing constants and configuration values.
 * Centralizes magic numbers and default values used throughout the application.
 */
object SSLConstants {
    // Network configuration
    const val DEFAULT_PORT = 443
    const val DEFAULT_TIMEOUT = 5000
    const val MAX_PORT = 65535
    const val MIN_PORT = 1

    // Timeout limits
    const val MIN_TIMEOUT = 100
    const val MAX_TIMEOUT = 60000

    // SSL/TLS configuration
    val DEFAULT_ENABLED_PROTOCOLS = arrayOf("TLSv1.2", "TLSv1.3")
    const val DEFAULT_SSL_CONTEXT_PROTOCOL = "TLS"

    // Output formatting
    const val MAX_LINE_LENGTH = 80
    const val CERTIFICATE_WRAP_LENGTH = 60

    // Exit codes
    const val EXIT_SUCCESS = 0
    const val EXIT_CONNECTION_ERROR = 1
    const val EXIT_INVALID_PARAMETERS = 2

    // Error messages
    const val ERROR_INVALID_PORT = "Port must be between 1 and 65535"
    const val ERROR_INVALID_TIMEOUT = "Timeout cannot be negative"
    const val ERROR_UNKNOWN_HOST = "Unknown host"
    const val ERROR_CONNECTION_TIMEOUT = "Connection timeout"
    const val ERROR_CONNECTION_FAILED = "Connection failed"
    const val ERROR_SSL_HANDSHAKE = "SSL Handshake failed"
    const val ERROR_SSL_PROTOCOL = "SSL Protocol error"
}
