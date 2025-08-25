package org.example

/**
 * SSL testing constants and configuration values.
 * Centralizes magic numbers and default values used throughout the application.
 */
object SSLConstants {
    // Network configuration - fixed to HTTPS standard
    const val HTTPS_PORT = 443
    const val DEFAULT_TIMEOUT = 5000
    const val DEFAULT_HANDSHAKE_TIMEOUT = 10000

    // Timeout limits
    const val MIN_TIMEOUT = 100
    const val MAX_TIMEOUT = 60000
    const val MIN_HANDSHAKE_TIMEOUT = 1000
    const val MAX_HANDSHAKE_TIMEOUT = 120000

    // Retry configuration
    const val MAX_RETRIES = 5
    const val MAX_RETRY_DELAY = 10000L
    const val DEFAULT_RETRY_DELAY = 1000L

    // SSL/TLS configuration
    val DEFAULT_ENABLED_PROTOCOLS = arrayOf("TLSv1.2", "TLSv1.3")
    const val DEFAULT_SSL_CONTEXT_PROTOCOL = "TLS"

    // Certificate validation
    const val OCSP_TIMEOUT = 5000

    // Output formatting
    const val MAX_LINE_LENGTH = 80

    // Exit codes
    const val EXIT_SUCCESS = 0
    const val EXIT_CONNECTION_ERROR = 1
    const val EXIT_INVALID_PARAMETERS = 2
    const val EXIT_CONFIGURATION_ERROR = 3
    const val EXIT_CERTIFICATE_ERROR = 4

    // Error messages
    const val ERROR_INVALID_TIMEOUT = "Timeout cannot be negative"
    const val ERROR_UNKNOWN_HOST = "Unknown host"
    const val ERROR_CONNECTION_TIMEOUT = "Connection timeout"
    const val ERROR_CONNECTION_FAILED = "Connection failed"
    const val ERROR_SSL_HANDSHAKE = "SSL Handshake failed"
    const val ERROR_SSL_PROTOCOL = "SSL Protocol error"
    const val ERROR_INVALID_CONFIGURATION = "Invalid configuration"
    const val ERROR_CERTIFICATE_VALIDATION = "Certificate validation failed"
}
