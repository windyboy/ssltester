package org.example.domain.exception

/**
 * Base exception for SSL testing errors.
 */
sealed class SSLTestException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /**
     * Exception thrown when there is a security-related error.
     */
    class SecurityException(message: String, cause: Throwable? = null) : SSLTestException(message, cause)

    /**
     * Exception thrown when there is a connection error.
     */
    class ConnectionException(message: String, cause: Throwable? = null) : SSLTestException(message, cause)

    /**
     * Exception thrown when there is a certificate validation error.
     */
    class CertificateException(message: String, cause: Throwable? = null) : SSLTestException(message, cause)

    /**
     * Exception thrown when there is a configuration error.
     */
    class ConfigurationException(message: String, cause: Throwable? = null) : SSLTestException(message, cause)
} 