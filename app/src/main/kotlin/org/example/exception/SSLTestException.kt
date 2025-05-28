package org.example.exception

/**
 * Custom exception class for SSL/TLS testing errors.
 * This exception includes an exit code to indicate the type of error that occurred.
 *
 * @property message The error message describing what went wrong
 * @property exitCode The exit code indicating the type of error
 * @property cause The underlying exception that caused this error, if any
 */
class SSLTestException(
    message: String,
    val exitCode: Int,
    cause: Throwable? = null
) : Exception(message, cause) {
    companion object {
        private const val serialVersionUID = 1L
    }
} 