package org.example.exception

/**
 * Exception thrown when an error occurs during SSL testing.
 *
 * @property message The error message
 * @property code The error code
 * @property cause The cause of the error
 */
class SSLTestException(
    override val message: String,
    val code: Int = 1,
    override val cause: Throwable? = null
) : Exception(message, cause) {
    companion object {
        private const val serialVersionUID = 1L
    }
} 