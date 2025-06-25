package org.example.exception

import java.net.ConnectException
import java.net.SocketTimeoutException
import javax.net.ssl.SSLException
import kotlin.test.*

class SSLTestExceptionTest {

    @Test
    fun `test HandshakeError creation`() {
        val cause = SSLException("SSL handshake failed")
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "SSL Handshake failed",
            cause = cause
        )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("SSL Handshake failed", error.message)
        assertEquals(cause, error.cause)
    }

    @Test
    fun `test HandshakeError without cause`() {
        val error = SSLTestException.HandshakeError(
            host = "test.com",
            port = 8443,
            message = "SSL Handshake failed"
        )

        assertEquals("test.com", error.host)
        assertEquals(8443, error.port)
        assertEquals("SSL Handshake failed", error.message)
        assertNull(error.cause)
    }

    @Test
    fun `test ConnectionError creation`() {
        val cause = ConnectException("Connection refused")
        val error = SSLTestException.ConnectionError(
            host = "example.com",
            port = 443,
            message = "Connection failed",
            cause = cause
        )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("Connection failed", error.message)
        assertEquals(cause, error.cause)
    }

    @Test
    fun `test ConnectionError without cause`() {
        val error = SSLTestException.ConnectionError(
            host = "test.com",
            port = 8443,
            message = "Connection failed"
        )

        assertEquals("test.com", error.host)
        assertEquals(8443, error.port)
        assertEquals("Connection failed", error.message)
        assertNull(error.cause)
    }

    @Test
    fun `test ConfigurationError creation`() {
        val cause = IllegalArgumentException("Invalid configuration")
        val error = SSLTestException.ConfigurationError(
            message = "Configuration error",
            cause = cause
        )

        assertEquals("Configuration error", error.message)
        assertEquals(cause, error.cause)
    }

    @Test
    fun `test ConfigurationError without cause`() {
        val error = SSLTestException.ConfigurationError(
            message = "Configuration error"
        )

        assertEquals("Configuration error", error.message)
        assertNull(error.cause)
    }

    @Test
    fun `test fromException with SSLException`() {
        val sslException = SSLException("SSL protocol error")
        val result = SSLTestException.fromException(sslException, "example.com", 443)

        assertIs<SSLTestException.HandshakeError>(result)
        assertEquals("example.com", result.host)
        assertEquals(443, result.port)
        assertTrue(result.message?.contains("SSL Error") == true)
        assertEquals(sslException, result.cause)
    }

    @Test
    fun `test fromException with ConnectException`() {
        val connectException = ConnectException("Connection refused")
        val result = SSLTestException.fromException(connectException, "example.com", 443)

        assertIs<SSLTestException.ConnectionError>(result)
        assertEquals("example.com", result.host)
        assertEquals(443, result.port)
        assertTrue(result.message?.contains("Connection Error") == true)
        assertEquals(connectException, result.cause)
    }

    @Test
    fun `test fromException with SocketTimeoutException`() {
        val timeoutException = SocketTimeoutException("Connection timed out")
        val result = SSLTestException.fromException(timeoutException, "example.com", 443)

        assertIs<SSLTestException.ConfigurationError>(result)
        assertTrue(result.message?.contains("Unexpected Error") == true)
        assertEquals(timeoutException, result.cause)
    }

    @Test
    fun `test fromException with RuntimeException`() {
        val runtimeException = RuntimeException("Unexpected error")
        val result = SSLTestException.fromException(runtimeException, "example.com", 443)

        assertIs<SSLTestException.ConfigurationError>(result)
        assertTrue(result.message?.contains("Unexpected Error") == true)
        assertEquals(runtimeException, result.cause)
    }

    @Test
    fun `test fromException with existing SSLTestException`() {
        val existingError = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "Existing error"
        )
        val result = SSLTestException.fromException(existingError, "newhost.com", 8443)

        // Should return the existing exception unchanged
        assertEquals(existingError, result)
        if (result is SSLTestException.HandshakeError) {
            assertEquals("example.com", result.host)
            assertEquals(443, result.port)
        }
    }

    @Test
    fun `test fromException with null host and port`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals("unknown", (result as? SSLTestException.HandshakeError)?.host ?: (result as SSLTestException.ConnectionError).host)
            assertEquals(-1, (result as? SSLTestException.HandshakeError)?.port ?: (result as SSLTestException.ConnectionError).port)
        }
    }

    @Test
    fun `test fromException with null host only`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, port = 443)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals("unknown", (result as? SSLTestException.HandshakeError)?.host ?: (result as SSLTestException.ConnectionError).host)
            assertEquals(443, (result as? SSLTestException.HandshakeError)?.port ?: (result as SSLTestException.ConnectionError).port)
        }
    }

    @Test
    fun `test fromException with null port only`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, host = "example.com")

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals("example.com", (result as? SSLTestException.HandshakeError)?.host ?: (result as SSLTestException.ConnectionError).host)
            assertEquals(-1, (result as? SSLTestException.HandshakeError)?.port ?: (result as SSLTestException.ConnectionError).port)
        }
    }

    @Test
    fun `test fromException with IOException`() {
        val ioException = java.io.IOException("IO error")
        val result = SSLTestException.fromException(ioException, "example.com", 443)

        assertIs<SSLTestException.ConfigurationError>(result)
        assertTrue(result.message?.contains("Unexpected Error") == true)
        assertEquals(ioException, result.cause)
    }

    @Test
    fun `test fromException with SecurityException`() {
        val securityException = SecurityException("Security error")
        val result = SSLTestException.fromException(securityException, "example.com", 443)

        assertIs<SSLTestException.ConfigurationError>(result)
        assertTrue(result.message?.contains("Unexpected Error") == true)
        assertEquals(securityException, result.cause)
    }

    @Test
    fun `test fromException with InterruptedException`() {
        val interruptedException = InterruptedException("Interrupted")
        val result = SSLTestException.fromException(interruptedException, "example.com", 443)

        assertIs<SSLTestException.ConfigurationError>(result)
        assertTrue(result.message?.contains("Unexpected Error") == true)
        assertEquals(interruptedException, result.cause)
    }

    @Test
    fun `test exception inheritance hierarchy`() {
        val handshakeError = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "Test error"
        )

        assertTrue(handshakeError is SSLTestException)
    }

    @Test
    fun `test exception message formatting`() {
        val sslException = SSLException("SSL protocol error")
        val result = SSLTestException.fromException(sslException, "example.com", 443)

        assertTrue(result.message?.contains("SSL Error") == true)
        assertTrue(result.message?.contains("SSL protocol error") == true)
    }

    @Test
    fun `test exception cause chaining`() {
        val rootCause = RuntimeException("Root cause")
        val sslException = SSLException("SSL error", rootCause)
        val result = SSLTestException.fromException(sslException, "example.com", 443)

        assertEquals(sslException, result.cause)
        assertEquals(rootCause, result.cause?.cause)
    }

    @Test
    fun `test exception with empty message`() {
        val sslException = SSLException("")
        val result = SSLTestException.fromException(sslException, "example.com", 443)

        assertTrue(result.message?.contains("SSL Error") == true)
    }

    @Test
    fun `test exception with null message`() {
        val sslException = SSLException(null as String?)
        val result = SSLTestException.fromException(sslException, "example.com", 443)

        assertTrue(result.message?.contains("SSL Error") == true)
    }

    @Test
    fun `test exception with special characters in hostname`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, "test-host.example.com", 443)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals("test-host.example.com", (result as? SSLTestException.HandshakeError)?.host ?: (result as SSLTestException.ConnectionError).host)
        }
    }

    @Test
    fun `test exception with IPv4 address`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, "192.168.1.1", 443)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals("192.168.1.1", (result as? SSLTestException.HandshakeError)?.host ?: (result as SSLTestException.ConnectionError).host)
        }
    }

    @Test
    fun `test exception with IPv6 address`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, "::1", 443)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals("::1", (result as? SSLTestException.HandshakeError)?.host ?: (result as SSLTestException.ConnectionError).host)
        }
    }

    @Test
    fun `test exception with very long hostname`() {
        val longHost = "a".repeat(100) + ".example.com"
        val exception = SSLTestException.ConnectionError(
            host = longHost,
            port = 443,
            message = "Connection failed"
        )
        
        assertEquals(longHost, exception.host)
        assertEquals(443, exception.port)
        assertEquals("Connection failed", exception.message)
    }

    @Test
    fun `test exception with negative port`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, "example.com", -1)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals(-1, (result as? SSLTestException.HandshakeError)?.port ?: (result as SSLTestException.ConnectionError).port)
        }
    }

    @Test
    fun `test exception with zero port`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, "example.com", 0)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals(0, (result as? SSLTestException.HandshakeError)?.port ?: (result as SSLTestException.ConnectionError).port)
        }
    }

    @Test
    fun `test exception with maximum port`() {
        val sslException = SSLException("SSL error")
        val result = SSLTestException.fromException(sslException, "example.com", 65535)

        if (result is SSLTestException.HandshakeError || result is SSLTestException.ConnectionError) {
            assertEquals(65535, (result as? SSLTestException.HandshakeError)?.port ?: (result as SSLTestException.ConnectionError).port)
        }
    }
} 