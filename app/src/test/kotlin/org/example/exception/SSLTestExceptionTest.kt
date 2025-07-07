package org.example.exception

import org.junit.jupiter.api.Test
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import java.time.Instant

class SSLTestExceptionTest {

    @Test
    fun `test HandshakeError creation and properties`() {
        val timestamp = Instant.now()
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "SSL handshake failed",
            cause = RuntimeException("Connection timeout"),
            timestamp = timestamp
        )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("SSL handshake failed", error.message)
        assertNotNull(error.cause)
        assertEquals(timestamp, error.timestamp)
    }

    @Test
    fun `test ConnectionError creation and properties`() {
        val timestamp = Instant.now()
        val error = SSLTestException.ConnectionError(
            host = "example.com",
            port = 443,
            message = "Connection failed",
            cause = RuntimeException("Network error"),
            timestamp = timestamp
        )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("Connection failed", error.message)
        assertNotNull(error.cause)
        assertEquals(timestamp, error.timestamp)
    }

    @Test
    fun `test ConfigurationError creation and properties`() {
        val timestamp = Instant.now()
        val error = SSLTestException.ConfigurationError(
            message = "Invalid configuration",
            cause = RuntimeException("Invalid port"),
            timestamp = timestamp
        )

        assertEquals("Invalid configuration", error.message)
        assertNotNull(error.cause)
        assertEquals(timestamp, error.timestamp)
    }

    @Test
    fun `test CertificateError creation and properties`() {
        val timestamp = Instant.now()
        val error = SSLTestException.CertificateError(
            host = "example.com",
            port = 443,
            message = "Certificate validation failed",
            cause = RuntimeException("Invalid certificate"),
            timestamp = timestamp
        )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("Certificate validation failed", error.message)
        assertNotNull(error.cause)
        assertEquals(timestamp, error.timestamp)
    }

    @Test
    fun `test fromException with SSLTestException`() {
        val originalError = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "Original error",
            cause = RuntimeException("Original cause"),
            timestamp = Instant.now()
        )

        val converted = SSLTestException.fromException(originalError, "new.example.com", 8443)
        
        assertTrue(converted is SSLTestException.HandshakeError)
        assertEquals("new.example.com", converted.host)
        assertEquals(8443, converted.port)
        assertEquals("Original error", converted.message)
        assertNotNull(converted.cause)
    }

    @Test
    fun `test fromException with SSLHandshakeException`() {
        val sslException = SSLHandshakeException("SSL handshake failed")
        
        val converted = SSLTestException.fromException(sslException, "example.com", 443)
        
        assertTrue(converted is SSLTestException.HandshakeError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("SSL handshake failed") == true)
        assertEquals(sslException, converted.cause)
    }

    @Test
    fun `test fromException with SSLException`() {
        val sslException = SSLException("SSL protocol error")
        
        val converted = SSLTestException.fromException(sslException, "example.com", 443)
        
        assertTrue(converted is SSLTestException.HandshakeError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("SSL protocol error") == true)
        assertEquals(sslException, converted.cause)
    }

    @Test
    fun `test fromException with ConnectException`() {
        val connectException = ConnectException("Connection refused")
        
        val converted = SSLTestException.fromException(connectException, "example.com", 443)
        
        assertTrue(converted is SSLTestException.ConnectionError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("Connection refused") == true)
        assertEquals(connectException, converted.cause)
    }

    @Test
    fun `test fromException with SocketTimeoutException`() {
        val timeoutException = SocketTimeoutException("Connection timeout")
        
        val converted = SSLTestException.fromException(timeoutException, "example.com", 443)
        
        assertTrue(converted is SSLTestException.ConnectionError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("Connection timeout") == true)
        assertEquals(timeoutException, converted.cause)
    }

    @Test
    fun `test fromException with UnknownHostException`() {
        val unknownHostException = UnknownHostException("Unknown host")
        
        val converted = SSLTestException.fromException(unknownHostException, "example.com", 443)
        
        assertTrue(converted is SSLTestException.ConnectionError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("Unknown host") == true)
        assertEquals(unknownHostException, converted.cause)
    }

    @Test
    fun `test fromException with generic Exception`() {
        val genericException = Exception("Generic error")
        
        val converted = SSLTestException.fromException(genericException, "example.com", 443)
        
        assertTrue(converted is SSLTestException.ConnectionError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("Generic error") == true)
        assertEquals(genericException, converted.cause)
    }

    @Test
    fun `test fromException with null host and port`() {
        val exception = RuntimeException("Test error")
        
        val converted = SSLTestException.fromException(exception, null, null)
        
        assertTrue(converted is SSLTestException.ConnectionError)
        assertEquals("unknown", converted.host)
        assertEquals(-1, converted.port)
        assertTrue(converted.message?.contains("Test error") == true)
        assertEquals(exception, converted.cause)
    }

    @Test
    fun `test exception inheritance hierarchy`() {
        val handshakeError = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "Test",
            cause = null,
            timestamp = Instant.now()
        )
        
        val connectionError = SSLTestException.ConnectionError(
            host = "example.com",
            port = 443,
            message = "Test",
            cause = null,
            timestamp = Instant.now()
        )
        
        val configError = SSLTestException.ConfigurationError(
            message = "Test",
            cause = null,
            timestamp = Instant.now()
        )
        
        val certError = SSLTestException.CertificateError(
            host = "example.com",
            port = 443,
            message = "Test",
            cause = null,
            timestamp = Instant.now()
        )

        assertTrue(handshakeError is SSLTestException)
        assertTrue(connectionError is SSLTestException)
        assertTrue(configError is SSLTestException)
        assertTrue(certError is SSLTestException)
    }

    @Test
    fun `test exception message formatting`() {
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "SSL handshake failed",
            cause = RuntimeException("Underlying cause"),
            timestamp = Instant.now()
        )

        val message = error.message
        assertNotNull(message)
        assertTrue(message.contains("example.com"))
        assertTrue(message.contains("443"))
        assertTrue(message.contains("SSL handshake failed"))
    }

    @Test
    fun `test exception cause chaining`() {
        val rootCause = RuntimeException("Root cause")
        val intermediateCause = RuntimeException("Intermediate", rootCause)
        val sslError = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "SSL error",
            cause = intermediateCause,
            timestamp = Instant.now()
        )

        assertEquals(intermediateCause, sslError.cause)
        assertEquals(rootCause, sslError.cause?.cause)
    }

    @Test
    fun `test exception timestamp consistency`() {
        val before = Instant.now()
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "Test",
            cause = null,
            timestamp = Instant.now()
        )
        val after = Instant.now()

        assertTrue(error.timestamp >= before)
        assertTrue(error.timestamp <= after)
    }

    @Test
    fun `test exception with null cause`() {
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "Test without cause",
            cause = null,
            timestamp = Instant.now()
        )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("Test without cause", error.message)
        assertTrue(error.cause == null)
    }

    @Test
    fun `test exception with empty message`() {
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = "",
            cause = null,
            timestamp = Instant.now()
        )

        assertEquals("", error.message)
    }

    @Test
    fun `test exception with special characters in message`() {
        val specialMessage = "Error with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        val error = SSLTestException.HandshakeError(
            host = "example.com",
            port = 443,
            message = specialMessage,
            cause = null,
            timestamp = Instant.now()
        )

        assertEquals(specialMessage, error.message)
    }
} 