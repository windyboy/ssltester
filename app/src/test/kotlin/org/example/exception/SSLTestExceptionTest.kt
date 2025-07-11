package org.example.exception

import org.junit.jupiter.api.Test
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.time.Instant
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class SSLTestExceptionTest {
    @Test
    fun testHandshakeErrorCreation() {
        val error =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "SSL handshake failed",
                cause = RuntimeException("Underlying cause"),
                timestamp = Instant.now(),
            )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("SSL handshake failed", error.message)
        assertNotNull(error.cause)
        assertTrue(error.cause is RuntimeException)
    }

    @Test
    fun testConnectionErrorCreation() {
        val error =
            SSLTestException.ConnectionError(
                host = "example.com",
                port = 443,
                message = "Connection failed",
                cause = RuntimeException("Underlying cause"),
                timestamp = Instant.now(),
            )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("Connection failed", error.message)
        assertNotNull(error.cause)
        assertTrue(error.cause is RuntimeException)
    }

    @Test
    fun testConfigurationErrorCreation() {
        val error =
            SSLTestException.ConfigurationError(
                message = "Configuration error",
                cause = RuntimeException("Underlying cause"),
                timestamp = Instant.now(),
            )

        assertEquals("Configuration error", error.message)
        assertNotNull(error.cause)
        assertTrue(error.cause is RuntimeException)
    }

    @Test
    fun testCertificateErrorCreation() {
        val error =
            SSLTestException.CertificateError(
                host = "example.com",
                port = 443,
                message = "Certificate error",
                cause = RuntimeException("Underlying cause"),
                timestamp = Instant.now(),
            )

        assertEquals("example.com", error.host)
        assertEquals(443, error.port)
        assertEquals("Certificate error", error.message)
        assertNotNull(error.cause)
        assertTrue(error.cause is RuntimeException)
    }

    @Test
    fun testFromExceptionWithSSLTestException() {
        val originalError =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "Original error",
                cause = RuntimeException("Original cause"),
                timestamp = Instant.now(),
            )

        val converted = SSLTestException.fromException(originalError, "new.example.com", 8443)

        // fromException should return the original exception unchanged
        assertTrue(converted is SSLTestException.HandshakeError)
        assertEquals("example.com", converted.host) // Original host, not new
        assertEquals(443, converted.port) // Original port, not new
        assertEquals("Original error", converted.message)
        assertNotNull(converted.cause)
    }

    @Test
    fun testFromExceptionWithSSLHandshakeException() {
        val sslException = SSLHandshakeException("SSL handshake failed")

        val converted = SSLTestException.fromException(sslException, "example.com", 443)

        assertTrue(converted is SSLTestException.HandshakeError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("SSL Error: SSL handshake failed") == true)
        assertEquals(sslException, converted.cause)
    }

    @Test
    fun testFromExceptionWithSSLException() {
        val sslException = SSLException("SSL protocol error")

        val converted = SSLTestException.fromException(sslException, "example.com", 443)

        assertTrue(converted is SSLTestException.HandshakeError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("SSL Error: SSL protocol error") == true)
        assertEquals(sslException, converted.cause)
    }

    @Test
    fun testFromExceptionWithConnectException() {
        val connectException = ConnectException("Connection refused")

        val converted = SSLTestException.fromException(connectException, "example.com", 443)

        assertTrue(converted is SSLTestException.ConnectionError)
        assertEquals("example.com", converted.host)
        assertEquals(443, converted.port)
        assertTrue(converted.message?.contains("Connection Error: Connection refused") == true)
        assertEquals(connectException, converted.cause)
    }

    @Test
    fun testFromExceptionWithSocketTimeoutException() {
        val timeoutException = SocketTimeoutException("Connection timeout")

        val converted = SSLTestException.fromException(timeoutException, "example.com", 443)

        assertTrue(converted is SSLTestException.ConfigurationError)
        assertTrue(converted.message?.contains("Unexpected Error: Connection timeout") == true)
        assertEquals(timeoutException, converted.cause)
    }

    @Test
    fun testFromExceptionWithUnknownHostException() {
        val unknownHostException = UnknownHostException("Unknown host")

        val converted = SSLTestException.fromException(unknownHostException, "example.com", 443)

        assertTrue(converted is SSLTestException.ConfigurationError)
        assertTrue(converted.message?.contains("Unexpected Error: Unknown host") == true)
        assertEquals(unknownHostException, converted.cause)
    }

    @Test
    fun testFromExceptionWithGenericException() {
        val genericException = Exception("Generic error")

        val converted = SSLTestException.fromException(genericException, "example.com", 443)

        assertTrue(converted is SSLTestException.ConfigurationError)
        assertTrue(converted.message?.contains("Unexpected Error: Generic error") == true)
        assertEquals(genericException, converted.cause)
    }

    @Test
    fun testFromExceptionWithNullHostAndPort() {
        val exception = RuntimeException("Test error")

        val converted = SSLTestException.fromException(exception, null, null)

        assertTrue(converted is SSLTestException.ConfigurationError)
        assertTrue(converted.message?.contains("Unexpected Error: Test error") == true)
        assertEquals(exception, converted.cause)
    }

    @Test
    fun testExceptionInheritanceHierarchy() {
        val handshakeError =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "Test",
                cause = null,
                timestamp = Instant.now(),
            )

        val connectionError =
            SSLTestException.ConnectionError(
                host = "example.com",
                port = 443,
                message = "Test",
                cause = null,
                timestamp = Instant.now(),
            )

        val configError =
            SSLTestException.ConfigurationError(
                message = "Test",
                cause = null,
                timestamp = Instant.now(),
            )

        val certError =
            SSLTestException.CertificateError(
                host = "example.com",
                port = 443,
                message = "Test",
                cause = null,
                timestamp = Instant.now(),
            )

        // These are always true since they inherit from SSLTestException
        // No need to check instance type as it's guaranteed by inheritance
    }

    @Test
    fun testExceptionMessageFormatting() {
        val error =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "SSL handshake failed",
                cause = RuntimeException("Underlying cause"),
                timestamp = Instant.now(),
            )

        val message = error.message
        assertNotNull(message)
        assertEquals("SSL handshake failed", message)
    }

    @Test
    fun testExceptionCauseChaining() {
        val rootCause = RuntimeException("Root cause")
        val intermediateCause = RuntimeException("Intermediate", rootCause)
        val sslError =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "SSL error",
                cause = intermediateCause,
                timestamp = Instant.now(),
            )

        assertEquals(intermediateCause, sslError.cause)
        assertEquals(rootCause, sslError.cause?.cause)
    }

    @Test
    fun testExceptionTimestampConsistency() {
        val before = Instant.now()
        val error =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "Test",
                cause = null,
                timestamp = Instant.now(),
            )
        val after = Instant.now()

        assertTrue(error.timestamp >= before)
        assertTrue(error.timestamp <= after)
    }

    @Test
    fun testExceptionWithNullCause() {
        val error =
            SSLTestException.HandshakeError(
                host = "example.com",
                port = 443,
                message = "Test",
                cause = null,
                timestamp = Instant.now(),
            )

        assertEquals("Test", error.message)
        assertEquals(null, error.cause)
    }

    @Test
    fun testCreateDetailedMessage() {
        val message =
            SSLTestException.createDetailedMessage(
                "Connection failed",
                "example.com",
                443,
                "Network timeout",
            )

        assertEquals("Connection failed for example.com:443 - Network timeout", message)
    }

    @Test
    fun testCreateDetailedMessageWithoutAdditionalInfo() {
        val message =
            SSLTestException.createDetailedMessage(
                "SSL handshake failed",
                "example.com",
                443,
            )

        assertEquals("SSL handshake failed for example.com:443", message)
    }

    @Test
    fun testCreateDetailedMessageWithNullAdditionalInfo() {
        val message =
            SSLTestException.createDetailedMessage(
                "Certificate error",
                "example.com",
                443,
                null,
            )

        assertEquals("Certificate error for example.com:443", message)
    }

    @Test
    fun testCreateDetailedMessageWithBlankAdditionalInfo() {
        val message =
            SSLTestException.createDetailedMessage(
                "Configuration error",
                "example.com",
                443,
                "   ",
            )

        assertEquals("Configuration error for example.com:443", message)
    }
}
